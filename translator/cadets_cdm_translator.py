#!/usr/local/bin/python3

"""
Load in trace records in CADETS json format, translate them to CDM format, and
write the CDM records to a file

Outputs a JSON CDM format and the binary avro format

"""

import argparse
from collections import namedtuple
import json
import logging
from logging.config import fileConfig
from multiprocessing import Process
import os
from os.path import isfile
import queue
import subprocess
import sys
import threading
import time

import confluent_kafka
from prometheus_client import CollectorRegistry, Gauge, Counter, push_to_gateway

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from tc.schema.serialization import AvroGenericSerializer, Utils
from tc.schema.serialization.kafka import KafkaAvroGenericSerializer


from translator import CDMTranslator

# Default values, replace or use command line arguments
TRACE_DIR = "../../trace-data"
IN_FILE = None
SCHEMA = "../../ta3-serialization-schema/avro/TCCDMDatum.avsc"
OUTPUT_DIR = "../../trace-data"
LOGGING_CONF = "logging.conf"
CDMVERSION = "20"
GROUP_ID = "CADETS_"+str(subprocess.getoutput(['sysctl -n kern.hostuuid']))
KAFKASTRING = "129.55.12.59:9092"
PRODUCER_ID = "cadets"
CA_CERT_LOCATION = "/var/private/ssl/ca-cert"
CERT_LOCATION = "/var/private/ssl/kafka.client.pem"
KEY_LOCATION = "/var/private/ssl/kafka.client.key"
KEY_PASSWORD = "TransparentComputing"
TOPIC = "ta1-cadets-cdm13"

logger = logging.getLogger("tc")

JsonOutput = namedtuple("JsonOutput", "output_dir")
BinaryOutput = namedtuple("BinaryOutput", "output_dir")
KafkaOutput = namedtuple("KafkaOutput", "conn_str topic enable_metrics myip use_ssl")
FileInput = namedtuple("FileInput", "path watch")
KafkaInput = namedtuple("KafkaInput", "conn_str topic enable_metrics myip use_ssl")

def get_arg_parser():
    parser = argparse.ArgumentParser(description="Translate CADETS json to CDM")

    parser.add_argument("--version", action="version",
                        version="cadets_cdm_translator.py - CDMv"+CDMVERSION)
    parser.add_argument("-session", action="store", default=0, help="Initial session count")
    parser.add_argument("-psf", action="store", type=str, default=SCHEMA,
                        help="Set the producer's schema file.")
    parser.add_argument("-v", action="store_true", default=False,
                        help="Turn up verbosity.")
    parser.add_argument("-tdir", action="store", type=str, default=TRACE_DIR,
                        help="Directory to load CADETS record files from")
    parser.add_argument("-odir", action="store", type=str, default=OUTPUT_DIR,
                        help="Directory to write CDM records files to")
    file_group = parser.add_mutually_exclusive_group(required=False)
    file_group.add_argument("-f", action="store", type=str, default=IN_FILE,
                            help="File to translate. Default is to translate every .json file in "
                                 "the directory")
    file_group.add_argument("-watch", action="store_true", default=False,
                            help="Watch for new files in source tdir")
    parser.add_argument("-lc", action="store", type=str, default=LOGGING_CONF,
                        help="Logging configuration file")
    output_group = parser.add_argument_group('output formats')
    output_group.add_argument("-wj", action="store_true", default=False,
                              help="Write JSON output file")
    output_group.add_argument("-wb", action="store_true", default=False,
                              help="Write binary output file")
    output_group.add_argument("-wk", action="store_true", default=False,
                              help="Write to Kafka")
    parser.add_argument("-validate", action="store_true", default=False,
                        help="Validate CDM produced")
    kafka_settings = parser.add_argument_group('Kafka settings')
    kafka_settings.add_argument("-kouts", action="store", default=KAFKASTRING,
                                required="-wk" in sys.argv or "-rk" in sys.argv,
                                help="Kafka connection string")
    kafka_settings.add_argument("-kins", action="store", default=KAFKASTRING,
                                required="-kin" in sys.argv or "-rk" in sys.argv,
                                help="Kafka connection string")
    kafka_settings.add_argument("-ktopic", action="store", type=str, default=TOPIC,
                                required="-wk" in sys.argv, help="Kafka topic to publish to")
    kafka_settings.add_argument("-kmetrics", action="store_true", default=False,
                                help="Enable Kafka metrics")
    kafka_settings.add_argument("-kmyip", action="store", type=str, required="-wk" in sys.argv,
                                help="IP address to publish from")
    kafka_settings.add_argument("-kin", action="store_true", default=False,
                                help="Read input from Kafka")
    kafka_settings.add_argument("-kintopic", action="store", type=str, default=TOPIC,
                                required="-kin" in sys.argv, help="Kafka topic to read from")
    kafka_settings.add_argument("-kinssl", action="store_true", default=False,
                                help="Use SSL for kafka input")
    kafka_settings.add_argument("-koutssl", action="store_true", default=False,
                                help="Use SSL for kafka input")
    parser.add_argument("-p", action="store_true", default=False,
                        help="Print progress message for longer translations")

    host_group_top = parser.add_argument_group('Host type (choose one)')
    host_group = host_group_top.add_mutually_exclusive_group(required=True)
    host_group.add_argument("-hs", "--host-server", dest='host_type', action="store_const",
                            const="HOST_SERVER", help="Host is a server.")
    host_group.add_argument("-hd", "--host-desktop", dest='host_type', action="store_const",
                            const="HOST_DESKTOP", help="Host is a desktop.")

    return parser


def main():
    parser = get_arg_parser()
    args = parser.parse_args()

    if args.watch and args.f:
        # incompatible args used
        parser.print_help()
        sys.exit(1)

    # Set up logging
    fileConfig(args.lc)

    if args.v:
        logging.getLogger("tc").setLevel(logging.DEBUG)

    # Load the avro schema
    p_schema = Utils.load_schema(args.psf)

    # Initialize a CDM Translator
    translator = CDMTranslator(p_schema, CDMVERSION, args.host_type, args.session)

    # Make sure the translator is doing something
    if not (args.wj or args.wb or args.wk):
        logger.warning("Translator will run, but produce no output.")

    # Load the input file
    if args.kin:
        wj = JsonOutput(args.odir) if args.wj else None
        wb = BinaryOutput(args.odir) if args.wb else None
        wk = KafkaOutput(args.kouts, args.ktopic, args.kmetrics, args.kmyip, args.koutssl) if args.wk else None
        rk = KafkaInput(args.kins, args.kintopic, args.kmetrics, args.kmyip, args.kinssl)
        try:
            translate_kafka(translator, rk, wj, wb, wk, args.p, args.validate)
        except KeyboardInterrupt: # handle ctrl+c
            for thread in threading.enumerate():
                if thread is not threading.main_thread():
                    thread.join()
    elif args.f is None:
        cfiles = [cf for cf in os.listdir(args.tdir) if isfile(os.path.join(args.tdir, cf))]
        file_queue = queue.Queue()
        for cf in cfiles:
            file_queue.put(cf)
        if args.watch:
            observer = Observer()
            observer.schedule(EnqueueFileHandler(file_queue), path=os.path.expanduser(args.tdir), recursive=False)
            observer.start()
        minutes_since_last_file = 0
        threads = []
        try:
            while args.watch or not file_queue.empty():
                try:
                    # wait up to 60 seconds for a file
                    # triggers queue.Empty exception if no files are in the queue.
                    cfile = file_queue.get(True, 60)
                    _, fext = os.path.splitext(cfile)
                    if args.p and minutes_since_last_file > 0:
                        sys.stdout.write("\n")
                        minutes_since_last_file = 0
                    if cfile.endswith(".cdm.json") or fext != ".json":
                        logger.info("Skipping file: %s", cfile)
                    else:
                        logger.info("Translating JSON file: %s", cfile)
                        path = os.path.join(args.tdir, cfile)
                        translator = CDMTranslator(p_schema, CDMVERSION, args.host_type, args.session)
                        wj = JsonOutput(args.odir) if args.wj else None
                        wb = BinaryOutput(args.odir) if args.wb else None
                        wk = KafkaOutput(args.kouts, args.ktopic, args.kmetrics, args.kmyip, args.koutssl) if args.wk else None
                        fi = FileInput(path, args.watch)

                        work_thread = Process(target=translate_file, args=(translator, fi, wj, wb, wk, args.p, args.validate))
                        work_thread.start()
                        threads.append(work_thread)
                        logger.info("About %d files left to translate.", file_queue.qsize())
                except queue.Empty:
                    if args.p:
                        minutes_since_last_file += 1
                        sys.stdout.write("\r%d minute(s) without a file to translate.", minutes_since_last_file)
                        sys.stdout.flush()
                    time.sleep(60)

        except KeyboardInterrupt: # handle ctrl+c
            if args.watch:
                observer.stop()
                observer.join()
            for thread in threading.enumerate():
                if thread is not threading.main_thread():
                    thread.join()

    else:
        path = os.path.join(args.tdir, args.f)
        wj = JsonOutput(args.odir) if args.wj else None
        wb = BinaryOutput(args.odir) if args.wb else None
        wk = KafkaOutput(args.kouts, args.ktopic, args.kmetrics, args.kmyip, args.koutssl) if args.wk else None
        rf = FileInput(path, args.watch)
        translate_file(translator, rf, wj, wb, wk, args.p, args.validate)


class EnqueueFileHandler(FileSystemEventHandler):
    def __init__(self, file_queue):
        super(FileSystemEventHandler, self).__init__()
        self.file_queue = file_queue
    def on_created(self, event):
        if not event.is_directory:
            new_file = event.src_path
            self.file_queue.put(new_file)

def setup_outputs(input_file, read_kafka, write_json, write_binary, write_kafka, p_schema, validate):
    if input_file:
        base_out = os.path.splitext(os.path.basename(input_file.path))[0]
    elif read_kafka:
        base_out = read_kafka.topic

    # Open the output files
    json_out = None
    bin_out = None
    producer = None
    config = None
    file_writer = None
    if write_json:
        json_out_path = os.path.join(write_json.output_dir, base_out+".cdm.json")
        json_out = open(os.path.expanduser(json_out_path), 'w')
    if write_binary:
        bin_out_path = os.path.join(os.path.expanduser(write_binary.output_dir), base_out+".cdm.bin")
        bin_out = open(bin_out_path, 'wb')
        # Create a file writer and serialize all provided records to it.
        file_writer = AvroGenericSerializer(p_schema, bin_out, skip_validate=not validate)
    if write_kafka:
        # Set up the config for the Kafka producer
        config = {}
        config["bootstrap.servers"] = write_kafka.conn_str
        config["api.version.request"] = True
        config["client.id"] = PRODUCER_ID
        if write_kafka.use_ssl:
            config["ssl.ca.location"] = CA_CERT_LOCATION
            config["ssl.certificate.location"] = CERT_LOCATION
            config["ssl.key.location"] = KEY_LOCATION
            config["ssl.key.password"] = KEY_PASSWORD
            config["security.protocol"] = "ssl"
# see https://github.com/edenhill/librdkafka/blob/master/CONFIGURATION.md
#         config["socket.keepalive.enable"] = True
#         config["log.connection.close"] = False
#         config["error_cb"] = None # Function Poiter
#         config["queue.buffering.max.ms"] = 10
        producer = confluent_kafka.Producer(config)
    return (json_out, bin_out, file_writer, producer)

def translate_kafka(translator, read_kafka, write_json, write_binary, write_kafka, show_progress, validate):
    p_schema = translator.schema
    # Initialize an avro serializer, this will be used to write out the CDM records
    serializer = KafkaAvroGenericSerializer(p_schema, skip_validate=not validate)

    (json_out, bin_out, file_writer, producer) = setup_outputs(None, read_kafka, write_json, write_binary, write_kafka, p_schema, validate)

    incount = 0
    cdmcount = 0

    config = {}
    config["bootstrap.servers"] = read_kafka.conn_str
    config["api.version.request"] = True
    if read_kafka.use_ssl:
        config["ssl.ca.location"] = CA_CERT_LOCATION
        config["ssl.certificate.location"] = CERT_LOCATION
        config["ssl.key.location"] = KEY_LOCATION
        config["ssl.key.password"] = KEY_PASSWORD
        config["security.protocol"] = "ssl"
    config["group.id"] = GROUP_ID
    config["default.topic.config"] = {"auto.offset.reset": "beginning"}

    consumer = confluent_kafka.Consumer(config)
    consumer.subscribe([read_kafka.topic])

    # Read the JSON CADETS records
    logger.info("Loading records from %s", read_kafka.topic)
    # Iterate through the records, translating each to a CDM record
    waiting = False # are we already waiting to find another value record?
    start_time = time.perf_counter()
    current_location = None
    while 1:
        try:
            raw_cadets_record = consumer.poll(timeout=20)
            if not raw_cadets_record:
                # If we caught up with realtime, print a message if we stay caught up with realtime
                if waiting:
                    logger.debug("So far, translated %d records into %d CDM items (%.2f records/sec)", incount, cdmcount, float(incount) / (time.perf_counter()-start_time))
                    if current_location:
                        logger.warning("No more records found at offset %d", current_location)
                    else:
                        logger.warning("No more records found at unknown offset")
                waiting = True
                continue
            elif not raw_cadets_record.error():
                current_location = raw_cadets_record.offset()
                logger.debug("Record read: %s", str(raw_cadets_record.value()))
                (cdm_inc, err) = handle_record(raw_cadets_record.value(), translator, incount, write_kafka, serializer, json_out, file_writer, producer, show_progress)
                if err:
                    logger.warning("Error: %s", err)
                    logger.warning("Invalid CADETS entry at offset %d: %s", current_location, raw_cadets_record.value())
                    continue
                else:
                    incount += 1
                    cdmcount += cdm_inc
                    waiting = False
            else:
                logger.warn("KafkaError: %s", raw_cadets_record.error())

        except (AttributeError, TypeError, UnicodeDecodeError) as err:
            # Skip the entry, but warn about it.
            if current_location:
                logger.warning("Undecodable CADETS entry at offset %d: %s", current_location, err)
            else:
                logger.warning("Undecodable CADETS entry at unknown offset: %s", err)
            continue
        except KeyboardInterrupt: # handle ctrl+c
            logger.info("Stopping")
            break

    consumer.close()

    if show_progress and incount >= 1000:
        sys.stdout.write("\n")
    logger.info("Translated %d records into %d CDM items (%.2f records/sec)", incount, cdmcount, float(incount) / (time.perf_counter()-start_time))

    close_outputs(write_kafka, json_out, bin_out, file_writer, producer)

def close_outputs(write_kafka, json_out, bin_out, file_writer, producer):
    if json_out != None:
        json_out.close()
        logger.info("Wrote JSON CDM records to {jo}".format(jo=json_out.name))
    if bin_out != None:
        file_writer.close_file_serializer()
        bin_out.close()
        logger.info("Wrote binary CDM records to {bo}".format(bo=bin_out.name))
    if write_kafka:
        producer.flush()
        logger.info("Wrote CDM records to kafka {to}".format(to=write_kafka.topic))


def translate_file(translator, input_file, write_json, write_binary, write_kafka, show_progress, validate):
    p_schema = translator.schema
    # Initialize an avro serializer, this will be used to write out the CDM records
    serializer = KafkaAvroGenericSerializer(p_schema, skip_validate=not validate)

    (json_out, bin_out, file_writer, producer) = setup_outputs(input_file, None, write_json, write_binary, write_kafka, p_schema, validate)

    incount = 0
    cdmcount = 0

    # Read the JSON CADETS records
    with open(file=input_file.path, mode='r', buffering=1, errors='ignore') as cadets_in:
        logger.info("Loading records from %s", cadets_in.name)
        # Iterate through the records, translating each to a CDM record
        waiting = False # are we already waiting to find another value record?
        last_error_location = -1
        start_time = time.perf_counter()
        while 1:
            current_location = cadets_in.tell()
            try:
                raw_cadets_record = cadets_in.readline()
            except UnicodeDecodeError as err:
                # Skip the entry, but warn about it.
                logger.warning("Undecodable CADETS entry at byte %d: %s", current_location, err)
                continue
            if raw_cadets_record:
                (cdm_inc, err) = handle_record(raw_cadets_record, translator, incount, write_kafka, serializer, json_out, file_writer, producer, show_progress)
                if err:
                    if input_file.watch and current_location > last_error_location:
                        last_error_location = current_location
                        cadets_in.seek(current_location)
                        time.sleep(10)
                        continue
                    if raw_cadets_record.strip():
                        logger.warning("Error: %s", err)
                        logger.warning("Invalid CADETS entry at byte %d: %s", current_location, raw_cadets_record)
                    continue
                else:
                    cdmcount += cdm_inc
                    incount += 1
                    waiting = False
            else:
                # If we reached the actual EOF and we're waiting for the file to finish, reset the file location and retry.
                # If we reached the actual EOF and we're not waiting, then just consider this file finished.
                if not waiting:
                    logger.warning("No more records found at byte %d", current_location)
                    waiting = True
                if input_file.watch and current_location > last_error_location:
                    last_error_location = current_location
                    cadets_in.seek(current_location)
                    time.sleep(30)
                else:
                    break

        # no more lines in the file. Is it really done, or should we wait for more lines?
        cadets_in.close()

    if show_progress and incount >= 1000:
        sys.stdout.write("\n")
    logger.info("Translated %d records into %d CDM items (%.2f records/sec)", incount, cdmcount, float(incount) / (time.perf_counter()-start_time))

    close_outputs(write_kafka, json_out, bin_out, file_writer, producer)

def handle_record(raw_cadets_record, translator, incount, write_kafka, serializer, json_writer, binary_writer, producer, show_progress):
    try:
        cadets_record = json.loads(raw_cadets_record)
    except ValueError as err:
        return (None, err)

    logger.debug("%d Record: %s", incount, cadets_record)
    cdm_records = translator.translate_record(cadets_record)
    logger.debug("%d translated to %d records", incount, len(cdm_records))

    if json_writer:
        write_cdm_json_records(cdm_records, serializer, json_writer, incount)
    if binary_writer:
        write_cdm_binary_records(cdm_records, binary_writer)
    if write_kafka:
        write_kafka_records(cdm_records, producer, serializer, incount, write_kafka.topic, write_kafka.myip, write_kafka.enable_metrics)

    incount += 1
    if show_progress and incount % 1000 == 0:
        sys.stdout.write("\rRead and translated >=%d records so far" % incount)
        sys.stdout.flush()

    return (len(cdm_records), None)

def write_cdm_json_records(cdm_records, serializer, json_out, incount):
    ''' Write an array of CDM records to a json output file via a serializer '''
    for cdm_record in cdm_records:
        if cdm_record != None:
            logger.debug("%d -> Translated CDM record: %s", incount, cdm_record)
            jout = serializer.serialize_to_json(cdm_record)
            json_out.write(jout+"\n")

def write_cdm_binary_records(cdm_records, file_writer):
    ''' Write an array of CDM records to a binary output file via a datum writer '''
    for cdm_record in cdm_records:
        if cdm_record != None:
            file_writer.serialize_to_file(cdm_record)


# Prometheus metric for generated records published to kafka
registry = CollectorRegistry()
ta1_send = Counter('ta1_send_total', 'Count of records sent', ['topic', 'host'], registry=registry)
ta1_last = Gauge('ta1_last_send_time', 'Last publish time', ['topic', 'host'], registry=registry)

def write_kafka_records(cdm_records, producer, serializer, kafka_key, topic, myip, enable_metrics):
    '''
    Write an array of CDM records to Kafka
    '''
    for edge in cdm_records:
        # Serialize the record
        message = serializer.serialize(topic, edge)
        ta1_send.labels(topic, myip).inc()
        ta1_last.labels(topic, myip).set_to_current_time()
        producer.produce(topic, value=message, key=str(kafka_key).encode())
        producer.poll(0)
    # TODO: Parameters
    try:
        if enable_metrics:
            push_to_gateway('ta3-prometheus-1.tc.bbn.com:3332', job='ta1-cadets', registry=registry)
    except Exception as ex:
        enable_metrics = False
        logger.warning(str(ex))
        logger.warning("Unable to connect to prometheus, disabling metrics push 2")

if __name__ == '__main__':
    main()
