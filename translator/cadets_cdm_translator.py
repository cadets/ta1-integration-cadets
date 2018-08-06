#!/usr/local/bin/python3

"""
Load in trace records in CADETS json format, translate them to CDM format, and
write the CDM records to a file

Outputs a JSON CDM format and the binary avro format

"""

import queue
import logging
from logging.config import fileConfig
import time
import argparse
import os
from os.path import isfile
import json

import sys

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from tc.schema.serialization import AvroGenericSerializer, Utils
from tc.schema.serialization.kafka import KafkaAvroGenericSerializer

import confluent_kafka

from prometheus_client import CollectorRegistry, Gauge, Counter, push_to_gateway

from translator import CDMTranslator

# Default values, replace or use command line arguments
TRACE_DIR = "../../trace-data"
IN_FILE = None
SCHEMA = "../../ta3-serialization-schema/avro/TCCDMDatum.avsc"
OUTPUT_DIR = "../../trace-data"
LOGGING_CONF = "logging.conf"
CDMVERSION = "19"
KAFKASTRING = "129.55.12.59:9092"
PRODUCER_ID = "cadets"
CA_CERT_LOCATION = "/var/private/ssl/ca-cert"
CERT_LOCATION = "/var/private/ssl/kafka.client.pem"
KEY_LOCATION = "/var/private/ssl/kafka.client.key"
KEY_PASSWORD = "TransparentComputing"
TOPIC = "ta1-cadets-cdm13"

logger = logging.getLogger("tc")

def get_arg_parser():
    parser = argparse.ArgumentParser(description="Translate CADETS json to CDM")

    parser.add_argument("--version", action="version", version="cadets_cdm_translator.py - CDMv"+CDMVERSION)
    parser.add_argument("-psf", action="store", type=str,
                        default=SCHEMA,
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
    kafka_settings.add_argument("-ks", action="store", default=KAFKASTRING,
                                required="-wk" in sys.argv, help="Kafka connection string")
    kafka_settings.add_argument("-ktopic", action="store", type=str, default=TOPIC,
                                required="-wk" in sys.argv, help="Kafka topic to publish to")
    kafka_settings.add_argument("-kmetrics", action="store_true", default=False,
                                help="Enable Kafka metrics")
    kafka_settings.add_argument("-kmyip", action="store", type=str, required="-wk" in sys.argv,
                                help="IP address to publish from")
    parser.add_argument("-punctuate", action="store", type=int, default=0,
                        help="Generate time markers, given the number of CPUs in the machine")
    parser.add_argument("-p", action="store_true", default=False,
                        help="Print progress message for longer translations")

    host_group_top = parser.add_argument_group('Host type (choose one)')
    host_group = host_group_top.add_mutually_exclusive_group(required=True)
    host_group.add_argument("-hs", "--host-server", dest='host_type', action="store_const", const="HOST_SERVER",
                            help="Host is a server.")
    host_group.add_argument("-hd", "--host-desktop", dest='host_type', action="store_const", const="HOST_DESKTOP",
                            help="Host is a desktop.")

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
    translator = CDMTranslator(p_schema, CDMVERSION, args.host_type)

    # Make sure the translator is doing something
    if not (args.wj or args.wb or args.wk):
        logger.warning("Translator will run, but produce no output.")

    # Load the input file
    if args.f is None:
        cfiles = [cf for cf in os.listdir(args.tdir) if isfile(os.path.join(args.tdir, cf))]
        file_queue = queue.Queue()
        for cf in cfiles:
            file_queue.put(cf)

        if args.watch:
            observer = Observer()
            observer.schedule(EnqueueFileHandler(file_queue), path=os.path.expanduser(args.tdir), recursive=False)
            observer.start()
        minutes_since_last_file = 0
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
                        logger.info("Skipping file: %s" , cfile)
                    else:
                        logger.info("Translating JSON file: %s" , cfile)
                        path = os.path.join(args.tdir, cfile)
                        translate_file(translator, path, args.odir, args.wb, args.wj, args.wk, args.ks, args.ktopic, args.kmetrics, args.kmyip, args.p, args.watch, args.punctuate, args.validate)
                        if not args.wk: # don't reset if we're just writing a stream of data to kafka
                            translator.reset()
                        logger.info("About %d files left to translate." , file_queue.qsize())
                except queue.Empty:
                    if args.p:
                        minutes_since_last_file += 1
                        sys.stdout.write("\r%d minute(s) without a file to translate." , minutes_since_last_file)
                        sys.stdout.flush()
                    time.sleep(10)

        except KeyboardInterrupt: # handle ctrl+c
            if args.watch:
                observer.stop()
                observer.join()

    else:
        path = os.path.join(args.tdir, args.f)
        translate_file(translator, path, args.odir, args.wb, args.wj, args.wk, args.ks, args.ktopic, args.kmetrics, args.kmyip, args.p, args.watch, args.punctuate, args.validate)


class EnqueueFileHandler(FileSystemEventHandler):
    def __init__(self, file_queue):
        super(FileSystemEventHandler, self).__init__()
        self.file_queue = file_queue
    def on_created(self, event):
        if not event.is_directory:
            new_file = event.src_path
            self.file_queue.put(new_file)

def translate_file(translator, path, output_dir, write_binary, write_json, write_kafka, kafkastring, kafkatopic, enable_metrics, myip, show_progress, watch, punctuate, validate):
    p_schema = translator.schema
    # Initialize an avro serializer, this will be used to write out the CDM records
    serializer = KafkaAvroGenericSerializer(p_schema, skip_validate=not validate)

    # Open the output files
    base_out = os.path.splitext(os.path.basename(path))[0]
    json_out = None
    bin_out = None
    if write_json:
        json_out_path = os.path.join(output_dir, base_out+".cdm.json")
        json_out = open(os.path.expanduser(json_out_path), 'w')
    if write_binary:
        bin_out_path = os.path.join(os.path.expanduser(output_dir), base_out+".cdm.bin")
        bin_out = open(bin_out_path, 'wb')
        # Create a file writer and serialize all provided records to it.
        file_writer = AvroGenericSerializer(p_schema, bin_out, skip_validate=not validate)
    if write_kafka:
        # Set up the config for the Kafka producer
        config = {}
        config["bootstrap.servers"] = kafkastring
        config["api.version.request"] = True
        config["client.id"] = PRODUCER_ID
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

    incount = 0
    cdmcount = 0

    # Read the JSON CADETS records
    with open(file=path, mode='r', buffering=1, errors='ignore') as cadets_in:
        logger.info("Loading records from %s" , cadets_in.name)
        # Iterate through the records, translating each to a CDM record
        previous_record = ""
        waiting = False # are we already waiting to find another value record?
        cpu_times = {}
        for i in range(1, punctuate):
            cpu_times[i] = 0
        last_time_marker = 0
        last_error_location = -1
        start_time = time.perf_counter()
        while 1:
            current_location = cadets_in.tell()
            try:
                raw_cadets_record = cadets_in.readline()
            except UnicodeDecodeError as err:
                # Skip the entry, but warn about it.
                logger.warning("Undecodable CADETS entry at byte %d: %s" , current_location, err)
                continue
            if raw_cadets_record:
                try:
                    cadets_record = json.loads(raw_cadets_record[2:])
                    record_cpu = cadets_record.get("cpu_id")
                    record_time = cadets_record.get("time")
                except ValueError as err:
                    # if we expect the file to be added to, try again
                    # otherwise, give up on the line and continue
                    if watch and current_location > last_error_location:
                        last_error_location = current_location
                        cadets_in.seek(current_location)
                        time.sleep(30)
                        continue
                    logger.warning("Error: %s" , err)
                    logger.warning("Invalid CADETS entry at byte %d: %s", current_location, raw_cadets_record)
                    continue

                waiting = False

                logger.debug("%d Record: %s" , incount, cadets_record)
                cdm_records = translator.translate_record(cadets_record)
                logger.debug("%d translated to %d records" , incount, len(cdm_records))

                if punctuate:
                    if  record_cpu is not None and record_time is not None:
                        cpu_times[record_cpu] = record_time
                    if record_time > last_time_marker + 1000001:
                        oldest_times = min(cpu_times.values())
                        if oldest_times > last_time_marker + 1000001:
                            time_marker = {}
                            time_marker["tsNanos"] = oldest_times - 1
                            record_wrapper = {}
                            record_wrapper["source"] = "SOURCE_FREEBSD_DTRACE_CADETS"
                            record_wrapper["CDMVersion"] = CDMVERSION
                            record_wrapper["datum"] = time_marker
                            cdm_records.append(record_wrapper)
                            last_time_marker = oldest_times

                cdmcount += len(cdm_records)

                if write_json:
                    write_cdm_json_records(cdm_records, serializer, json_out, incount)
                if write_binary:
                    write_cdm_binary_records(cdm_records, file_writer)
                if write_kafka:
                    write_kafka_records(cdm_records, producer, serializer, incount, kafkatopic, myip, enable_metrics)

                incount += 1
                previous_record = raw_cadets_record
                if show_progress and incount % 1000 == 0:
                    sys.stdout.write("\rRead and translated >=%d records so far" % incount)
                    sys.stdout.flush()
            else:
                # "]" marks the end of the records in the file, even if there are still more lines
                # If we find that, we're all done with the file.
                # If we reached the actual EOF and we're waiting for the file to finish, reset the file location and retry.
                # If we reached the actual EOF and we're not waiting, then just consider this file finished.
                if not raw_cadets_record:
                    if not waiting:
                        logger.warning("No more records found at byte %d" , current_location)
                        waiting = True
                    if watch and current_location > last_error_location:
                        last_error_location = current_location
                        cadets_in.seek(current_location)
                        time.sleep(30)
                    else:
                        break
                elif raw_cadets_record.strip() == "]":
                    break

        # no more lines in the file. Is it really done, or should we wait for more lines?
        cadets_in.close()

    if show_progress and incount >= 1000:
        sys.stdout.write("\n")
    logger.info("Translated %d records into %d CDM items (%.2f records/sec)" , incount, cdmcount, float(incount) / (time.perf_counter()-start_time))

    if json_out != None:
        json_out.close()
        logger.info("Wrote JSON CDM records to {jo}".format(jo=json_out.name))

    if bin_out != None:
        file_writer.close_file_serializer()
        bin_out.close()
        logger.info("Wrote binary CDM records to {bo}".format(bo=bin_out.name))
    if write_kafka:
        producer.flush()
        logger.info("Wrote CDM records to kafka {to}".format(to=kafkatopic))

def write_cdm_json_records(cdm_records, serializer, json_out, incount):
    ''' Write an array of CDM records to a json output file via a serializer '''
    for cdm_record in cdm_records:
        if cdm_record != None:
            logger.debug("%d -> Translated CDM record: %s" , incount, cdm_record)
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
