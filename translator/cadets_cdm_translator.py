#!/usr/local/bin/python3

"""
Load in trace records in CADETS json format, translate them to CDM format, and write the CDM records to a file
  Outputs a JSON CDM format and the binary avro format

"""

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import queue
import logging
import time
from logging.config import fileConfig
import argparse
import os
from os.path import isfile
import json

import sys
#sys.path.insert(0, '../../ta3-api-bindings-python')

from tc.schema.serialization import AvroGenericSerializer, Utils
from tc.schema.serialization.kafka import KafkaAvroGenericSerializer

from pykafka import KafkaClient
from pykafka.partitioners import HashingPartitioner

from translator import CDMTranslator

# Default values, replace or use command line arguments
TRACE_DIR = "../../trace-data"
IN_FILE = None
SCHEMA = "../../ta3-serialization-schema/avro/TCCDMDatum.avsc"
OUTPUT_DIR = "../../trace-data"
LOGGING_CONF = "logging.conf"
CDMVERSION = "13"
KAFKASTRING = "129.55.12.59:9092"
TOPIC = "ta1-cadets-cdm13"

logger = logging.getLogger("tc")

def get_arg_parser():
    parser = argparse.ArgumentParser(description="Translate CADETS json to CDM")

    parser.add_argument("-psf", action="store", type=str,
                        default=SCHEMA,
                        help="Set the producer's schema file.")
    parser.add_argument("-v", action="store_true", default=False,
                        help="Turn up verbosity.")
    parser.add_argument("-tdir", action="store", type=str, default=TRACE_DIR,
                        help="Directory to load CADETS record files from")
    parser.add_argument("-odir", action="store", type=str, default=OUTPUT_DIR,
                        help="Directory to write CDM records files to")
    parser.add_argument("-f", action="store", type=str, default=IN_FILE,
                        help="File to translate, default is to translate every file in the directory that ends with .json")
    parser.add_argument("-lc", action="store", type=str, default=LOGGING_CONF,
                        help="Logging configuration file")
    parser.add_argument("-wj", action="store_true", default=False, help="Write JSON output file")
    parser.add_argument("-wb", action="store_true", default=False, help="Write binary output file")
    parser.add_argument("-wk", action="store_true", default=False, help="Write to Kafka")
    parser.add_argument("-ks", action="store", default=KAFKASTRING, help="Kafka connection string")
    parser.add_argument("-ktopic", action="store", type=str, default=TOPIC,
                        help="Kafka topic to publish to")
    parser.add_argument("-cdmv", action="store", type=str, default=CDMVERSION,
                        help="CDM Version number, make sure this matches the schema file you set with psf")
    parser.add_argument("-p", action="store_true", default=False, help="Print progress message for longer translations")
    parser.add_argument("-watch", action="store_true", default=False, help="Watch for new files in source tdir - not compatible with -f")

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
    translator = CDMTranslator(p_schema, args.cdmv)

    # Make sure the translator is doing something
    if not (args.wj or args.wb or args.wk):
        logger.warn("Translator will run, but produce no output.")

    # Load the input file
    if args.f is None:
        cfiles = [cf for cf in os.listdir(args.tdir) if isfile(os.path.join(args.tdir, cf))]
        file_queue = queue.Queue()
        for cf in cfiles:
            file_queue.put(cf)

        if args.watch:
            observer = Observer()
            observer.schedule(EnqueueFileHandler(file_queue), path=os.path.expanduser(args.tdir), recursive=True)
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
                        logger.info("Skipping file: "+cfile)
                    else:
                        logger.info("Translating JSON file: "+cfile)
                        path = os.path.join(args.tdir, cfile)
                        translate_file(translator, path, args.odir, args.wb, args.wj, args.wk, args.ks, args.ktopic, args.p, args.watch)
                        translator.reset()
                        logger.info("About "+str(file_queue.qsize())+" files left to translate.")
                except queue.Empty:
                    if args.p:
                        minutes_since_last_file += 1
                        sys.stdout.write("\r%d minute(s) without a file to translate." % minutes_since_last_file )
                        sys.stdout.flush()
                    time.sleep(1)

        except KeyboardInterrupt: # handle ctrl+c
            if args.watch:
                observer.stop()
                observer.join()

    else:
        path = os.path.join(args.tdir, args.f)
        translate_file(translator, path, args.odir, args.wb, args.wj, args.wk, args.ks, args.ktopic, args.p, args.watch)


class EnqueueFileHandler(FileSystemEventHandler):
    def __init__(self, file_queue):
        super(FileSystemEventHandler, self).__init__()
        self.file_queue = file_queue
    def on_created(self, event):
        if not event.is_directory:
            new_file = event.src_path
            self.file_queue.put(new_file)

def translate_file(translator, path, output_dir, write_binary, write_json, write_kafka, kafkastring, kafkatopic, show_progress, watch):
    p_schema = translator.schema
    # Initialize an avro serializer, this will be used to write out the CDM records
    serializer = KafkaAvroGenericSerializer(p_schema)

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
        file_writer = AvroGenericSerializer(p_schema, bin_out)
    if write_kafka:
        client = KafkaClient(kafkastring)
        # Create the topic in kafka if it doesn't already exist
        pykafka_topic = client.topics[kafkatopic.encode("utf-8")]
        producer = pykafka_topic.get_producer(
            partitioner=HashingPartitioner(), sync=False,
            linger_ms=1, ack_timeout_ms=30000, max_retries=0)
    incount = 0
    cdmcount = 0

    # Read the JSON CADETS records
    with open(path, 'r') as cadets_in:
        logger.info("Loading records from "+cadets_in.name)
        # Iterate through the records, translating each to a CDM record
        previous_record = ""
        while 1:
            current_location = cadets_in.tell()
            # XXX: Strip null from json record
            raw_cadets_record = cadets_in.readline().replace("\\0", "")
            if raw_cadets_record and len(raw_cadets_record) > 3 and raw_cadets_record != previous_record:
                try:
                    cadets_record = json.loads(raw_cadets_record[2:])
                except ValueError as err:
                    # if we expect the file to be added to, try again
                    # otherwise, give up on the line and continue
                    if watch:
                        cadets_in.seek(current_location)
                    else:
                        logger.warn("Invalid CADETS entry: " + raw_cadets_record)
                        logger.warn("Error was: " + str(err))
                    continue

                logger.debug("{i} Record: {data}".format(i=incount, data=cadets_record))
                cdm_records = translator.translate_record(cadets_record)
                logger.debug("{i} translated to {t1} records".format(i=incount, t1=len(cdm_records)))

                cdmcount += len(cdm_records)

                if write_json:
                    write_cdm_json_records(cdm_records, serializer, json_out, incount)
                if write_binary:
                    write_cdm_binary_records(cdm_records, file_writer)
                if write_kafka:
                    write_kafka_records(cdm_records, producer, serializer, incount, kafkatopic)

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
                    if watch:
                        cadets_in.seek(current_location)
                        time.sleep(1)
                    else:
                        break
                elif raw_cadets_record.strip() == "]":
                    break

        # no more lines in the file. Is it really done, or should we wait for more lines?
        cadets_in.close()

    if show_progress and incount >= 1000:
        sys.stdout.write("\n")
    logger.info("Translated {i} records into {ic} CDM items".format(i=incount, ic=cdmcount))

    if json_out != None:
        json_out.close()
        logger.info("Wrote JSON CDM records to {jo}".format(jo=json_out.name))

    if bin_out != None:
        file_writer.close_file_serializer()
        bin_out.close()
        logger.info("Wrote binary CDM records to {bo}".format(bo=bin_out.name))
    if write_kafka:
        producer.stop()
        logger.info("Wrote CDM records to kafka {to}".format(to=kafkatopic))

def write_cdm_json_records(cdm_records, serializer, json_out, incount):
    ''' Write an array of CDM records to a json output file via a serializer '''
    for cdm_record in cdm_records:
        if cdm_record != None:
            logger.debug("{i} -> Translated CDM record: {data}".format(i=incount, data=cdm_record))
            jout = serializer.serialize_to_json(cdm_record)
            json_out.write(jout+"\n")

def write_cdm_binary_records(cdm_records, file_writer):
    ''' Write an array of CDM records to a binary output file via a datum writer '''
    for cdm_record in cdm_records:
        if cdm_record != None:
            file_writer.serialize_to_file(cdm_record)

def write_kafka_records(cdm_records, producer, serializer, kafka_key, topic):
    '''
    Write an array of CDM records to Kafka
    '''
    for edge in cdm_records:
        # Serialize the record
        message = serializer.serialize(topic, edge)
        producer.produce(message, str(kafka_key).encode())

if __name__ == '__main__':
    main()
