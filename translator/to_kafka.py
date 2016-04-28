#!/usr/bin/python

"""
A quick wrapper around 3 scripts
1)  Run events.d to generate the CADETS json output file
    Stop events.d after X time has passed
2)  Run cadets_cdm_translator to convert to CDM binary
3)  Run publish_from_file to push the CDM to kafka
 
Then loop back to 1 N times (-1 for infinite)

Note, this will cause gaps where events.d is not running (when steps 2 and 3 are)
However, this is intended for testing purposes only
"""


import logging
from logging.config import fileConfig
import argparse
import os
import subprocess
from os.path import isfile
import json
from threading import Timer
import signal

from tc.schema.serialization import Utils
from tc.schema.serialization.kafka import KafkaAvroGenericSerializer

from avro.io import DatumWriter
from avro.datafile import DataFileWriter

from translator import CDMTranslator
import cadets_cdm_translator

# Default values, replace or use command line arguments
DTRACE_SCRIPT_DIR = "/root/dtrace-scripts"
EVENTS_SCRIPT = "events.d"
CADETS_OUT = "output.json"
CDM_OUT = "cdm.bin"
SCHEMA = "/opt/starc/avro/TCCDMDatum.avsc"

KAFKASTRING="10.0.5.35:9092,10.0.5.36:9092,10.0.5.37:9092,10.0.5.38:9092,10.0.5.39:9092,10.0.5.40:9092"
TOPIC="CADETS"

EVENTS_RUN_TIME_SECS=60
ITERATIONS=5

LOGGING_CONF = "logging.conf"

logger = logging.getLogger("tc")

def tokafka_arg_parser():
    parser = argparse.ArgumentParser(description="Translate CADETS json to CDM")

    parser.add_argument("-psf", action="store", type=str,
            default=SCHEMA,
            help="Set the producer's schema file.")  
    parser.add_argument("-v", action="store_true", default=False,
            help="Turn up verbosity.")
    parser.add_argument("-d", action="store", type=str, default=DTRACE_SCRIPT_DIR,
                        help="Directory to run events capture script from")
    parser.add_argument("-script", action="store", type=str, default=EVENTS_SCRIPT,
                        help="Script file to generate events with")
    parser.add_argument("-so", action="store", type=str, default=CADETS_OUT,
                        help="Output file to write the events to")
    parser.add_argument("-co", action="store", type=str, default=CDM_OUT,
                        help="Output file to write the CDM events to")
    parser.add_argument("-lc", action="store", type=str, default=LOGGING_CONF,
                        help="Logging configuration file")
    parser.add_argument("-ks", action="store", type=str, default=KAFKASTRING,
                        help="Kafka connection string")
    parser.add_argument("-topic", action="store", type=str, default=TOPIC,
                        help="Kafka topic to publish to")
    parser.add_argument("-es", action="store", type=int, default=EVENTS_RUN_TIME_SECS,
                        help="Time to run the events.d script for")
    parser.add_argument("-n", action="store", type=int, default=ITERATIONS,
                        help="Number of event capture and publish loop iterations")

    return parser


def tokafka():
    parser = tokafka_arg_parser()
    args = parser.parse_args()

    # Set up logging
    fileConfig(args.lc)
    
    if args.v:
        logging.getLogger("tc").setLevel(logging.DEBUG)
   
    # Load the avro schema
    p_schema = Utils.load_schema(args.psf)
    
    # Initialize a CDM Translator
    translator = CDMTranslator(p_schema)
    
    # Load the input file
    i=0
    while args.n < 0 or i < args.n:
        run_events_script(args.d, args.script, args.so, args.es)
        
        run_cdm_translator(translator, args.d, p_schema, args.so, args.co)

        run_kafka_publish(args.d, args.co, p_schema, args.ks, args.topic)

        i=i+1

def run_events_script(events_dir, events_script, output, timeout):
    cmd="{d}/{s}".format(d=events_dir, s=events_script, o=output)
    logger.info("Executing command: "+cmd)

    fout = open(os.path.join(events_dir, output), 'w')
    
    proc = subprocess.Popen(cmd, shell=True, cwd=events_dir, stdout=fout, stderr=subprocess.PIPE)
    logger.info("Proc created: "+str(proc.pid))
    
    timer = Timer(timeout, ctrlc, [proc])
    try:
        logger.info("Starting timer, waiting for "+str(timeout))
        timer.start()
        proc.wait()
    finally:
        timer.cancel()

def ctrlc(proc):
    logger.info("Sending control-c to "+str(proc.pid))
    proc.send_signal(signal.SIGTERM)
    logger.info("Done")

def run_cdm_translator(translator, events_dir, schema, output, cdm_output):
    logger.info("Running CDM Translator")
    cadets_cdm_translator.translate_file(translator, os.path.join(events_dir, output), events_dir, True, False)

def run_kafka_publish(event_dir, cdm_output, schema, kafkastring, topic):
    deserializer = KafkaAvroGenericDeserializer(p_schema)
    client=KafkaClient(kafkastring)
    
    # Create the topic in kafka if it doesn't already exist
    pykafka_topic = client.topics[topic]
    
    producer = pykafka_topic.get_producer(
        partitioner=HashingPartitioner(), sync=False,
        linger_ms = 1, ack_timeout_ms=30000, max_retries=0)
    
    logger.info("Starting producer.")

    rfile = open(os.path.join(events_dir, cdm_output), 'r')
    records = deserializer.deserialize_from_file(rfile)

    i = 0
    for edge in records:
        # Provide a key for the record, this will determine which partition the record goes to
        kafka_key = str(i).encode()
        i = i + 1

        # Serialize the record
        message = serializer.serialize(topic, edge)

        if logger.isEnabledFor(logging.DEBUG):
            msg = "Attempting to send record k: {key}, value: {value}" \
                .format(key=kafka_key, value=edge)
            logger.debug(msg)

        producer.produce(message, kafka_key)
            
    producer.stop()
    rfile.close()
    logger.info("Wrote "+str(i)+" records to "+topic)


tokafka()
