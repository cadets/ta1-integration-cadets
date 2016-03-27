#!/usr/bin/python

"""
Load in trace records in CADETS json format, translate them to CDM format, and write the CDM records to a file
  Outputs a JSON CDM format and the binary avro format
  
"""

import logging
from logging.config import fileConfig
import argparse
import os
import json

from tc.schema.serialization import Utils
from tc.schema.serialization.kafka import KafkaAvroGenericSerializer

from avro.io import DatumWriter
from avro.datafile import DataFileWriter

from translator import CDMTranslator

# Default values, replace or use command line arguments
TRACE_DIR = "../../trace-data"
IN_FILE = "git_server.json"
SCHEMA = "/opt/starc/avro/TCCDMDatum.avsc"
OUTPUT_DIR = "output"
LOGGING_CONF = "logging.conf"

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
                        help="File to translate")
    parser.add_argument("-lc", action="store", type=str, default=LOGGING_CONF,
                        help="Logging configuration file")
    parser.add_argument("-wj", action="store_true", default=True, help="Write JSON output file")
    parser.add_argument("-wb", action="store_true", default=True, help="Write binary output file")
        
    return parser


def main():
    parser = get_arg_parser()
    args = parser.parse_args()

    # Set up logging
    fileConfig(args.lc)
    
    if args.v:
        logging.getLogger("tc").setLevel(logging.DEBUG)
   
    logger = logging.getLogger("tc")
    
    # Load the avro schema
    p_schema = Utils.load_schema(args.psf)
    
    # Initialize an avro serializer, this will be used to write out the CDM records
    serializer = KafkaAvroGenericSerializer(p_schema)
    
    # Initialize a CDM Translator
    translator = CDMTranslator(p_schema)
    
    # Load the input file
    path = os.path.join(args.tdir, args.f)    
    
    # Read the JSON CADETS records
    with open(path, 'r') as cadets_in:
        logger.info("Loading records from "+cadets_in.name)
        cadets_records = json.load(cadets_in)
        cadets_in.close()
        
    # Open the output files
    base_out = os.path.basename(path)
    json_out = None
    bin_out = None
    if args.wj:
        json_out_path = os.path.join(args.odir, base_out+".CDM.json")
        json_out = open(json_out_path, 'w')
    if args.wb:
        bin_out_path = os.path.join(args.odir, base_out+".CDM.bin")
        bin_out = open(bin_out_path, 'w')
        # Create a file writer and serialize all provided records to it.
        datum_writer = DatumWriter(p_schema)
        file_writer = DataFileWriter(bin_out, datum_writer, p_schema)

    # Iterate through the records, translating each to a CDM record
    count = 0
    for cadets_record in cadets_records:
        logger.debug("{i} Record: {data}".format(i=count, data=cadets_record))
        cdm_records = translator.translate_record(cadets_record)
        
        for cdm_record in cdm_records:
            if cdm_record != None:
                logger.debug("{i} Translated record: {data}".format(i=count, data=cdm_record))
                count += 1
        
                if args.wj:
                    # Serialize the record
                    jout = serializer.serialize_to_json(cdm_record)
                    json_out.write(jout+"\n")
        
                if args.wb:
                    file_writer.append(cdm_record)
            
        
    logger.info("Translated {i} records".format(i=count))
   
    if json_out != None:
        json_out.close()
        logger.info("Wrote JSON CDM records to {jo}".format(jo=json_out.name))
         
    if bin_out != None:
        file_writer.flush()
        file_writer.close()
        bin_out.close()
        logger.info("Wrote binary CDM records to {bo}".format(bo=bin_out.name))
        
main()