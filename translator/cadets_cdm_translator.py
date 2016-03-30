#!/usr/bin/python

"""
Load in trace records in CADETS json format, translate them to CDM format, and write the CDM records to a file
  Outputs a JSON CDM format and the binary avro format
  
"""

import logging
from logging.config import fileConfig
import argparse
import os
from os.path import isfile
import json

from tc.schema.serialization import Utils
from tc.schema.serialization.kafka import KafkaAvroGenericSerializer

from avro.io import DatumWriter
from avro.datafile import DataFileWriter

from translator import CDMTranslator

# Default values, replace or use command line arguments
TRACE_DIR = "../../trace-data"
IN_FILE = None
SCHEMA = "../../ta3-serialization-schema/avro/TCCDMDatum.avsc"
OUTPUT_DIR = "output"
LOGGING_CONF = "logging.conf"

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
   
    # Load the avro schema
    p_schema = Utils.load_schema(args.psf)
    
    # Initialize a CDM Translator
    translator = CDMTranslator(p_schema)
    
    # Load the input file
    
    if args.f == None:
        cfiles = [cf for cf in os.listdir(args.tdir) if isfile(os.path.join(args.tdir, cf))]
        for cfile in cfiles:
            _, fext = os.path.splitext(cfile)
            if fext == ".json":
                logger.info("Translating JSON file: "+cfile)
                path = os.path.join(args.tdir, cfile)
                translate_file(translator, path, args.odir, args.wb, args.wj)
                translator.reset()
                
    else:    
        path = os.path.join(args.tdir, args.f)
        translate_file(translator, path, args.odir, args.wb, args.wj)
        
        
def translate_file(translator, path, output_dir, write_binary, write_json):
    p_schema = translator.schema
    # Initialize an avro serializer, this will be used to write out the CDM records
    serializer = KafkaAvroGenericSerializer(p_schema)
    
    # Read the JSON CADETS records
    with open(path, 'r') as cadets_in:
        logger.info("Loading records from "+cadets_in.name)
        cadets_records = json.load(cadets_in)
        cadets_in.close()
        
    # Open the output files
    base_out = os.path.basename(path)
    json_out = None
    bin_out = None
    if write_json:
        json_out_path = os.path.join(output_dir, base_out+".CDM.json")
        json_out = open(json_out_path, 'w')
    if write_binary:
        bin_out_path = os.path.join(output_dir, base_out+".CDM.bin")
        bin_out = open(bin_out_path, 'w')
        # Create a file writer and serialize all provided records to it.
        datum_writer = DatumWriter(p_schema)
        file_writer = DataFileWriter(bin_out, datum_writer, p_schema)

    # Iterate through the records, translating each to a CDM record
    
    incount = 0
    cdmcount = 0
    
    for cadets_record in cadets_records:
        logger.debug("{i} Record: {data}".format(i=incount, data=cadets_record))
        cdm_records = translator.translate_record(cadets_record)
        more_records = translator.handle_entry_match()
        logger.debug("{i} translated to {t1} records, plus {t2} records from earlier events".format(i=incount, t1=len(cdm_records), t2=len(more_records)))
        
        if more_records != None:
            for m_record in more_records:
                cdm_records.append(m_record)
            
        cdmcount += len(cdm_records)
        
        if write_json:
            write_cdm_json_records(cdm_records, serializer, json_out, incount)
        if write_binary:
            write_cdm_binary_records(cdm_records, file_writer, bin_out)
            
        incount += 1
                        
    # Finish by generating events for any entry that we haven't yet received a return for
    final_records = translator.handle_entry_match(True)
    if final_records != None:
        logger.debug("Adding {i} more records from entry events with no return".format(i=len(final_records)))
        cdmcount += len(final_records)
        if write_json:
            write_cdm_json_records(cdm_records, serializer, json_out, incount)
        if write_binary:
            write_cdm_binary_records(cdm_records, file_writer, bin_out)
    
    logger.info("Translated {i} records into {ic} CDM items".format(i=incount, ic=cdmcount))
   
    if json_out != None:
        json_out.close()
        logger.info("Wrote JSON CDM records to {jo}".format(jo=json_out.name))
         
    if bin_out != None:
        file_writer.flush()
        file_writer.close()
        bin_out.close()
        logger.info("Wrote binary CDM records to {bo}".format(bo=bin_out.name))
        
def write_cdm_json_records(cdm_records, serializer, json_out, incount):
    ''' Write an array of CDM records to a json output file via a serializer '''
    for cdm_record in cdm_records:
        if cdm_record != None:
            logger.debug("{i} -> Translated CDM record: {data}".format(i=incount, data=cdm_record))
            
            jout = serializer.serialize_to_json(cdm_record)
            json_out.write(jout+"\n")
    
def write_cdm_binary_records(cdm_records, file_writer, bin_out):
    ''' Write an array of CDM records to a binary output file via a datum writer '''
    for cdm_record in cdm_records:
        if cdm_record != None:    
            file_writer.append(cdm_record)
        
        
main()