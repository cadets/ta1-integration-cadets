#!/usr/local/bin/python3

"""
Load in trace records in CDM json format and sanity check them

Won't catch all possible errors, but should help
"""

import logging
from logging.config import fileConfig
import argparse
import os
import json

from tc.schema.serialization import Utils
from tc.schema.serialization.kafka import KafkaAvroGenericDeserializer

from translator import CDMTranslator

# Default values, replace or use command line arguments
SCHEMA = "../../ta3-serialization-schema/avro/TCCDMDatum.avsc"
LOGGING_CONF = "logging.conf"
CDMVERSION = "13"

logger = logging.getLogger("tc")

def get_arg_parser():
    parser = argparse.ArgumentParser(description="Translate CADETS json to CDM")

    parser.add_argument("-psf", action="store", type=str,
                        default=SCHEMA,
                        help="Set the producer's schema file.")
    parser.add_argument("-v", action="store_true", default=False,
                        help="Turn up verbosity.")
    parser.add_argument("-lc", action="store", type=str, default=LOGGING_CONF,
                        help="Logging configuration file")
    parser.add_argument("-cdmv", action="store", type=str, default=CDMVERSION,
                        help="CDM Version number, make sure this matches the schema file you set with psf")
    parser.add_argument("files", nargs="+", help="files to check")

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
    translator = CDMTranslator(p_schema, args.cdmv)

    for cfile in args.files:
    # Load the input file
        path = os.path.expanduser(cfile)
        examine_file(translator, path)

referenced_uuids = {}

def examine_file(translator, path):
    '''
    Go through file line-by-line to check each record and look for any warning signs
    '''
    logger.info("Examining JSON file: "+path)
    p_schema = translator.schema
    # Initialize an avro serializer, this will be used to write out the CDM records
    deserializer = KafkaAvroGenericDeserializer(p_schema, p_schema)

    # Read the JSON CADETS records
    with open(path, 'r') as cadets_in:
        referenced_uuids.clear()
        incount = 0
        # Iterate through the records, translating each to a CDM record
        while 1:
            raw_record = cadets_in.readline()
            if not raw_record:
                break
            if raw_record == "\n":
                continue

            incount = incount + 1

            try:
                cadets_record = json.loads(raw_record)
            except ValueError:
                logger.warn("Invalid CDM entry: " + raw_record)
                continue

            validated = examine_record(translator, cadets_record)
            if not validated:
                logger.warn("Check record #" + str(incount) + ": " + raw_record)

        cadets_in.close()
#         logger.info("referenced_uuids size: " + str(len(referenced_uuids)))


def examine_record(translator, record):
    '''
    Check if there is anything unexpected about the record

    Returns True if the record looks normal
    '''
    if not record.get("datum"):
        # Everything should have a datum. Why is it missing?
        return False

    details = record["datum"]

    if details.get("baseObject"):
        referenced_uuids[details["uuid"]] = "FILE"
        if details["uuid"] == "00000000000000000000000000000000":
            logger.warn("Was trace run on a file system with UFS?")
            return False
        return True

    if not details.get("type"):
        # Everything but files should have a "type"
        logger.warn("Record has no type")
        return False

    record_type = details["type"]

    if record_type.startswith("EVENT"):
        referenced_uuids[details["uuid"]] = "EVENT"
    elif record_type.startswith("EDGE"):
        if not referenced_uuids.get(details["toUuid"]):
            logger.warn("Edge to an unknown node")
            referenced_uuids[details["toUuid"]] = "UNKNOWN"
            return False
        if not referenced_uuids.get(details["fromUuid"]):
            logger.warn("Edge from an unknown node")
            referenced_uuids[details["fromUuid"]] = "UNKNOWN"
            return False
    elif record_type == "SUBJECT_PROCESS":
        referenced_uuids[details["uuid"]] = "PROCESS"
    elif record_type == "PRINCIPAL_LOCAL":
        referenced_uuids[details["uuid"]] = "PRINCIPAL"

    return True

if __name__ == '__main__':
    main()

