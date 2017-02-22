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

# Default values, replace or use command line arguments
SCHEMA = "../../ta3-serialization-schema/avro/TCCDMDatum.avsc"
LOGGING_CONF = "logging.conf"
CDMVERSION = "15"

logger = logging.getLogger("tc")

def get_arg_parser():
    parser = argparse.ArgumentParser(description="Examine CDM json produced by CADETS")

    parser.add_argument("-v", action="store_true", default=False,
                        help="Turn up verbosity.")
    parser.add_argument("-lc", action="store", type=str, default=LOGGING_CONF,
                        help="Logging configuration file")
    parser.add_argument("files", nargs="+", help="files to check")

    return parser


def main():
    parser = get_arg_parser()
    args = parser.parse_args()

    # Set up logging
    fileConfig(args.lc)

    if args.v:
        logging.getLogger("tc").setLevel(logging.DEBUG)

    for cfile in args.files:
    # Load the input file
        path = os.path.expanduser(cfile)
        examine_file(path)

referenced_uuids = {}

def examine_file(path):
    '''
    Go through file line-by-line to check each record and look for any warning signs
    '''

    # Read the JSON CADETS records
    logger.info("Examining JSON file: "+path)
    with open(path, 'r') as cadets_in:
        referenced_uuids.clear()
        incount = 0
        # Iterate through the records, translating each to a CDM record
        while 1:
            raw_record = cadets_in.readline()
            if not raw_record: # EOF
                break
            if raw_record == "\n": # blank line
                continue

            incount = incount + 1

            try:
                cadets_record = json.loads(raw_record)
            except ValueError:
                logger.error("Invalid CDM entry: " + raw_record)
                continue

            if cadets_record["CDMVersion"] != CDMVERSION:
                logger.error("File is wrong CDM Version")
                break

            validated = examine_record(cadets_record)
            if not validated:
                logger.error("Check record #" + str(incount) + ": " + raw_record.strip())

        cadets_in.close()
#         logger.info("referenced_uuids size: " + str(len(referenced_uuids)))


def examine_record(record):
    '''
    Check if there is anything unexpected about the record

    Returns True if the record looks normal
    '''
    if not record.get("datum"):
        # Everything should have a datum. Why is it missing?
        return False

    record_type=None
    details = record["datum"]
    if details.get("Event"):
        details = details.get("Event")
    elif details.get("Subject"):
        details = details.get("Subject")
    elif details.get("SrcSinkObject"):
        details = details.get("SrcSinkObject")
    elif details.get("FileObject"):
        details = details.get("FileObject")
    elif details.get("Principal"):
        details = details.get("Principal")
    elif details.get("NetFlowObject"):
        details = details.get("NetFlowObject")
        record_type = "NetFlow"

    if details.get("baseObject"):
        referenced_uuids[details["uuid"]] = "FILE"
        if details["uuid"] == "00000000-0000-0000-0000-000000000000":
            logger.warn("Was trace run on a file system with UFS?")
            return False
        if not record_type:
            record_type = details["baseObject"].get("type")
        return True

    if not record_type:
        record_type = details.get("type")
        
    if not record_type:
        # Everything but files should have a "type"
        logger.warn("Record has no type")
        return False

    if record_type.startswith("EVENT"):
        referenced_uuids[details["uuid"]] = "EVENT"
        predicate1 = details.get("predicateObject")
        predicate2 = details.get("predicateObject2")
        if predicate1 and not referenced_uuids.get(predicate1.get("UUID")):
            logger.warn("Undefined uuid: %s", predicate1.get("UUID"))
            referenced_uuids[predicate1.get("UUID")] = "UNKNOWN"
            return False
        if predicate2 and not referenced_uuids.get(predicate2.get("UUID")):
            logger.warn("Undefined uuid: %s", predicate2.get("UUID"))
            referenced_uuids[predicate2.get("UUID")] = "UNKNOWN"
            return False
    elif record_type == "SUBJECT_PROCESS":
        referenced_uuids[details["uuid"]] = "PROCESS"
    elif record_type == "PRINCIPAL_LOCAL":
        referenced_uuids[details["uuid"]] = "PRINCIPAL"
    else:
        referenced_uuids[details["uuid"]] = "OTHER"

    return True

if __name__ == '__main__':
    main()

