# Building CADETS
Instructions for building CADETS from scratch are [here](https://git.tc.bbn.com/bbn/ta1-integration-cadets/wikis/buildcadets)

# CADETS example trace data
Available at https://github.com/cadets/trace-data

The trace data is available in both the initial CADETS-specific format, as well as in both the json and binary CDM formats.

# CDM Translator
This is a python translator program that takes a CADETS trace as input and
outputs records in the CDM format.

Run the translator with `python3 cadets_cdm_translator.py --help` to see all the options.

Some default values for the arguments can be found below:
```
TRACE_DIR = "../../trace-data"
IN_FILE = None
SCHEMA = "../../ta3-serialization-schema/avro/TCCDMDatum.avsc"
OUTPUT_DIR = "../../trace-data"
LOGGING_CONF = "logging.conf"
KAFKASTRING = "129.55.12.59:9092"
TOPIC = "ta1-cadets-cdm13"
```

Other configuration settings, such as the ones related to SSL, are not expected
to change, and can only be changed in the source code.

```
CDMVERSION = "19"
GROUP_ID = "CADETS_"+str(subprocess.getoutput(['sysctl -n kern.hostuuid']))
PRODUCER_ID = "cadets"
CA_CERT_LOCATION = "/var/private/ssl/ca-cert"
CERT_LOCATION = "/var/private/ssl/kafka.client.pem"
KEY_LOCATION = "/var/private/ssl/kafka.client.key"
KEY_PASSWORD = "TransparentComputing"
```

# CDM translation
Details of the CADETS-to-CDM translation will be stored [here](https://git.tc.bbn.com/tc-all/cdm-docs/tree/master/ta1-cadets)

# Input

The translator can take as input a single file, a folder, or a kafka stream.

Only one input option can be used.

# Output

The translator can produce CDM data in binary or json format, or can write CDM to kafka.

Any number of output options can be selected.

# Publishing to Kafka

```
python3 ./cadets_cdm_translator.py [input options] -wk -kouts localhost:9092 -kmyip 192.168.1.102 -ktopic test-cdm4 [other options]
```

# Consuming from Kafka

```
python3 ./cadets_cdm_translator.py -kin -kintopic test-cadets4 -kins localhost:9092 [output options] [other options]
```
