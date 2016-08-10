# Building CADETS
Instructions for building CADETS from scratch are [here](https://git.tc.bbn.com/bbn/ta1-integration-cadets/wikis/buildcadets)

# CADETS example trace data 
Available at https://github.com/cadets/trace-data
The trace data is in a CADETS specific JSON format, not TC CDM.

# CDM Translator
This is a python translator program that takes a CADETS trace as input and outputs records in the CDM format.  The translator is a python program that takes a CADETS json trace as input and writes out CDM records in two files, one json format suitable for viewing and the second the Avro binary format.

Run the translator via:

```
$ python cadets_cdm_translator.py --help
usage: cadets_cdm_translator.py [-h] [-psf PSF] [-v] [-tdir TDIR] [-odir ODIR]
                                [-f F] [-lc LC] [-wj] [-wb]

Translate CADETS json to CDM

optional arguments:
  -h, --help  show this help message and exit
  -psf PSF    Set the producer's schema file.
  -v          Turn up verbosity.
  -tdir TDIR  Directory to load CADETS record files from
  -odir ODIR  Directory to write CDM records files to
  -f F        File to translate, default is to translate every file in the
              directory that ends with .json
  -lc LC      Logging configuration file
  -wj         Write JSON output file
  -wb         Write binary output file

```

The default value for tdir (directory that holds the .json CADETS traces) is:
```
TRACE_DIR = "../../trace-data"
```
Change this via the -tdir property (or edit the default in the code)

The default value for the Avro schema is
```
SCHEMA = "../../ta3-serialization-schema/avro/TCCDMDatum.avsc"
```
Change this via the -psf property

The default value for the file to translate is None, which will cause it to trasnlate every .json file in TRACE_DIR.  Use -f to translate a specific file.

# CDM translation
Details of the CADETS-to-CDM translation will be stored [here](https://git.tc.bbn.com/bbn/ta1-integration-cadets/wikis/home)

# Publishing to Kafka
You can use the examples in ta3-api-bindings-python to publish these traces to Kafka
Issue #2 is to more seamlessly integrate those examples.

https://git.tc.bbn.com/bbn/ta3-api-bindings-python/wikis/home

For now, use ta3-api-bindings-python/examples/publish_from_file.py:

For example, this publishes the git_server trace to the CADETS1 topic.  This assumes you're either running inside tc-in-a-box, or running on a host machine communicating with tc-in-a-box via port forwarding. 

```
$ python publish_from_file.py -f ../../trace-data/buildinject/cdm/buildinject.cdm.bin -topic ta1-cadets-cdm13 -delay 0
```

Options:

```
-ks ta3-starc-1a.tc.bbn.com:9092
-v
```



