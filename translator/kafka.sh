#!/usr/bin/env bash

set -e

IP=$(ifconfig vtnet0|grep -E 'inet '|awk '{print $2}')

# RIPE
#if [[ "${IP}" == "10.0.6.1" ]]; then
#       KS="10.0.50.9:9092"
# MARPLE
#elif [[ "${IP}" == "10.0.6.15" ]]; then
#	KS="10.0.50.19:9092"
# ADAPT
#elif [[ "${IP}" == "10.0.6.54" ]]; then
#	KS="10.0.50.24:9092"
#	PUNCTUATE="-punctuate 6"
#else
#	echo "Invalid IP"
#	exit 1
#fi

# For RIPE experiment
KS="10.0.6.24:9092"

echo "************************************************************************************************"
echo "On ${IP}, so using -ks ${KS}"
echo "************************************************************************************************"

cd /opt/starc/ta1-integration-cadets/translator && sudo -u lariat ./cadets_cdm_translator.py -watch -tdir /data -wk -p -ks ${KS} -ktopic ta1-cadets-cdm17 ${PUNCTUATE}
