#!/usr/bin/env bash

set -e

IP=$(ifconfig vtnet0|grep -E 'inet '|awk '{print $2}')

if [[ "${IP}" == "10.0.6.20" ]]; then
	KS="10.0.6.9:9092"
elif [[ "${IP}" == "10.0.6.2" ]]; then
	KS="128.55.12.74:9092"
else
	echo "Invalid IP"
	exit 1
fi

echo "************************************************************************************************"
echo "On ${IP}, so using -ks ${KS}"
echo "************************************************************************************************"

cd /opt/starc/ta1-integration-cadets/translator && ./cadets_cdm_translator.py -watch -tdir /data -wk -p -ks ${KS} -ktopic ta1-cadets-cdm13
