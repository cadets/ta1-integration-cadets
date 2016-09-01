#!/usr/bin/env bash

set -x

#sudo rm -i /data/2016*.json

while true; do
	FILE=/data/$(date +%Y%m%d%H%M%S).json
	sudo /opt/starc/dtrace-scripts/audit.d > ${FILE}
done
