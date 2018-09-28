#!/usr/bin/env bash

set -x

#sudo rm -i /data/2016*.json

while true; do
	FILE=/data/$(date +%Y%m%d%H%M%S).json
# 	sudo /opt/starc/dtrace-scripts/audit.d -o ${FILE} $(sysctl -n kern.hostuuid)
	sudo /opt/starc/dtrace-scripts/run_auditd.sh > ${FILE}
done
