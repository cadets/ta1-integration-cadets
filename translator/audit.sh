#!/usr/bin/env bash

set -e -x

FILE=/data/$(date +%Y%m%d%H%M%S).json
sudo /opt/starc/dtrace-scripts/audit.d > ${FILE}
