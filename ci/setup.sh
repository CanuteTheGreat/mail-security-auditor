#!/bin/sh
# Provisions real dependencies the tests exercise (runs inside the CI container).
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq dnsmasq-base >/dev/null
