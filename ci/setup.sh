#!/bin/sh
# Provisions real dependencies the tests exercise (runs inside the CI container).
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq dnsmasq-base >/dev/null
# reference implementations for tests/test_accuracy.py (pyspf = the RFC 7208 SPF library policyd-spf uses)
pip install -q --disable-pip-version-check --root-user-action=ignore pyspf dnspython 2>/dev/null || pip install -q --disable-pip-version-check pyspf dnspython
