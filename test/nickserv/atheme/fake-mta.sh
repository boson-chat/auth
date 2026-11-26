#!/bin/sh
# Atheme's "MTA": store the message for the tests.
cat > "/mail/$(date +%s%N).eml"
