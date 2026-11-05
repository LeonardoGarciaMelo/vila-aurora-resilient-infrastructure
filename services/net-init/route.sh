#!/bin/sh
# Runs inside a cloud service's network namespace to add return routes through the hub.
ip route replace 10.50.0.0/24 via 10.60.0.1
ip route replace 10.70.0.0/24 via 10.60.0.1
echo "routes installed"
