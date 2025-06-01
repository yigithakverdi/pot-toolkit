#!/bin/bash

# --- Configuration ---
OVS_BRIDGE="br-dpdkpot-test"
INGRESS_PORT_NAME="vhu_ingress_test_out"
# Socket path may also need to be manually removed if OVS doesn't clean it up on port deletion,
# though usually it does.
# INGRESS_SOCK_PATH="/var/run/openvswitch/${INGRESS_PORT_NAME}.sock"


echo "--- OVS Cleanup ---"
echo "1. Deleting port '${INGRESS_PORT_NAME}' from bridge '${OVS_BRIDGE}'..."
sudo ovs-vsctl --if-exists del-port ${OVS_BRIDGE} ${INGRESS_PORT_NAME}

echo "2. Deleting bridge '${OVS_BRIDGE}'..."
sudo ovs-vsctl --if-exists del-br ${OVS_BRIDGE}

# echo "Optional: Removing socket file if it persists..."
# sudo rm -f ${INGRESS_SOCK_PATH}

echo "OVS test environment cleanup complete."
sudo ovs-vsctl show