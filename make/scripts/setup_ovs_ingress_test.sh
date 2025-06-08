#!/bin/bash

# --- Configuration ---
OVS_BRIDGE="br-dpdkpot-test"
INGRESS_PORT_NAME="vhu_ingress_test_out"
# OVS typically creates sockets in /var/run/openvswitch or a configured ovs-run directory
# Ensure this path is accessible for mounting into the Docker container.
HOST_OVS_RUN_DIR="/var/run/openvswitch" # Common default
INGRESS_SOCK_PATH="${HOST_OVS_RUN_DIR}/${INGRESS_PORT_NAME}"

echo "Host OVS Run Directory: ${HOST_OVS_RUN_DIR}"
echo "Ingress Socket Path on Host: ${INGRESS_SOCK_PATH}"

# --- OVS Setup ---
echo "Cleaning up existing test bridge '${OVS_BRIDGE}' if any..."
sudo ovs-vsctl --if-exists del-br ${OVS_BRIDGE}

echo "1. Creating OVS bridge '${OVS_BRIDGE}' with datapath_type=netdev..."
sudo ovs-vsctl add-br ${OVS_BRIDGE} -- set bridge ${OVS_BRIDGE} datapath_type=netdev

echo "2. Adding dpdkvhostuser port '${INGRESS_PORT_NAME}' to bridge '${OVS_BRIDGE}'..."
# OVS will create and listen on the socket specified by options:vhost-server-path
# The DPDK application in the container will connect to this socket.
sudo ovs-vsctl add-port ${OVS_BRIDGE} ${INGRESS_PORT_NAME} -- \
    set Interface ${INGRESS_PORT_NAME} type=dpdkvhostuser \
    options:vhost-server-path=${INGRESS_SOCK_PATH}

echo "OVS setup for Ingress test complete."

# --- Verification (Optional) ---
echo "Verifying OVS setup:"
sudo ovs-vsctl show
echo "Checking for socket file at ${INGRESS_SOCK_PATH}:"
ls -l ${INGRESS_SOCK_PATH}

echo "Setting permissions for the socket ${INGRESS_SOCK_PATH}..."
sudo chmod 777 ${INGRESS_SOCK_PATH}
# Alternatively, sudo chmod 777 ${INGRESS_SOCK_PATH} for testing if 666 isn't enough
echo "Permissions set."

echo "You might need to ensure permissions on ${HOST_OVS_RUN_DIR} or specifically ${INGRESS_SOCK_PATH}"
echo "allow the user inside the Docker container to access the socket."
echo "If the container runs as non-root, 'sudo chmod 777 ${INGRESS_SOCK_PATH}' might be needed after it's created by OVS,"
echo "or ensure the 'dpdk' user has group access if OVS creates sockets with a specific group."