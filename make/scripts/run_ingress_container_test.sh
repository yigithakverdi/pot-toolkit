#!/bin/bash

# --- Configuration ---
CONTAINER_NAME="dpdk-ingress-test"
IMAGE_NAME="dpdk-pot-app:latest" # Your application image

# Host directory where OVS created the socket (must match OVS setup script)
HOST_OVS_RUN_DIR="/var/run/openvswitch"
# Mount point for the OVS run directory inside the container
CONTAINER_OVS_RUN_DIR="/var/run/openvswitch"

# Basename of the socket file (must match OVS setup script)
INGRESS_SOCK_BASENAME="vhu_ingress_test_out"
# Full path to the socket *inside the container*
CONTAINER_SOCK_PATH="${CONTAINER_OVS_RUN_DIR}/${INGRESS_SOCK_BASENAME}.sock"

# DPDK EAL Parameters for the Ingress application
INGRESS_CPU_CORE="7"       # Dedicated CPU core for the Ingress app (ensure it's isolated)
INGRESS_HUGE_MEM="256M"    # Hugepage memory for Ingress (e.g., 256MB)
INGRESS_FILE_PREFIX="ingress_test_node" # Unique prefix for hugepage files

# --- Docker Execution ---
echo "Stopping and removing any existing container named '${CONTAINER_NAME}'..."
docker stop ${CONTAINER_NAME} >/dev/null 2>&1 || true
docker rm ${CONTAINER_NAME} >/dev/null 2>&1 || true

echo "Running Ingress container '${CONTAINER_NAME}'..."
docker run -it --rm \
    --name ${CONTAINER_NAME} \
    --privileged \
    -v /dev/hugepages:/dev/hugepages \
    -v ${HOST_OVS_RUN_DIR}:${CONTAINER_OVS_RUN_DIR}:rw \
    ${IMAGE_NAME} \
    -l ${INGRESS_CPU_CORE} \
    --socket-mem ${INGRESS_HUGE_MEM} \
    --file-prefix ${INGRESS_FILE_PREFIX} \
    --vdev "virtio_user0,path=${CONTAINER_SOCK_PATH},queues=1" \
    -- \
    --role ingress
    # Add any other application-specific arguments for the ingress role after '--role ingress'
    # For example, if your ingress app needs to know which DPDK port is its output:
    # --output-port 0  (assuming virtio_user0 will be DPDK port 0, to be verified by app logic)

echo "Ingress container '${CONTAINER_NAME}' started."
echo "Check container logs for DPDK initialization and connection status."