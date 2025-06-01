#!/bin/bash

# --- Configuration ---
CONTAINER_NAME="dpdk-ingress-source-test"
IMAGE_NAME="dpdk-pot-app-source:latest" # Your application image

# Host directory where OVS created the socket (must match OVS setup script)
HOST_OVS_RUN_DIR="/run/openvswitch"
# Mount point for the OVS run directory inside the container
CONTAINER_OVS_RUN_DIR="/var/run/openvswitch"

# Basename of the socket file (must match OVS setup script)
INGRESS_SOCK_BASENAME="vhu_ingress_test_out"
# Full path to the socket *inside the container*
CONTAINER_SOCK_PATH="${CONTAINER_OVS_RUN_DIR}/${INGRESS_SOCK_BASENAME}"

echo "DEBUG: HOST_OVS_RUN_DIR is '${HOST_OVS_RUN_DIR}'"
echo "DEBUG: CONTAINER_OVS_RUN_DIR is '${CONTAINER_OVS_RUN_DIR}'"
echo "DEBUG: INGRESS_SOCK_BASENAME is '${INGRESS_SOCK_BASENAME}'"
echo "DEBUG: CONTAINER_SOCK_PATH is '${CONTAINER_SOCK_PATH}'" # Added for clarity

echo "Container socket path: ${CONTAINER_SOCK_PATH}"
# Check if the socket file exists on the host
if [ -e "${HOST_OVS_RUN_DIR}/${INGRESS_SOCK_BASENAME}" ]; then
    echo "Socket file ${HOST_OVS_RUN_DIR}/${INGRESS_SOCK_BASENAME} exists on the host."
    ls -la "${HOST_OVS_RUN_DIR}/${INGRESS_SOCK_BASENAME}"
else
    echo "ERROR: Socket file ${HOST_OVS_RUN_DIR}/${INGRESS_SOCK_BASENAME} does not exist on the host."
    exit 1
fi

# DPDK EAL Parameters for the Ingress application
INGRESS_CPU_CORE="4"       # Dedicated CPU core for the Ingress app
INGRESS_HUGE_MEM="64"    # Hugepage memory for Ingress
INGRESS_FILE_PREFIX="ingress_test_node" # Unique prefix for hugepage files

# Construct the --vdev argument string
# For client mode, path is mandatory. queues=1 is also common.
# Ensure CONTAINER_SOCK_PATH is correctly expanded here.
INGRESS_EAL_VDEV_ARGS="net_virtio_user0,path=${CONTAINER_SOCK_PATH},server=0,queues=1"
echo "DEBUG: Using --vdev arguments: '${INGRESS_EAL_VDEV_ARGS}'"

# --- Docker Execution ---
echo "Stopping and removing any existing container named '${CONTAINER_NAME}'..."
sudo docker stop ${CONTAINER_NAME} >/dev/null 2>&1 || true
sudo docker rm ${CONTAINER_NAME} >/dev/null 2>&1 || true

echo "--- [DEBUG] Checking socket visibility inside a temporary container ---"
docker run --rm \
    --entrypoint /bin/ls \
    -v ${HOST_OVS_RUN_DIR}:${CONTAINER_OVS_RUN_DIR}:ro \
    ${IMAGE_NAME} \
    -lAR ${CONTAINER_OVS_RUN_DIR}/
echo "--- [DEBUG] End of socket visibility check ---"

echo "--- [DEBUG] Checking libraries and ldconfig inside a temporary container (as root) ---"
sudo docker run --rm -u root --entrypoint /bin/sh ${IMAGE_NAME} -c "\
    echo 'Contents of /usr/local/lib/x86_64-linux-gnu:'; \
    ls -lA /usr/local/lib/x86_64-linux-gnu/; \
    echo '---'; \
    echo 'ldconfig -p output for librte:'; \
    ldconfig -p | grep librte; \
    echo '---'; \
    echo 'Checking for librte_net_virtio specifically:'; \
    ldconfig -p | grep librte_net_virtio; \
    echo '---'; \
    echo 'Checking for librte_bus_vdev specifically:'; \
    ldconfig -p | grep librte_bus_vdev; \
    echo '--- [DEBUG] End of library check ---'
"

echo "Running Ingress container '${CONTAINER_NAME}'..."
sudo docker run -it --rm \
    --name ${CONTAINER_NAME} \
    --privileged \
    -v /dev/hugepages:/dev/hugepages \
    -v ${HOST_OVS_RUN_DIR}:${CONTAINER_OVS_RUN_DIR}:rw \
    ${IMAGE_NAME} \
    -l ${INGRESS_CPU_CORE} \
    --socket-mem ${INGRESS_HUGE_MEM} \
    --single-file-segments \
    --file-prefix ${INGRESS_FILE_PREFIX} \
    --log-level=8 \
    --log-level="lib.eal:debug" \
    --log-level="bus.vdev:debug" \
    --no-pci \
    -d /usr/local/lib/x86_64-linux-gnu/pmds-25.2 \
    --vdev "${INGRESS_EAL_VDEV_ARGS}" \
    -- \
    --role ingress
    # Add any other application-specific arguments for the ingress role after '--role ingress'

echo "Ingress container '${CONTAINER_NAME}' exited."
# echo "Check container logs for DPDK initialization and connection status."