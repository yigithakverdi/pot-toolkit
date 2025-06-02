#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
IMAGE_NAME="dpdk-pot-app-source:latest" # Your DPDK application image

C1_NAME="c1-dpdk-veth"
C1_VETH_HOST_END="veth_h_c1" # Host side name for veth end going to C1
C1_IFACE_IN_CONTAINER="eth0" # Interface name inside C1
C1_IP_ADDR="10.10.20.1/24"   # Optional IP for C1 for kernel-level tests

C2_NAME="c2-dpdk-veth"
C2_VETH_HOST_END="veth_h_c2" # Host side name for veth end going to C2
C2_IFACE_IN_CONTAINER="eth0" # Interface name inside C2
C2_IP_ADDR="10.10.20.2/24"   # Optional IP for C2 for kernel-level tests

# Suggested testpmd EAL configurations
# Ensure these cores are not heavily used by the host or each other.
TESTPMD_C1_LCORE="1" # Core for testpmd in C1 (e.g., CPU core 1)
TESTPMD_C1_FILE_PREFIX="c1_veth_test"
TESTPMD_C2_LCORE="2" # Core for testpmd in C2 (e.g., CPU core 2)
TESTPMD_C2_FILE_PREFIX="c2_veth_test"
TESTPMD_SOCKET_MEM="128" # Socket memory for testpmd instances

# --- Helper Functions ---
info() {
    echo "[INFO] $1"
}

error_exit() {
    echo "[ERROR] $1" >&2
    exit 1
}

# --- Cleanup Function ---
cleanup() {
    info "--- Starting Cleanup ---"
    for container_name in "$C1_NAME" "$C2_NAME"; do
        if sudo docker ps -a --format '{{.Names}}' | grep -q "^${container_name}$"; then
            info "Stopping and removing container: $container_name"
            sudo docker stop "$container_name" >/dev/null 2>&1 || true
            sudo docker rm "$container_name" >/dev/null 2>&1 || true
        else
            info "Container $container_name not found or already removed."
        fi
    done

    # Deleting one end of veth pair deletes the peer automatically
    if ip link show "$C1_VETH_HOST_END" >/dev/null 2>&1; then
        info "Deleting veth interface: $C1_VETH_HOST_END (and its peer $C2_VETH_HOST_END)"
        sudo ip link del "$C1_VETH_HOST_END" >/dev/null 2>&1 || true
    else
        info "veth interface $C1_VETH_HOST_END not found or already removed."
    fi
    info "--- Cleanup Complete ---"
    echo
}

# --- Function to Launch Container and Get PID ---
# Args: $1=container_name, $2=image_name, $3=variable_name_to_store_PID
launch_container_and_get_pid() {
    local container_name="$1"
    local image_name="$2"
    local pid_var_name="$3"

    info "Launching container: $container_name from image $image_name"
    sudo docker run -d \
        --name="$container_name" \
        --hostname="$container_name" \
        --privileged \
        --network=none \
        --entrypoint sleep \
        -v /dev/hugepages:/dev/hugepages \
        -v /sys/bus/pci/devices:/sys/bus/pci/devices \
        -v /sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages \
        -v /sys/devices/system/node:/sys/devices/system/node \
        "$image_name" \
        infinity

    # Give Docker a moment to update its state
    sleep 2 

    if ! sudo docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
        error_exit "Container $container_name failed to start or exited prematurely. Check 'sudo docker logs $container_name'."
    fi

    local pid_val
    pid_val=$(sudo docker inspect -f '{{.State.Pid}}' "$container_name")
    if [ -z "$pid_val" ] || [ "$pid_val" = "0" ]; then # PID 0 is invalid # <--- CORRECTED LINE (single =)
        error_exit "Failed to get a valid PID for container $container_name."
    fi

    # Set the PID in the calling scope
    eval "$pid_var_name=\"$pid_val\""
    info "Container $container_name launched. PID: $pid_val"
}

# --- Function to Setup Veth in Container ---
# Args: $1=container_pid, $2=veth_host_end, $3=iface_name_in_container, $4=ip_addr (optional)
setup_veth_in_container() {
    local container_pid="$1"
    local veth_host_end="$2"
    local iface_in_container="$3"
    local ip_addr="$4"

    info "Moving veth end '$veth_host_end' to container PID $container_pid and naming it '$iface_in_container'"
    sudo ip link set "$veth_host_end" netns "$container_pid"
    sudo nsenter -t "$container_pid" -n ip link set "$veth_host_end" name "$iface_in_container"
    sudo nsenter -t "$container_pid" -n ip link set "$iface_in_container" up

    if [ -n "$ip_addr" ]; then
        info "Assigning IP $ip_addr to $iface_in_container in container PID $container_pid"
        sudo nsenter -t "$container_pid" -n ip addr add "$ip_addr" dev "$iface_in_container"
    fi
    info "Interface $iface_in_container configured and UP in container PID $container_pid."
}

# --- Main Execution ---
cleanup

info "--- Starting veth Pair and Container Setup ---"

# 1. Create veth pair on host
info "Creating veth pair: $C1_VETH_HOST_END (peer $C2_VETH_HOST_END)"
sudo ip link add "$C1_VETH_HOST_END" type veth peer name "$C2_VETH_HOST_END"
sudo ip link set "$C1_VETH_HOST_END" up # Bring host ends up before moving
sudo ip link set "$C2_VETH_HOST_END" up
info "veth pair created and up on host."

# 2. Setup Container 1
C1_ACTUAL_PID="" # Ensure variable is clear before assignment
launch_container_and_get_pid "$C1_NAME" "$IMAGE_NAME" "C1_ACTUAL_PID"
setup_veth_in_container "$C1_ACTUAL_PID" "$C1_VETH_HOST_END" "$C1_IFACE_IN_CONTAINER" "$C1_IP_ADDR"

# 3. Setup Container 2
C2_ACTUAL_PID="" # Ensure variable is clear
launch_container_and_get_pid "$C2_NAME" "$IMAGE_NAME" "C2_ACTUAL_PID"
setup_veth_in_container "$C2_ACTUAL_PID" "$C2_VETH_HOST_END" "$C2_IFACE_IN_CONTAINER" "$C2_IP_ADDR"

info "--- Setup Complete! ---"
echo
info "You can now access the containers to run testpmd."
echo
info "To access Container 1 ($C1_NAME):"
echo "  sudo docker exec -it --user root $C1_NAME bash"
echo
info "Suggested testpmd command for Container 1 (using core $TESTPMD_C1_LCORE, interface $C1_IFACE_IN_CONTAINER):"
echo "  # Ensure you are root inside the container"
echo "  # Dynamically find PMD directory (or replace with hardcoded path like /usr/local/lib/x86_64-linux-gnu/pmds-25.2/)"
echo "  PMDS_DIR=\$(ls -d /usr/local/lib/x86_64-linux-gnu/pmds-*/ | head -n 1) && \\"
echo "  dpdk-testpmd \\"
echo "    -l $TESTPMD_C1_LCORE \\"
echo "    --iova-mode=va \\"
echo "    --socket-mem $TESTPMD_SOCKET_MEM \\"
echo "    --file-prefix $TESTPMD_C1_FILE_PREFIX \\"
echo "    --single-file-segments \\"
echo "    --no-pci \\"
echo "    --log-level=8 \\"
echo "    --vdev=\"net_af_packet0,iface=$C1_IFACE_IN_CONTAINER\" \\"
echo "    -d \"\${PMDS_DIR%/}\" \\" # Removes trailing slash if any, though often not an issue
echo "    -- \\"
echo "    --interactive --portmask=0x1"
echo
info "To access Container 2 ($C2_NAME):"
echo "  sudo docker exec -it --user root $C2_NAME bash"
echo
info "Suggested testpmd command for Container 2 (using core $TESTPMD_C2_LCORE, interface $C2_IFACE_IN_CONTAINER):"
echo "  # Ensure you are root inside the container"
echo "  # Dynamically find PMD directory (or replace with hardcoded path like /usr/local/lib/x86_64-linux-gnu/pmds-25.2/)"
echo "  PMDS_DIR=\$(ls -d /usr/local/lib/x86_64-linux-gnu/pmds-*/ | head -n 1) && \\"
echo "  dpdk-testpmd \\"
echo "    -l $TESTPMD_C2_LCORE \\"
echo "    --iova-mode=va \\"
echo "    --socket-mem $TESTPMD_SOCKET_MEM \\"
echo "    --file-prefix $TESTPMD_C2_FILE_PREFIX \\"
echo "    --single-file-segments \\"
echo "    --no-pci \\"
echo "    --log-level=8 \\"
echo "    --vdev=\"net_af_packet0,iface=$C2_IFACE_IN_CONTAINER\" \\"
echo "    -d \"\${PMDS_DIR%/}\" \\" # Removes trailing slash if any
echo "    -- \\"
echo "    --interactive --portmask=0x1"
echo
info ">>> IMPORTANT NOTE ON POTENTIAL EAL ERRORS (mlx5, mempool ops): <<<"
info "If testpmd fails with 'mlx5 trace' or 'mempool ops exceeded' errors inside the containers,"
info "you may need to manually and temporarily disable/rename the 'librte_net_mlx5.so' (and potentially"
info "other 'librte_*mlx5.so*' files) from the main DPDK library directory"
info "('/usr/local/lib/x86_64-linux-gnu/') INSIDE THE CONTAINER before running testpmd."
info "This is because the EAL might still load them from default paths even if not using the mlx5 PMD."
info "Remember to run 'ldconfig' inside the container after renaming/restoring such libraries."

