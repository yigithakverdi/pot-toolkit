#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
IMAGE_NAME="dpdk-base:ubuntu24.04-24.03.1"  # Your DPDK image
NUM_TRANSIT_NODES=${1:-5}  # Default to 5 transit nodes, take from first argument
NODE_PREFIX="transit-node"  # Prefix for node names
VETH_PREFIX="veth"  # Prefix for veth interfaces
NET_PREFIX="10.10.20"  # Network prefix for IP addresses
IPV6_PREFIX="2001:db8:1::"  # IPv6 prefix for addresses
KEYS_FILE="${2:-$(pwd)/keys.txt}"  # Path to input keys file, if available
GEN_KEYS_FILE="$(pwd)/container_keys.txt"  # Path to generated keys file
SOCKET_MEM="128"  # Socket memory for DPDK
START_LCORE=1  # Starting CPU core number

# Validate input
if [[ ! "$NUM_TRANSIT_NODES" =~ ^[0-9]+$ ]] || [ "$NUM_TRANSIT_NODES" -lt 1 ] || [ "$NUM_TRANSIT_NODES" -gt 100 ]; then
    echo "Error: Number of transit nodes must be a positive integer (1-100)"
    echo "Usage: $0 [number_of_transit_nodes] [optional_keys_file]"
    exit 1
fi

echo "[INFO] Setting up $NUM_TRANSIT_NODES transit nodes in a chain topology"

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
    
    # Stop and remove all containers with our prefix
    local containers=$(sudo docker ps -a --format '{{.Names}}' | grep "^${NODE_PREFIX}")
    if [ -n "$containers" ]; then
        echo "$containers" | xargs -r sudo docker stop >/dev/null 2>&1 || true
        echo "$containers" | xargs -r sudo docker rm >/dev/null 2>&1 || true
        info "Removed all transit node containers"
    fi
    
    # Remove all veth interfaces with our prefix
    local veths=$(ip link show | grep "${VETH_PREFIX}" | awk -F': ' '{print $2}' | cut -d'@' -f1)
    if [ -n "$veths" ]; then
        for veth in $veths; do
            sudo ip link del "$veth" >/dev/null 2>&1 || true
        done
        info "Removed all veth interfaces"
    fi
    
    info "--- Cleanup Complete ---"
}

# --- Key Management Function ---
generate_keys_file() {
    info "Generating keys file at $GEN_KEYS_FILE"
    > "$GEN_KEYS_FILE"  # Clear file
    
    # If we have an input keys file, try to use those keys first
    declare -A key_map
    if [ -f "$KEYS_FILE" ]; then
        info "Reading keys from $KEYS_FILE"
        while read -r line || [ -n "$line" ]; do
            # Skip comments and empty lines
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "$line" ]] && continue
            
            read -r ipv6 key <<< "$line"
            if [ -n "$ipv6" ] && [ -n "$key" ]; then
                key_map["$ipv6"]="$key"
            fi
        done < "$KEYS_FILE"
    fi
    
    # Generate keys for each container
    for i in $(seq 0 $NUM_TRANSIT_NODES); do
        local ipv6="${IPV6_PREFIX}${i}"
        local key
        
        # Check if we already have a key for this IP in our map
        if [ -n "${key_map[$ipv6]}" ]; then
            key="${key_map[$ipv6]}"
        else
            # Generate a new random key
            key="$(openssl rand -hex 16)"
        fi
        
        echo "$ipv6 $key" >> "$GEN_KEYS_FILE"
    done
    
    info "Keys file generated with $((NUM_TRANSIT_NODES + 1)) entries"
}

# --- Launch Container Function ---
# Args: $1=container_name, $2=container_index
launch_container() {
    local name="$1"
    local index="$2"
    local lcore=$((START_LCORE + index % $(nproc)))
    
    info "Launching container: $name (using core $lcore)"
    sudo docker run -d \
        --name="$name" \
        --hostname="$name" \
        --privileged \
        --cpuset-cpus="$lcore" \
        --network=none \
        --entrypoint sleep \
        -v /dev/hugepages:/dev/hugepages \
        -v /dev/vfio:/dev/vfio \
        -v /sys/bus/pci/devices:/sys/bus/pci/devices \
        -v /sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages \
        -v /sys/devices/system/node:/sys/devices/system/node \
        -v "$GEN_KEYS_FILE":/etc/dpdk-pot/keys.txt \
        "$IMAGE_NAME" \
        infinity

    sleep 1
    
    local pid
    pid=$(sudo docker inspect -f '{{.State.Pid}}' "$name")
    if [ -z "$pid" ] || [ "$pid" = "0" ]; then
        error_exit "Failed to get PID for container $name"
    fi
    
    echo "$pid"
}

# --- Create and Assign Veth Function ---
# Args: $1=left_name, $2=right_name, $3=left_container_pid, $4=right_container_pid, $5=left_ip, $6=right_ip, $7=left_idx, $8=right_idx
create_and_assign_veth() {
    local left_veth="$1"
    local right_veth="$2"
    local left_pid="$3"
    local right_pid="$4"
    local left_ip="$5"
    local right_ip="$6"
    local left_idx="$7"
    local right_idx="$8"
    
    info "Creating veth pair: $left_veth <-> $right_veth"
    sudo ip link add "$left_veth" type veth peer name "$right_veth"
    sudo ip link set "$left_veth" up
    sudo ip link set "$right_veth" up
    
    # Move left veth to left container
    info "Moving $left_veth to container PID $left_pid"
    sudo ip link set "$left_veth" netns "$left_pid"
    sudo nsenter -t "$left_pid" -n ip link set "$left_veth" name "eth0"
    sudo nsenter -t "$left_pid" -n ip link set "eth0" up
    if [ -n "$left_ip" ]; then
        sudo nsenter -t "$left_pid" -n ip addr add "$left_ip" dev "eth0"
    fi
    
    # Add IPv6 address to left container
    left_ipv6="${IPV6_PREFIX}${left_idx}/64"
    info "Adding IPv6 address $left_ipv6 to ${NODE_PREFIX}-${left_idx}"
    sudo nsenter -t "$left_pid" -n sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
    sudo nsenter -t "$left_pid" -n sysctl -w net.ipv6.conf.eth0.disable_ipv6=0 >/dev/null 2>&1 || true
    sudo nsenter -t "$left_pid" -n ip -6 addr add "$left_ipv6" dev "eth0"
    
    # Move right veth to right container
    info "Moving $right_veth to container PID $right_pid"
    sudo ip link set "$right_veth" netns "$right_pid"
    sudo nsenter -t "$right_pid" -n ip link set "$right_veth" name "eth0"
    sudo nsenter -t "$right_pid" -n ip link set "eth0" up
    if [ -n "$right_ip" ]; then
        sudo nsenter -t "$right_pid" -n ip addr add "$right_ip" dev "eth0"
    fi
    
    # Add IPv6 address to right container
    right_ipv6="${IPV6_PREFIX}${right_idx}/64"
    info "Adding IPv6 address $right_ipv6 to ${NODE_PREFIX}-${right_idx}"
    sudo nsenter -t "$right_pid" -n sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
    sudo nsenter -t "$right_pid" -n sysctl -w net.ipv6.conf.eth0.disable_ipv6=0 >/dev/null 2>&1 || true
    sudo nsenter -t "$right_pid" -n ip -6 addr add "$right_ipv6" dev "eth0"
}

# --- Main Execution ---
cleanup

# Generate keys file first
generate_keys_file

info "--- Creating Transit Node Chain with $NUM_TRANSIT_NODES Nodes ---"

# Launch all containers first
declare -a container_pids
declare -a container_names

for i in $(seq 0 $NUM_TRANSIT_NODES); do
    name="${NODE_PREFIX}-${i}"
    container_names+=("$name")
    pid=$(launch_container "$name" "$i")
    container_pids+=("$pid")
    info "Launched container $name with PID $pid"
done

# Now create veth pairs between containers
for i in $(seq 0 $((NUM_TRANSIT_NODES - 1))); do
    left_idx=$i
    right_idx=$((i + 1))
    
    left_name="${container_names[$left_idx]}"
    right_name="${container_names[$right_idx]}"
    left_pid="${container_pids[$left_idx]}"
    right_pid="${container_pids[$right_idx]}"
    
    left_veth="${VETH_PREFIX}_${left_idx}_${right_idx}_l"
    right_veth="${VETH_PREFIX}_${left_idx}_${right_idx}_r"
    
    left_ip="${NET_PREFIX}.${left_idx}/24"
    right_ip="${NET_PREFIX}.${right_idx}/24"
    
    create_and_assign_veth "$left_veth" "$right_veth" "$left_pid" "$right_pid" "$left_ip" "$right_ip" "$left_idx" "$right_idx"
done

info "--- Setup Complete! ---"
echo
info "Transit chain created with $NUM_TRANSIT_NODES nodes"
info "Container keys file generated at $GEN_KEYS_FILE"
echo

# Print instructions for accessing the containers
info "To access a specific transit node (example for node 0):"
echo "  sudo docker exec -it --user root ${NODE_PREFIX}-0 bash"
echo
info "To run DPDK testpmd in a container (replace NODE_IDX with the node number):"
echo "  NODE_IDX=0"
echo "  sudo docker exec -it --user root ${NODE_PREFIX}-\${NODE_IDX} bash"
echo "  # Inside container:"
echo "  PMDS_DIR=\$(ls -d /usr/local/lib/x86_64-linux-gnu/dpdk/pmds-*/ | head -n 1) && \\"
echo "  dpdk-testpmd \\"
echo "    -l \$((1 + \$NODE_IDX % \$(nproc))) \\"
echo "    --iova-mode=va \\"
echo "    --socket-mem ${SOCKET_MEM} \\"
echo "    --file-prefix \"node_\${NODE_IDX}\" \\"
echo "    --single-file-segments \\"
echo "    --no-pci \\"
echo "    --vdev=\"net_af_packet0,iface=eth0\" \\"
echo "    -d \"\${PMDS_DIR%/}\" \\"
echo "    -- \\"
echo "    --interactive --portmask=0x1"
echo
info "To run your DPDK POT application in a container:"
echo "  sudo docker exec -it --user root ${NODE_PREFIX}-\${NODE_IDX} bash"
echo "  # Inside container:"
echo "  # Keys file is already mounted at /etc/dpdk-pot/keys.txt"
echo "  dpdk-pot --role transit --node-id \${NODE_IDX} --keys-file /etc/dpdk-pot/keys.txt"
echo
info "To clean up all containers and interfaces:"
echo "  $0 0  # (passing 0 will just clean up)"
echo
info "IPv6 Addressing information:"
info "Each container has been assigned an IPv6 address in the format:"
info "  ${IPV6_PREFIX}[node_index]  (e.g. ${IPV6_PREFIX}0, ${IPV6_PREFIX}1, etc.)"
info "These addresses match the keys in the generated $GEN_KEYS_FILE file"
echo

