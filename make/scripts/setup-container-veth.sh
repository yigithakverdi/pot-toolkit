#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
IMAGE_NAME="yigithak/dpdk-pot:latest"
NUM_TRANSIT_NODES=${1:-3}  # Default to 3 transit nodes
NODE_PREFIX="pot-node"
INGRESS_NODE="${NODE_PREFIX}-ingress"
EGRESS_NODE="${NODE_PREFIX}-egress"
TRANSIT_NODE_PREFIX="${NODE_PREFIX}-transit"
VETH_PREFIX="veth"
IPV6_PREFIX="2001:db8:1::"
GEN_KEYS_FILE="/etc/secret/pot_keys.txt"
SEGMENT_LIST_FILE="/etc/segment/segment_list.txt"
SOCKET_MEM="128"
START_LCORE=1

# --- Helper Functions ---
info() { echo "[INFO] $1" >&2; }
error_exit() { echo "[ERROR] $1" >&2; exit 1; }

# --- Cleanup Function ---
cleanup() {
    info "--- Starting Cleanup ---"
    local containers=$(sudo docker ps -a --format '{{.Names}}' | grep "^${NODE_PREFIX}")
    if [ -n "$containers" ]; then
        echo "$containers" | xargs -r sudo docker stop >/dev/null 2>&1 || true
        echo "$containers" | xargs -r sudo docker rm >/dev/null 2>&1 || true
        info "Removed all POT node containers"
    fi
    local veths=$(ip link show | grep -oP "${VETH_PREFIX}[^@]+")
    if [ -n "$veths" ]; then
        for veth in $veths; do sudo ip link del "$veth" >/dev/null 2>&1 || true; done
        info "Removed all veth interfaces"
    fi
    info "--- Cleanup Complete ---"
}

# --- Key and Segment List Generation ---
generate_keys_file() {
    info "Generating keys file: $GEN_KEYS_FILE"
    > "$GEN_KEYS_FILE"
    # Egress key + one key per transit node
    for i in $(seq 0 $NUM_TRANSIT_NODES); do
        echo "$(openssl rand -hex 32)" >> "$GEN_KEYS_FILE"
    done
}

generate_segment_list() {
    info "Generating segment list: $SEGMENT_LIST_FILE"
    > "$SEGMENT_LIST_FILE"
    # Path is: ingress -> transit-1 -> ... -> transit-N -> egress
    for i in $(seq 1 $NUM_TRANSIT_NODES); do
        echo "${IPV6_PREFIX}${i}" >> "$SEGMENT_LIST_FILE"
    done
    echo "${IPV6_PREFIX}$((NUM_TRANSIT_NODES + 1))" >> "$SEGMENT_LIST_FILE"
}

# --- Connection Verification Function ---
# --- NEW: Connection Verification Function (Corrected) ---
verify_connections() {
    info "--- Verifying Network Connections ---"
    local -a names=($1)
    local total_nodes=${#names[@]}

    for i in $(seq 0 $((total_nodes - 2))); do
        local source_node="${names[$i]}"
        local target_node="${names[$i+1]}"
        local target_ip="${IPV6_PREFIX}$((i + 1))"

        # Determine the correct outgoing interface for the ping.
        # The first node (ingress) uses eth0.
        # Transit nodes use eth1 to connect to the *next* node in the chain.
        local source_interface="eth0"
        if [ "$i" -gt 0 ]; then
            source_interface="eth1"
        fi

        info "Pinging from $source_node ($source_interface) to $target_node ($target_ip)..."
        
        # Use ping's -I flag to specify the outgoing interface, removing routing ambiguity.
        if sudo docker exec "$source_node" ping -6 -c 3 -I "$source_interface" "$target_ip" >/dev/null 2>&1; then
            info "✅ Success: $source_node can reach $target_node"
        else
            error_exit "❌ Failure: $source_node cannot reach $target_node. Aborting."
        fi
    done
    info "--- All direct connections verified successfully ---"
}

# --- Container and Network Setup ---
launch_container() {
    local name="$1"
    info "Launching container: $name"
    sudo docker run -d --name="$name" --hostname="$name" --privileged --network=none \
        --entrypoint sleep -v /dev/hugepages:/dev/hugepages \
        -v "$GEN_KEYS_FILE":/etc/secret/pot_keys.txt \
        -v "$SEGMENT_LIST_FILE":/etc/segment/segment_list.txt \
        -v "$(pwd)/build/dpdk-pot":/usr/local/bin/dpdk-pot \
        "$IMAGE_NAME" infinity >/dev/null
    sleep 1
    sudo docker inspect -f '{{.State.Pid}}' "$name"
}

create_and_assign_veth() {
    local left_veth="$1" right_veth="$2" left_pid="$3" right_pid="$4" left_idx="$5" right_idx="$6"
    info "Creating veth pair: $left_veth <-> $right_veth"
    sudo ip link add "$left_veth" type veth peer name "$right_veth"
    
    # Correct interface naming:
    # Ingress (idx 0) uses eth0.
    # Transit (idx > 0) uses eth1 to connect to the "right".
    local left_if_name="eth0"
    if [ "$left_idx" -gt 0 ]; then
        left_if_name="eth1"
    fi
    # The node on the right of the pair always gets connected on its "left" interface, which is eth0.
    local right_if_name="eth0"

    sudo ip link set "$left_veth" netns "$left_pid"
    sudo nsenter -t "$left_pid" -n ip link set "$left_veth" name "$left_if_name"
    sudo nsenter -t "$left_pid" -n ip addr add "${IPV6_PREFIX}${left_idx}/64" dev "$left_if_name"
    sudo nsenter -t "$left_pid" -n ip link set "$left_if_name" up

    sudo ip link set "$right_veth" netns "$right_pid"
    sudo nsenter -t "$right_pid" -n ip link set "$right_veth" name "$right_if_name"
    sudo nsenter -t "$right_pid" -n ip addr add "${IPV6_PREFIX}${right_idx}/64" dev "$right_if_name"
    sudo nsenter -t "$right_pid" -n ip link set "$right_if_name" up
}

# --- NEW: Automated DPDK App Launcher ---
launch_dpdk_app() {
    local name="$1"
    local role="$2"
    local node_index="$3"
    local num_transit="$4"
    local lcore=$((START_LCORE + node_index % $(nproc)))

    info "Starting DPDK app in $name (role: $role, index: $node_index, lcore: $lcore)"
    
    local vdevs=""
    if [ "$role" == "transit" ]; then
        # Transit nodes have two interfaces
        vdevs="--vdev=net_af_packet0,iface=eth0 --vdev=net_af_packet1,iface=eth1"
    else
        # Ingress and Egress have one
        vdevs="--vdev=net_af_packet0,iface=eth0"
    fi
    
    # Construct the full command to be executed inside the container
    local cmd="dpdk-pot -l $lcore -n 4 --no-pci --iova-mode=va --socket-mem $SOCKET_MEM $vdevs -- \
        --type $role \
        --node-index $node_index \
        --num-transit $num_transit \
        --log-level debug"
        
    # Execute the command in the background inside the container
    sudo docker exec -d --user root "$name" bash -c "$cmd"
}


# --- Main Execution ---
cleanup
generate_keys_file
generate_segment_list

info "--- Creating POT Network with Ingress, $NUM_TRANSIT_NODES Transit Nodes, and Egress ---"

declare -a container_pids
declare -a container_names

# 1. Launch Ingress
pid=$(launch_container "$INGRESS_NODE")
container_pids+=( "$pid" ); container_names+=( "$INGRESS_NODE" )

# 2. Launch Transit Nodes
for i in $(seq 1 $NUM_TRANSIT_NODES); do
    name="${TRANSIT_NODE_PREFIX}-${i}"
    pid=$(launch_container "$name")
    container_pids+=( "$pid" ); container_names+=( "$name" )
done

# 3. Launch Egress
pid=$(launch_container "$EGRESS_NODE")
container_pids+=( "$pid" ); container_names+=( "$EGRESS_NODE" )

# 4. Connect nodes with veth pairs
total_nodes=${#container_names[@]}
for i in $(seq 0 $((total_nodes - 2))); do
    left_idx=$i; right_idx=$((i + 1))
    left_pid="${container_pids[$left_idx]}"; right_pid="${container_pids[$right_idx]}"
    left_veth="${VETH_PREFIX}_${left_idx}l"; right_veth="${VETH_PREFIX}_${left_idx}r"
    create_and_assign_veth "$left_veth" "$right_veth" "$left_pid" "$right_pid" "$left_idx" "$right_idx"
done

# 5. VERIFY THE CONNECTIONS
# Pass the container_names array as a single, quoted string
verify_connections "${container_names[*]}"

info "--- Network Setup Complete. Starting DPDK Applications... ---"

# 5. NEW: Automatically start the DPDK app in each container
# Ingress
launch_dpdk_app "${container_names[0]}" "ingress" 0 "$NUM_TRANSIT_NODES"
# Transit
for i in $(seq 1 $NUM_TRANSIT_NODES); do
    launch_dpdk_app "${container_names[$i]}" "transit" "$i" "$NUM_TRANSIT_NODES"
done
# Egress
launch_dpdk_app "${container_names[-1]}" "egress" $((NUM_TRANSIT_NODES + 1)) "$NUM_TRANSIT_NODES"

info "--- All applications started. Network is live. ---"
echo "To view logs for a node, run: sudo docker logs -f ${NODE_PREFIX}-<type>-<number>"
echo "To clean up all resources, run: $0"