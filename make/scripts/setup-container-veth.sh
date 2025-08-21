#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
<<<<<<< HEAD
IMAGE_NAME="yigithak/dpdk-pot:latest"  # Your DPDK image
NUM_TRANSIT_NODES=${1:-5}  # Default to 5 transit nodes, take from first argument
NODE_PREFIX="pot-node"     # Common prefix for all nodes
INGRESS_NODE="${NODE_PREFIX}-ingress"  # Ingress node name
EGRESS_NODE="${NODE_PREFIX}-egress"    # Egress node name
TRANSIT_NODE_PREFIX="${NODE_PREFIX}-transit"  # Prefix for transit nodes
VETH_PREFIX="veth"  # Prefix for veth interfaces
NET_PREFIX="10.10.20"  # Network prefix for IP addresses
IPV6_PREFIX="2001:db8:1::"  # IPv6 prefix for addresses
KEYS_FILE="${2:-$(pwd)/keys.txt}"  # Path to input keys file, if available
GEN_KEYS_FILE="$(pwd)/container_keys.txt"  # Path to generated keys file
SEGMENT_LIST_FILE="$(pwd)/segment_list.txt"  # Path to generated segment list file
SOCKET_MEM="128"  # Socket memory for DPDK
START_LCORE=1  # Starting CPU core number
# Common DPDK args - we use ethX where X is the node index
DPDK_BASE_ARGS="-n 4 --no-pci --iova-mode=va --socket-mem ${SOCKET_MEM}"
=======
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
>>>>>>> origin/refactor/major

IPERF_CLIENT_NODE="pot-iperf-client"
IPERF_SERVER_NODE="pot-iperf-server"
IPERF_CLIENT_IPV6="2001:db8:1::c1"
IPERF_SERVER_IPV6="2001:db8:1::d1"
IPERF_IMAGE_NAME="yigithak/ubuntu-iperf:latest"


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

# generate_segment_list() {
#     info "Generating segment list: $SEGMENT_LIST_FILE"
#     > "$SEGMENT_LIST_FILE"
#     # Path is: ingress -> transit-1 -> ... -> transit-N -> egress
#     for i in $(seq 1 $NUM_TRANSIT_NODES); do
#         echo "${IPV6_PREFIX}${i}" >> "$SEGMENT_LIST_FILE"
#     done
#     echo "${IPV6_PREFIX}$((NUM_TRANSIT_NODES + 1))" >> "$SEGMENT_LIST_FILE"
# }

generate_segment_list() {
    info "Generating segment list: $SEGMENT_LIST_FILE"
    > "$SEGMENT_LIST_FILE"
    
    # --- FIX ---
    # The segment list must contain the IP addresses of the *receiving* interfaces
    # of the transit and egress nodes. These are the 'right' side IPs from our loop.
    # For a path ingress -> transit-1 -> egress:
    # - transit-1's receiving IP is ::2
    # - egress's receiving IP is ::4
    
    # Path is: ingress -> transit-1 -> ... -> transit-N -> egress
    for i in $(seq 0 $((NUM_TRANSIT_NODES))); do
        # The receiving IP for the node at link 'i' is (i * 2 + 2)
        local segment_ip_suffix=$((i * 2 + 2))
        echo "${IPV6_PREFIX}${segment_ip_suffix}" >> "$SEGMENT_LIST_FILE"
    done
}

<<<<<<< HEAD
# --- Launch Container Function ---
# Args: $1=container_name, $2=container_index
launch_container() {
    local name="$1"
    local index="$2"
    local lcore=$((START_LCORE + index % $(nproc)))
    
    info "Launching container: $name (using core $lcore)" >&2
        sudo docker run -d \
            --name="$name" \
            --hostname="$name" \
            --privileged \
            --network=none \
            --cap-add=NET_ADMIN \
            --cap-add=SYS_ADMIN \
            --entrypoint sleep \
            -v /dev/hugepages:/dev/hugepages \
            -v /dev/vfio:/dev/vfio \
            -v /sys/bus/pci/devices:/sys/bus/pci/devices \
            -v /sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages \
            -v /sys/devices/system/node:/sys/devices/system/node \
            -v /lib/modules:/lib/modules \
            -v "$GEN_KEYS_FILE":/etc/dpdk-pot/keys.txt \
            -v "$SEGMENT_LIST_FILE":/etc/dpdk-pot/segment_list.txt \
            "$IMAGE_NAME" \
            infinity >/dev/null

    sleep 1
    
    local pid
    pid=$(sudo docker inspect -f '{{.State.Pid}}' "$name")
    if [ -z "$pid" ] || [ "$pid" = "0" ]; then
        error_exit "Failed to get PID for container $name"
    fi
    
    echo "$pid"
}

# --- Verification Function ---
=======
# --- Connection Verification Function ---
>>>>>>> origin/refactor/major
verify_connections() {
    info "--- Verifying Network Connections ---"
    local -a names=($1)
    local total_nodes=${#names[@]}

    for i in $(seq 0 $((total_nodes - 2))); do
        local source_node="${names[$i]}"
        local target_node="${names[$i+1]}"
        
        # --- FIX ---
        # The target IP must match the logic from the main loop.
        # It's the 'right' side of the veth pair for link 'i'.
        local target_ip_suffix=$((i * 2 + 2))
        local target_ip="${IPV6_PREFIX}${target_ip_suffix}"

        # The outgoing interface is always eth1 for nodes in the DPDK chain.
        local source_interface="eth1"

        info "Pinging from $source_node ($source_interface) to $target_node ($target_ip)..."
        
        if sudo docker exec "$source_node" ping -6 -c 3 -I "$source_interface" "$target_ip"; then
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
    local image_to_use="${2:-$IMAGE_NAME}" # Use 2nd arg, or default to IMAGE_NAME

    info "Launching container: $name (using image $image_to_use)"
    sudo docker run -d --name="$name" --hostname="$name" --privileged --network=none \
        --entrypoint sleep -v /dev/hugepages:/dev/hugepages \
        -v "$GEN_KEYS_FILE":/etc/secret/pot_keys.txt \
        -v "$SEGMENT_LIST_FILE":/etc/segment/segment_list.txt \
        -v /var/log/dpdk-pot:/var/log/dpdk-pot \
        -v /home/ubuntu/dpdk-pot/results/latency:/tmp \
        -v "$(pwd)/build/dpdk-pot":/usr/local/bin/dpdk-pot \
        "$image_to_use" infinity >/dev/null
    sleep 1
    sudo docker inspect -f '{{.State.Pid}}' "$name"
}

# create_and_assign_veth() {
#     local left_veth=$1 right_veth=$2 left_pid=$3 right_pid=$4
#     local left_ip=$5 right_ip=$6 left_iface=$7 right_iface=$8

#     info "Creating veth pair: $1 ($left_ip on $left_iface) <-> $2 ($right_ip on $right_iface)"
#     sudo ip link add "$left_veth" type veth peer name "$right_veth"

#     # Deterministic MAC generation for all veths except veth_srvb
#     if [[ "$right_veth" == "veth_srvb" ]]; then
#         sudo ip link set "$right_veth" address 02:cc:ef:38:4b:25
#         # 02:bc:84:2b:49:7c
#         # Hardcoded MAC address --> 02:cc:ef:38:4b:25
#     else
#         # Deterministic MAC generation based on veth name (hash)
#         mac_from_name() {
#             local name="$1"
#             # Use md5sum to hash the name, take first 5 bytes for uniqueness
#             local hash=$(echo -n "$name" | md5sum | awk '{print $1}')
#             # Always use 02 as the first byte (locally administered, unicast)
#             printf '02:%s:%s:%s:%s:%s' \
#                 "${hash:0:2}" "${hash:2:2}" "${hash:4:2}" "${hash:6:2}" "${hash:8:2}"
#         }
#         left_mac=$(mac_from_name "$left_veth")
#         right_mac=$(mac_from_name "$right_veth")
#         sudo ip link set "$left_veth" address "$left_mac"
#         sudo ip link set "$right_veth" address "$right_mac"
#     fi

#     sudo ip link set "$left_veth" netns "$left_pid"
#     sudo nsenter -t "$left_pid" -n ip link set "$left_veth" name "$left_iface"
    
#     # Set MAC inside the namespace after renaming
#     sudo nsenter -t "$left_pid" -n ip link set "$left_iface" address "$left_mac"
#     sudo nsenter -t "$left_pid" -n ip addr add "${left_ip}/64" dev "$left_iface"
#     sudo nsenter -t "$left_pid" -n ip link set "$left_iface" up

#     sudo ip link set "$right_veth" netns "$right_pid"
#     sudo nsenter -t "$right_pid" -n ip link set "$right_veth" name "$right_iface"
    
#     # Set MAC inside the namespace after renaming
#     sudo nsenter -t "$right_pid" -n ip link set "$right_iface" address "$right_mac"
#     sudo nsenter -t "$right_pid" -n ip addr add "${right_ip}/64" dev "$right_iface"
#     sudo nsenter -t "$right_pid" -n ip link set "$right_iface" up
# }

create_and_assign_veth() {
    local left_veth=$1 right_veth=$2 left_pid=$3 right_pid=$4
    local left_ip=$5 right_ip=$6 left_iface=$7 right_iface=$8

    info "Creating veth pair: $1 ($left_ip on $left_iface) <-> $2 ($right_ip on $right_iface)"
    sudo ip link add "$left_veth" type veth peer name "$right_veth"

    # Define mac_from_name locally for other interfaces
    mac_from_name_local() {
        local name="$1"
        local hash=$(echo -n "$name" | md5sum | awk '{print $1}')
        printf '02:%s:%s:%s:%s:%s' \
            "${hash:0:2}" "${hash:2:2}" "${hash:4:2}" "${hash:6:2}" "${hash:8:2}"
    }

    local left_mac=""
    local right_mac=""

    # Special handling for veth_srvb's MAC
    if [[ "$right_veth" == "veth_srvb" ]]; then
        right_mac="02:cc:ef:38:4b:25" # The desired hardcoded MAC for iperf-server's eth0
        left_mac=$(mac_from_name_local "$left_veth") # Left side still uses deterministic MAC
        sudo ip link set "$right_veth" address "$right_mac" # Set on host before moving to netns
    else
        left_mac=$(mac_from_name_local "$left_veth")
        right_mac=$(mac_from_name_local "$right_veth")
        sudo ip link set "$left_veth" address "$left_mac"
        sudo ip link set "$right_veth" address "$right_mac"
    fi

    # Assign left veth to its namespace and configure
    sudo ip link set "$left_veth" netns "$left_pid"
    sudo nsenter -t "$left_pid" -n ip link set "$left_veth" name "$left_iface"
    sudo nsenter -t "$left_pid" -n ip link set "$left_iface" address "$left_mac"
    sudo nsenter -t "$left_pid" -n ip addr add "${left_ip}/64" dev "$left_iface"
    sudo nsenter -t "$left_pid" -n ip link set "$left_iface" up

    # Assign right veth to its namespace and configure
    sudo ip link set "$right_veth" netns "$right_pid"
    sudo nsenter -t "$right_pid" -n ip link set "$right_veth" name "$right_iface"
    sudo nsenter -t "$right_pid" -n ip link set "$right_iface" address "$right_mac" # <-- This is CRUCIAL
    sudo nsenter -t "$right_pid" -n ip addr add "${right_ip}/64" dev "$right_iface"
    sudo nsenter -t "$right_pid" -n ip link set "$right_iface" up
}

# launch_dpdk_app() {
#     local name="$1"
#     local role="$2"
#     local node_index="$3"
#     local num_transit="$4"
#     local lcore=$((START_LCORE + node_index % $(nproc)))

#     info "Starting DPDK app in $name (role: $role, index: $node_index, lcore: $lcore)"
    
#     local vdevs="--vdev=net_af_packet0,iface=eth0 --vdev=net_af_packet1,iface=eth1"
#     local pmd_dir="-d /usr/local/lib/x86_64-linux-gnu/dpdk/pmds-24.1/"
#     local cmd="dpdk-pot -l $lcore -n 4 --no-pci --iova-mode=va --socket-mem $SOCKET_MEM $pmd_dir $vdevs -- \
#         --type $role \
#         --node-index $node_index \
#         --num-transit $num_transit \
#         --log-level debug"
#     sudo docker exec -d --user root "$name" bash -c "$cmd"
# }

launch_dpdk_app() {
    local name="$1"
    local role="$2"
    local node_index="$3"
    local num_transit="$4"
    
    local num_available_lcores=$(nproc)
    local lcore_offset=$((node_index % num_available_lcores))
    local lcore=$lcore_offset

    info "Starting DPDK app in $name (role: $role, index: $node_index, assigned lcore: $lcore)"
    
    local vdevs="--vdev=net_af_packet0,iface=eth0 --vdev=net_af_packet1,iface=eth1"
    local pmd_dir="-d /usr/local/lib/x86_64-linux-gnu/dpdk/pmds-24.1/"
    local cmd="dpdk-pot -l $lcore -n 4 --no-pci --iova-mode=va --socket-mem $SOCKET_MEM $pmd_dir $vdevs -- \
        --type $role \
        --node-index $node_index \
        --num-transit $num_transit \
        --logging-level debug"
    sudo docker exec -d --user root "$name" bash -c "$cmd"
}

# --- Main Execution ---
cleanup
generate_keys_file
generate_segment_list

info "--- Launching All Containers ---"
# Launch DPDK nodes
launch_container "$INGRESS_NODE"
for i in $(seq 1 $NUM_TRANSIT_NODES); do launch_container "${TRANSIT_NODE_PREFIX}-${i}"; done
launch_container "$EGRESS_NODE"

# --- ADD THESE TWO LINES ---
info "Launching iperf containers..."
launch_container "$IPERF_CLIENT_NODE" "$IPERF_IMAGE_NAME"
launch_container "$IPERF_SERVER_NODE" "$IPERF_IMAGE_NAME"
# ---------------------------

# Collect PIDs
declare -A pids
pids["$INGRESS_NODE"]=$(sudo docker inspect -f '{{.State.Pid}}' "$INGRESS_NODE")
for i in $(seq 1 $NUM_TRANSIT_NODES); do pids["${TRANSIT_NODE_PREFIX}-${i}"]=$(sudo docker inspect -f '{{.State.Pid}}' "${TRANSIT_NODE_PREFIX}-${i}"); done
pids["$EGRESS_NODE"]=$(sudo docker inspect -f '{{.State.Pid}}' "$EGRESS_NODE")
pids["$IPERF_CLIENT_NODE"]=$(sudo docker inspect -f '{{.State.Pid}}' "$IPERF_CLIENT_NODE")
pids["$IPERF_SERVER_NODE"]=$(sudo docker inspect -f '{{.State.Pid}}' "$IPERF_SERVER_NODE")


info "--- Creating Network Topology ---"
# 1. Connect the DPDK chain: ingress -> transit -> ... -> egress
dpdk_nodes=("$INGRESS_NODE")
for i in $(seq 1 $NUM_TRANSIT_NODES); do dpdk_nodes+=("${TRANSIT_NODE_PREFIX}-${i}"); done
dpdk_nodes+=("$EGRESS_NODE")

# The main chain will connect eth1 on the left node to eth0 on the right node
# for i in $(seq 0 $((${#dpdk_nodes[@]} - 2))); do
#     node1=${dpdk_nodes[$i]}
#     node2=${dpdk_nodes[$i+1]}
#     create_and_assign_veth "veth_chain_${i}a" "veth_chain_${i}b" "${pids[$node1]}" "${pids[$node2]}" \
#                            "${IPV6_PREFIX}${i}" "${IPV6_PREFIX}$((i+1))" \
#                            "eth1" "eth0"
# done
# for i in $(seq 0 $((${#dpdk_nodes[@]} - 2))); do
#     node1=${dpdk_nodes[$i]}
#     node2=${dpdk_nodes[$i+1]}
#     ipv6=$((i+1))
#     create_and_assign_veth "veth_chain_${i}a" "veth_chain_${i}b" "${pids[$node1]}" "${pids[$node2]}" \
#                            "${IPV6_PREFIX}${ipv6}" "${IPV6_PREFIX}${ipv6}" \
#                            "eth1" "eth0"
# done
for i in $(seq 0 $((${#dpdk_nodes[@]} - 2))); do
    node1=${dpdk_nodes[$i]}
    node2=${dpdk_nodes[$i+1]}
    left_ipv6="2001:db8:1::$(($i*2+1))"
    right_ipv6="2001:db8:1::$(($i*2+2))"
    create_and_assign_veth "veth_chain_${i}a" "veth_chain_${i}b" "${pids[$node1]}" "${pids[$node2]}" \
                           "$left_ipv6" "$right_ipv6" \
                           "eth1" "eth0"
done

# 2. Connect iperf-client to ingress (on eth0)
create_and_assign_veth "veth_clia" "veth_clib" "${pids[$IPERF_CLIENT_NODE]}" "${pids[$INGRESS_NODE]}" \
                       "$IPERF_CLIENT_IPV6" "${IPV6_PREFIX}100" \
                       "eth0" "eth0"

# 3. Connect egress (eth1) to iperf-server (eth0)
create_and_assign_veth "veth_srva" "veth_srvb" "${pids[$EGRESS_NODE]}" "${pids[$IPERF_SERVER_NODE]}" \
                       "${IPV6_PREFIX}200" "$IPERF_SERVER_IPV6" \
                       "eth1" "eth0"

info "Will sleep for 5 seconds to allow network setup to stabilize..."
sleep 5

info "--- Verifying Connections ---"
info "Pinging from iperf-client to ingress..."
sudo docker exec "$IPERF_CLIENT_NODE" ping -6 -c 2 "${IPV6_PREFIX}100" || error_exit "Client to Ingress ping failed!"

info "Pinging from egress to iperf-server..."
# Note: Egress needs iproute2 for ping. Assuming it's in the DPDK image.
# We must specify eth1 as the outgoing interface.
sudo docker exec "$EGRESS_NODE" ping -6 -c 2 -I eth1 "$IPERF_SERVER_IPV6" || error_exit "Egress to Server ping failed!"

info "Verifying DPDK chain connections..."
# Pass the correct dpdk_nodes array as a single, quoted string
verify_connections "${dpdk_nodes[*]}"

info "--- Starting DPDK Applications ---"
launch_dpdk_app "$INGRESS_NODE" "ingress" 0 "$NUM_TRANSIT_NODES"
for i in $(seq 1 $NUM_TRANSIT_NODES); do
    launch_dpdk_app "${TRANSIT_NODE_PREFIX}-${i}" "transit" "$i" "$NUM_TRANSIT_NODES"
done
launch_dpdk_app "$EGRESS_NODE" "egress" $((NUM_TRANSIT_NODES + 1)) "$NUM_TRANSIT_NODES"

info "--- ✅ Network is live. Ready for iperf test. ---"
echo "Your DPDK application must be configured to forward packets arriving at Ingress"
echo "from source ${IPERF_CLIENT_IPV6} to the final destination ${IPERF_SERVER_IPV6}"
echo ""
echo "To start the iperf server, run:"
echo "  sudo docker exec ${IPERF_SERVER_NODE} iperf -s -u -V"
echo ""
echo "To start the iperf client, run:"
echo "  sudo docker exec ${IPERF_CLIENT_NODE} iperf -c ${IPERF_SERVER_IPV6} -u -V -l 128 -b 10M"
echo ""
echo "To view DPDK logs, run: sudo docker logs -f ${INGRESS_NODE}"

# Command to run
# dpdk-pot -l 1 -n 4 --no-pci --iova-mode=va --socket-mem 128 -d /usr/local/lib/x86_64-linux-gnu/dpdk/pmds-24.1/ --vdev="net_af_packet0,iface=eth0" --vdev="net_af_packet1,iface=eth1" -- --node-index 1 --num-transit 1 --type transit --log-level debug &
# echo "your_message" | nc -u -w1 2a05:d014:dc7:128f:6f72:fa2a:cd2b:29fc 5001