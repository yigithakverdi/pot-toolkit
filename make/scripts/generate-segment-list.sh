#!/bin/bash

# Script to generate a segment list file for the SRv6 path
# Usage: ./generate-segment-list.sh [num_transit_nodes] [ipv6_prefix] [output_file]

# Default values
NUM_TRANSIT_NODES=${1:-2}
IPV6_PREFIX=${2:-"2a05:d014:dc7:12"}
OUTPUT_FILE=${3:-"$(pwd)/segment_list.txt"}

# Function to log messages
info() {
    echo -e "\033[1;34m[INFO]\033[0m $1"
}

error() {
    echo -e "\033[1;31m[ERROR]\033[0m $1"
}

success() {
    echo -e "\033[1;32m[SUCCESS]\033[0m $1"
}

# Generate segment list file
generate_segment_list() {
    info "Generating segment list file at $OUTPUT_FILE"
    > "$OUTPUT_FILE"  # Clear file
    
    # Add all transit nodes to the segment list in reverse order (last to first)
    # This creates a path that will be traversed in order: ingress → transit-1 → ... → transit-N → egress
    for i in $(seq $NUM_TRANSIT_NODES -1 1); do
        # Generate an IPv6 address for this transit node
        # Format: [prefix]:dc:96:48:6b:f3:e1:82:c7:b$i
        local ipv6="${IPV6_PREFIX}:dc:96:48:6b:f3:e1:82:c7:b${i}"
        echo "$ipv6" >> "$OUTPUT_FILE"
    done
    
    # Add the egress node last
    # Format: [prefix]:09:81:69:d7:d9:3b:cb:d2:b3
    local egress_ipv6="${IPV6_PREFIX}:09:81:69:d7:d9:3b:cb:d2:b3"
    echo "$egress_ipv6" >> "$OUTPUT_FILE"
    
    success "Segment list file generated with $((NUM_TRANSIT_NODES + 1)) entries"
}

# Main execution
generate_segment_list

# Display the contents
info "Generated segment list:"
cat "$OUTPUT_FILE" | nl

# Display usage instructions
echo 
echo "==== How to use this segment list ===="
echo "1. Mount this file in your containers:"
echo "   -v \"$OUTPUT_FILE:/etc/dpdk-pot/segment_list.txt\""
echo 
echo "2. In your DPDK-POT application:"
echo "   --segment-list /etc/dpdk-pot/segment_list.txt"
echo 
echo "3. This creates a path: ingress → transit-1 → ... → transit-N → egress"
