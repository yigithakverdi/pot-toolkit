#!/bin/bash

# Set the number of transit nodes for this experiment
TRANSIT_NODES=4  # Change this to 4, 5, etc. as needed

# Directory to store results
RESULTS_DIR="/home/ubuntu/dpdk-pot/results/transit-${TRANSIT_NODES}"
echo "[INFO] Creating results directory: $RESULTS_DIR"
mkdir -p "$RESULTS_DIR"

# Datagram sizes and bandwidths to test
DATAGRAM_SIZES=(64 512)
BANDWIDTHS=(10 20 50 100 200)

# Duration and other iperf options
DURATION=60
INTERVAL=0.5
SERVER_IP="2001:db8:1::100"

echo "[INFO] Starting experiments for $TRANSIT_NODES transit nodes."
for SIZE in "${DATAGRAM_SIZES[@]}"; do
  for BW in "${BANDWIDTHS[@]}"; do
    SERVER_OUT="iperf_server_output_${TRANSIT_NODES}_transits_${SIZE}_${BW}.txt"
    CLIENT_OUT="iperf_client_output_${TRANSIT_NODES}_transits_${SIZE}_${BW}.txt"

    echo "[INFO] Running experiment: Datagram size = $SIZE, Bandwidth = ${BW}M"
    echo "[INFO] Starting iperf server... (output: $SERVER_OUT)"
    sudo docker exec pot-iperf-server iperf -s -u -V -i $INTERVAL -t $DURATION > "$SERVER_OUT" 2>&1 &
    SERVER_EXEC_PID=$!
    sleep 1

    echo "[INFO] Starting iperf client... (output: $CLIENT_OUT)"
    sudo docker exec pot-iperf-client iperf -c $SERVER_IP -u -V -l $SIZE -b ${BW}M -t $DURATION -i $INTERVAL > "$CLIENT_OUT" 2>&1

    echo "[INFO] Killing iperf server process inside container (just in case)..."
    sudo docker exec pot-iperf-server pkill iperf 2>/dev/null

    wait $SERVER_EXEC_PID

    echo "[INFO] Experiment complete for size $SIZE, bandwidth $BW. Moving output files."
    mv "$SERVER_OUT" "$RESULTS_DIR/"
    mv "$CLIENT_OUT" "$RESULTS_DIR/"
    echo "[INFO] Files moved to $RESULTS_DIR."
    echo "---------------------------------------------"
  done
done

echo "[INFO] All experiments completed. Results are in $RESULTS_DIR"