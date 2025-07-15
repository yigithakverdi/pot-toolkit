import re
import matplotlib.pyplot as plt

# === Step 1: Parse Server Log ===
def parse_iperf_server_log(path):
    with open(path, 'r') as f:
        lines = f.readlines()

    time_stamps = []
    jitter_list = []
    loss_rate_list = []
    throughput_list = []

    pattern = re.compile(
        r"\[\s*\d+\] (\d+\.\d+)-(\d+\.\d+) sec\s+([\d\.]+) MBytes\s+([\d\.]+) Mbits/sec\s+([\d\.]+) ms\s+(\d+)/(\d+) \(([\d\.]+)%\)"
    )

    for line in lines:
        match = pattern.search(line)
        if match:
            start, end = float(match.group(1)), float(match.group(2))
            throughput = float(match.group(4))
            jitter = float(match.group(5))
            lost = int(match.group(6))
            total = int(match.group(7))
            loss_rate = (lost / total) * 100 if total != 0 else 0
            midpoint = (start + end) / 2
            time_stamps.append(midpoint)
            throughput_list.append(throughput)
            jitter_list.append(jitter)
            loss_rate_list.append(loss_rate)

    return time_stamps, throughput_list, jitter_list, loss_rate_list

# === Step 2: Parse Client Log ===
def parse_iperf_client_log(path):
    with open(path, 'r') as f:
        lines = f.readlines()

    time_stamps = []
    throughput_list = []

    pattern = re.compile(
        r"\[\s*\d+\] (\d+\.\d+)-(\d+\.\d+) sec\s+([\d\.]+) MBytes\s+([\d\.]+) Mbits/sec"
    )

    for line in lines:
        match = pattern.search(line)
        if match:
            start, end = float(match.group(1)), float(match.group(2))
            throughput = float(match.group(4))
            midpoint = (start + end) / 2
            time_stamps.append(midpoint)
            throughput_list.append(throughput)

    return time_stamps, throughput_list

# === Step 3: Plotting ===
def plot_metrics(time_server, throughput_server, jitter, loss_rate, time_client, throughput_client):
    plt.figure(figsize=(15, 10))

    # Throughput Comparison
    plt.subplot(3, 1, 1)
    plt.plot(time_client, throughput_client, label='Client Throughput', color='blue')
    plt.plot(time_server, throughput_server, label='Server Throughput', color='green', linestyle='--')
    plt.xlabel("Time (s)")
    plt.ylabel("Throughput (Mbits/sec)")
    plt.title("Throughput vs. Time")
    plt.legend()
    plt.grid(True)

    # Jitter
    plt.subplot(3, 1, 2)
    plt.plot(time_server, jitter, color='orange')
    plt.xlabel("Time (s)")
    plt.ylabel("Jitter (ms)")
    plt.title("Jitter vs. Time (UDP)")
    plt.grid(True)

    # Packet Loss
    plt.subplot(3, 1, 3)
    plt.plot(time_server, loss_rate, color='red')
    plt.xlabel("Time (s)")
    plt.ylabel("Packet Loss (%)")
    plt.title("Packet Loss Rate vs. Time")
    plt.grid(True)

    plt.tight_layout()
    plt.show()

# === Step 4: Run All ===
if __name__ == "__main__":
    # Update filenames if needed
    server_log = "/home/ubuntu/iperf_server_output_2_transits.txt"
    client_log = "/home/ubuntu/iperf_client_output_2_transits.txt"

    time_server, throughput_server, jitter, loss_rate = parse_iperf_server_log(server_log)
    time_client, throughput_client = parse_iperf_client_log(client_log)

    plot_metrics(time_server, throughput_server, jitter, loss_rate, time_client, throughput_client)
