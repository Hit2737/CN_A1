# Packet Sniffer and Traffic Analysis 🕵️‍♂️📊

## Overview 🚀

This project captures network traffic using a `scapy`-based packet sniffer, analyzes key metrics (e.g., packet size, flow counts), and saves the results in CSV files. It is useful for monitoring replayed traffic using tools like `tcpreplay`. The program tracks metrics like total data transferred, packet sizes, source-destination pairs, and flow counts.

## Features ✨

- **Capture Packets**: Sniff traffic on a specific network interface for a given duration.
- **Metrics**: Calculates total data transferred, total packets, min/max/average packet sizes, and tracks source-destination flows.
- **Flow Counts**: Tracks the number of flows for source and destination IPs.
- **CSV Output**: Saves metrics, flows, and source-destination data in CSV files for analysis.
- **Visualization**: Generates and saves a histogram of packet sizes.

## How It Works 🛠️

1. **Capture Traffic**: Uses `scapy.sniff()` to capture packets from a specified network interface.
2. **Analyze Packets**: Extracts key details like packet size, source/destination IPs, and ports.
3. **Generate CSVs**: Saves the captured data and metrics in `packet_metrics.csv`, `packet_flows.csv`, and `ip_flows.csv`.
4. **Plot Data**: Creates a histogram of packet sizes and saves it as an image (`packet_size_distribution.png`).

## Files Generated 📂

- **`packet_metrics.csv`**: Contains overall traffic stats (total data, packet count, etc.).
- **`packet_flows.csv`**: Lists source-destination pairs and data transferred.
- **`ip_flows.csv`**: Tracks flow counts for each IP.
- **`packet_size_distribution.png`**: A histogram of packet sizes.

## Running the Script ⚙️

1. **Install Dependencies**:
   ```bash
   pip install scapy matplotlib
   ```

2. **Run the Script**:
   ```bash
   python packet_sniffer.py
   ```

3. **Replay Traffic**:
   If you're replaying traffic with `tcpreplay`, start the replay before running the script. The sniffer will capture it during the specified duration.
   ```bash
   tcpreplay --intf1=lo --topspeed path/to/pcapfile
   ```

## License 📜

MIT License.
