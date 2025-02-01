# CS331 - Computer Networks Assignment 1
## Guntas Singh Saran (22110089) & Hitesh Kumar (22110098)

This guide explains how to execute the `main.sh` script to automate packet sniffing with `sniffer_speed.py` and packet replay with `tcpreplay`. It also includes manual steps for running these tools separately.

**[0.pcap File](https://drive.google.com/file/d/1RYzeM1c66SWBhli8TADAGDsRPSjP3x2e/view?usp=drive_link)**

## Optimal Configuration
- **Optimal PPS:** We've found **1900 PPS** to be the highest rate at which our packet sniffer does not drop packets.
- **Replay Duration:** This corresponds to `tcpreplay` running for approximately **420.20 seconds**.
- **Timeout Recommendation:** Set the timeout a **few seconds beyond 420 seconds to ensure `sniffer_speed.py` starts before `tcpreplay`**.

## Usage Instructions

### Recommended Interface
- **macOS:** Use the **loopback interface `lo0`**. (Works best!)
- **Linux:** Use the **loopback interface `lo`**. (Sends some duplicate packets too)

**We suggest loopback because the code filters loopback traffic. If using another interface, ensure there's no other network traffic to avoid interference.**

### Running the Script

```bash
chmod +x main.sh
```

```bash
./main.sh -i <interface> -p <pps> [-m <mbps>] [-t <timeout>] [-q <question>]
```

#### Flags:
- `-i <interface>`: **(Required)** Network interface to sniff/replay packets. Use `lo0` (macOS) or `lo` (Linux).
- `-p <pps>`: **(Required if `-m` not provided)** Packets per second for `tcpreplay`.
- `-m <mbps>`: **(Optional)** Mbps rate for `tcpreplay` (alternative to `-p`).
- `-t <timeout>`: **(Optional)** Duration (in seconds) for running the sniffer and replay.
- `-q <question>`: **(Optional)** Specify `1` or `2` to get metrics for specific questions. If omitted, only basic metrics are collected.

### Example (these were all we ran):

**This first command runs completely fine on Mac.**
```bash
./main.sh -i lo -p 1900 -t 430
```

**These two commands run perfectly in Linux just that Linux's Loopback duplicates packets that our sniffer has not filtered out.**
```bash
./main.sh -i lo -p 1900 -t 430 -q 1
```

```bash
./main.sh -i lo -p 1900 -t 430 -q 2
```
This runs the sniffer on `lo`, replays packets at 1900 PPS, runs for 430 seconds, and collects metrics for question 1.

---

## Demonstration
### **ALL THE PACKETS ARE RECEIVED WITHOUT LOSS OVER MAC's LOOPBACK `lo0`**

```bash
./main.sh -i lo -p 1900 -t 430
```

<div align = "center">
    <img src = "https://github.com/Hit2737/CN_A1/blob/main/Images_Guntas/main.png" style="width: 100%">
</div>

<div align = "center">
    <img src = "https://github.com/Hit2737/CN_A1/blob/main/Images_Guntas/windows.png" style="width: 100%">
</div>

<div align = "center">
    <img src = "https://github.com/Hit2737/CN_A1/blob/main/Images_Guntas/done.png" style="width: 100%">
</div>


## Manual Execution

### 1. Start Packet Sniffer
Open the first terminal:

```bash
python3 sniffer_speed.py -i lo -t 430 -q 1
```

- `-i lo`: Interface to sniff packets.
- `-t 430`: Run for 430 seconds.
- `-q 1`: Collect metrics for question 1.

### 2. Start Packet Replay
Open a second terminal:

```bash
sudo tcpreplay -i lo --pps=1900 --quiet 0.pcap
```

- `-i lo`: Interface to replay packets.
- `--pps=1900`: Replay rate.
- `0.pcap`: The pcap file to replay.

### 3. Alternative: Sniffing Offline PCAP (No Replay)
If you prefer not to run `tcpreplay` (not recommended), you can sniff packets from an offline pcap file:

```bash
python3 sniffer_speed.py -f 0.pcap -q 1
```

- `-f 0.pcap`: Read packets from the pcap file.
- `-q 1`: Collect metrics for question 1.

---

## Final Notes
- Ensure Python virtual environment (`venv`) is activated if present.
- Use `sudo` for commands requiring elevated permissions.
- Adjust `timeout` based on your replay duration.

---

# Our Results

```bash
~$ sudo tcpreplay -i lo0 --topspeed 0.pcap
```

```
>>
Actual: 805995 packets (364641929 bytes) sent in 1.03 seconds
Rated: 353074502.1 Bps, 2824.59 Mbps, 780426.66 pps
Flows: 41747 flows, 40422.67 fps, 805296 unique flow packets, 454 unique non-flow packets
Statistics for network device: lo0
	Successful packets:        805995
	Failed packets:            0
	Truncated packets:         0
	Retried packets (ENOBUFS): 0
	Retried packets (EAGAIN):  0
```


```bash
~$ python3 sniffer_speed.py -f 0.pcap -q 1
```

```
>>
--- Metrics ---
Total data transferred: 364632128 bytes //364641929 bytes
Total packets transferred: 805963
Min packet size: 42 bytes
Max packet size: 1514 bytes
Average packet size: 452.42 bytes

--- Packet Size Distribution Percentiles ---
50th percentile: 106.0 bytes
75th percentile: 868.0 bytes
90th percentile: 1514.0 bytes
95th percentile: 1514.0 bytes
99th percentile: 1514.0 bytes

Most packets lie between 60.0 and 868.0 bytes

Source-Destination pair with most data: 172.16.133.95:49358 -> 157.56.240.102:443 (17342229 bytes)

--- Performance Metrics ---
----------------------------
Total Packets Received: 805963
Total Data: 364632128 bytes (356086.06 KB)
----------------------------
```

```bash
~$ python3 sniffer_speed.py -f 0.pcap -q 2
```

```
>>
--- Question 2 Metrics ---

All packets destined to IMS server:
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S

All packets both from and to IMS server:
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S / Raw
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S

Unique connections to IMS server (with their connection counts):
defaultdict(<class 'int'>, {'10.1.12.123:1234 -> 10.0.137.79:4321': 30})

All packets transferred on port 4321 (both src and dst):
Ether / IP / UDP 172.16.128.169:rwhois > 172.16.133.248:snmp / SNMP
Ether / IP / UDP 172.16.133.248:snmp > 172.16.128.169:rwhois / SNMP
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S / Raw
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.0.137.79:rwhois > 10.1.12.123:search_agent S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S
Ether / IP / TCP 10.1.12.123:search_agent > 10.0.137.79:rwhois S

----------Summary------------
Q1: Unique Packets Destined to IMS server: 30
Q2: Course registered on IMS is:
course = Embedded_system
Q3: Total data transferred on port 4321: 2970 bytes
Q4: Total number of SuperUsers: 69

-----------------------------


--- Performance Metrics ---
----------------------------
Total Packets Received: 805963
Total Data: 364632128 bytes (356086.06 KB)
----------------------------
```
