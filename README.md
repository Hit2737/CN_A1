# CS331 - Computer Networks Assignment 1
## Guntas Singh Saran (22110089) & Hitesh Kumar (22110098)


# Packet Sniffer & Traffic Replay Automation

This guide explains how to execute the `main.sh` script, which automates the process of running a packet sniffer (`sniffer_speed.py`) and replaying network traffic using `tcpreplay`.

## Prerequisites

- **Operating System:** Linux or macOS
- **Dependencies:**
  - `tcpreplay`
  - `python3`
  - Virtual environment (optional, but recommended)

Ensure you have `gnome-terminal` installed for Linux or Terminal for macOS.

## Script Overview

The `main.sh` script performs the following tasks:
1. Starts a packet sniffer in a new terminal.
2. Replays network traffic (`0.pcap` file) at a specified speed using `tcpreplay`.
3. Manages virtual environments if present.

## Usage

```bash
chmod +x main.sh
```
```bash
./main.sh -i <interface> -p <pps> [-m <mbps>] [-t <timeout>] [-q <question>]
```

### Required Flags

- `-i <interface>`: **(Required)** Network interface **[we suggest LOOPBACK `lo0` (in macOS) and `lo` (in Linux)]** to capture/replay traffic (e.g., lo0`, `en0`, `eth0`, `wlan0`).
- `-p <pps>`: **(Required if `-m` is not provided)** Packets per second for `tcpreplay`, we have figured out **`--pps=1900`** for loss-less tranfer.
- `-q <question>`: Passes a custom question argument to `sniffer_speed.py`, you can specify to replicate the results of question 1 or question 2 (CTF).

### Optional Flags

- `-m <mbps>`: Replay speed in megabits per second (overrides `-p` if provided).
- `-t <timeout>`: Duration in seconds to run the sniffer and replay (automatically stops after timeout).

### Usage Example

1. **Replay using the specified 1900 packets per second and 425 seconds timeout to answer Question 1:**
   ```bash
   ./main.sh -i lo0 -p 1900 -t 425 -q 1
   ```
   
2. **Replay using the specified 1900 packets per second and 425 seconds timeout to answer Question 2:**
   ```bash
   ./main.sh -i lo0 -p 1900 -t 425 -q 2
   ```
   
3. **Replay using the specified 1900 packets per second to answer Question 2:**
   ```bash
    ./main.sh -i lo0 -p 1900 -t 425 -q 2
   ```
   Here you need to interrupt by `<Ctrl-C>` to stop the 

## Virtual Environment Handling

- If a `venv/` directory exists in the current script directory, it will automatically activate it before running Python or `tcpreplay` commands.

## Important Notes

- **PCAP File:** Ensure `0.pcap` exists in the script directory, as it's the file replayed.
- **Permissions:** The script uses `sudo` for privileged operations. You may be prompted for your password.
- **Compatibility:** For Linux systems, `gnome-terminal` is required. For macOS, the script uses AppleScript to open new Terminal windows.

## Stopping the Script

If you need to manually stop the processes:

- Use `Ctrl+C` in the respective terminal windows.
- Uncomment the `kill` section at the end of the script to enable automatic termination of `tcpreplay` processes.

## Manual Running of Scripts

- **Permission Errors:** Ensure you have the necessary privileges to capture/replay packets.
- **Missing Dependencies:** Install `tcpreplay` and `gnome-terminal` if errors occur during execution.

---

```bash
tcpreplay -i en0 --topspeed 0.pcap
```

```bash
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
Actual: 805892 packets (364635582 bytes) sent in 3.23 seconds
Rated: 112840490.4 Bps, 902.72 Mbps, 249392.14 pps
Flows: 41680 flows, 12898.33 fps, 805193 unique flow packets, 454 unique non-flow packets
Statistics for network device: en0
	Successful packets:        805892
	Failed packets:            0
	Truncated packets:         0
	Retried packets (ENOBUFS): 1664125
	Retried packets (EAGAIN):  0
```
