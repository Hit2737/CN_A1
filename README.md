# CN_A1

CS331 - Computer Networks Assignment 1

```bash
~$ python3 packet_sniffer.py --timeout 10 --interface en0
~$ python3 packet_sniffer.py -t 10 -i en0
~$ python3 packet_sniffer.py -file /path/to/file.pcap
~$ python3 packet_sniffer.py -f /path/to/file.pcap
```

```bash
Reading packets from ./0.pcap...

--- Metrics ---
Total data transferred: 364564032 bytes
Total packets transferred: 805438
Min packet size: 54 bytes
Max packet size: 1514 bytes
Average packet size: 452.63 bytes
```

```bash
tcpreplay -i en0 --topspeed 0.pcap
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
