#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <ctime>
#include <vector>
#include <cstring>

using namespace std;

int total_packets = 0;
int total_data = 0;
vector<int> packet_sizes;
time_t start_time;
int duration;

// Callback function for processing packets
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    if (difftime(time(0), start_time) > duration) {
        pcap_breakloop((pcap_t *)user); // Stop capturing when time is exceeded
        return;
    }

    total_packets++;
    total_data += pkthdr->len;
    packet_sizes.push_back(pkthdr->len);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <interface> <duration_in_seconds>\n";
        return 1;
    }

    string interface = argv[1];
    duration = stoi(argv[2]);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        cerr << "Could not open device " << interface << ": " << errbuf << endl;
        return 1;
    }

    cout << "Sniffing packets on " << interface << " for " << duration << " seconds...\n";
    start_time = time(0);
    pcap_loop(handle, 0, packet_handler, (u_char *)handle);
    pcap_close(handle);

    // Compute min, max, avg packet sizes
    int min_pkt_size = packet_sizes.empty() ? 0 : *min_element(packet_sizes.begin(), packet_sizes.end());
    int max_pkt_size = packet_sizes.empty() ? 0 : *max_element(packet_sizes.begin(), packet_sizes.end());
    double avg_pkt_size = packet_sizes.empty() ? 0 : total_data / (double)total_packets;
    double pps = total_packets / (double)duration;
    double bandwidth_mbps = (total_data * 8.0) / (duration * 1000000.0); // Convert bytes to bits then Mbps

    cout << "\n--- Packet Sniffing Summary ---\n";
    cout << "Total packets received: " << total_packets << endl;
    cout << "Total data received: " << total_data << " bytes (" << total_data / (1024.0 * 1024.0) << " MB)\n";
    cout << "Min packet size: " << min_pkt_size << " bytes\n";
    cout << "Max packet size: " << max_pkt_size << " bytes\n";
    cout << "Average packet size: " << avg_pkt_size << " bytes\n";
    cout << "Packets per second (pps): " << pps << "\n";
    cout << "Bandwidth usage: " << bandwidth_mbps << " Mbps\n";

    return 0;
}
