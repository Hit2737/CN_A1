#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <ctime>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>

using namespace std;

int main(int argc, char *argv[]) {
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <interface> <duration_in_seconds>\n";
        return 1;
    }

    string interface = argv[1];
    int duration = stoi(argv[2]);

    int raw_socket;
    char buffer[65535];
    struct sockaddr saddr;
    socklen_t saddr_size = sizeof(saddr);

    // Create raw socket
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_socket < 0) {
        perror("Socket creation failed");
        return 1;
    }

    // Bind socket to specified interface
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ);
    if (ioctl(raw_socket, SIOCGIFINDEX, &ifr) < 0) {
        perror("Interface binding failed");
        close(raw_socket);
        return 1;
    }

    struct sockaddr_ll sock_addr = {};
    sock_addr.sll_family = AF_PACKET;
    sock_addr.sll_protocol = htons(ETH_P_ALL);
    sock_addr.sll_ifindex = ifr.ifr_ifindex;

    if (bind(raw_socket, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) < 0) {
        perror("Failed to bind socket to interface");
        close(raw_socket);
        return 1;
    }

    cout << "Sniffing packets on interface " << interface << " for " << duration << " seconds...\n";

    int total_packets = 0;
    int total_data = 0;
    vector<int> packet_sizes;
    time_t start_time = time(0);

    while (difftime(time(0), start_time) < duration) {
        ssize_t packet_size = recvfrom(raw_socket, buffer, sizeof(buffer), 0, &saddr, &saddr_size);
        if (packet_size > 0) {
            total_packets++;
            total_data += packet_size;
            packet_sizes.push_back(packet_size);
        }
    }

    close(raw_socket);

    // Compute min, max, and average packet sizes
    int min_pkt_size = packet_sizes.empty() ? 0 : *min_element(packet_sizes.begin(), packet_sizes.end());
    int max_pkt_size = packet_sizes.empty() ? 0 : *max_element(packet_sizes.begin(), packet_sizes.end());
    double avg_pkt_size = packet_sizes.empty() ? 0 : total_data / (double)total_packets;

    // Compute packets per second (pps) and bandwidth in Mbps
    double pps = total_packets / (double)duration;
    double bandwidth_mbps = (total_data * 8.0) / (duration * 1000000.0); // Convert bytes to bits and then Mbps

    // Display results
    cout << "\n--- Packet Sniffing Summary ---\n";
    cout << "Total packets received: " << total_packets << endl;
    cout << "Total data received: " << total_data << " bytes (" << total_data / (1024.0 * 1024.0) << " MB)\n";
    cout << "Min packet size: " << min_pkt_size << " bytes" << endl;
    cout << "Max packet size: " << max_pkt_size << " bytes" << endl;
    cout << "Average packet size: " << avg_pkt_size << " bytes\n";
    cout << "Packets per second (pps): " << pps << " pps\n";
    cout << "Bandwidth usage: " << bandwidth_mbps << " Mbps\n";

    return 0;
}
