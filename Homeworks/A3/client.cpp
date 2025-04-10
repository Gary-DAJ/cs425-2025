#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

// Function to send a raw TCP packet with given sequence number, SYN and ACK flags
void send_raw_packet(int sock, int seq, int syn_flag, int ack_flag) {
    char packet[4096];  // Buffer to hold the full packet (IP + TCP headers)
    memset(packet, 0, sizeof(packet));  // Zero out the buffer

    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(*iph) + sizeof(*tcph)); // Correct length
    iph->protocol = IPPROTO_TCP;
    iph->saddr = inet_addr("127.0.0.1"); // Source IP
    iph->daddr = inet_addr("127.0.0.1"); // Destination IP

    tcph->source = htons(54321);         // Source port is 54321
    tcph->dest = htons(12345);           // Destination port
    tcph->seq = htonl(seq);              // TCP sequence number
    tcph->syn = syn_flag;                // SYN flag
    tcph->ack = ack_flag;                // ACK flag
    tcph->doff = 5;                      // TCP header size (5 * 4 = 20 bytes)

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Send the raw packet
    if (sendto(sock, packet, 400, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto");
        exit(1);
    }
}

// Function to receive a packet and extract the TCP sequence number if SYN-ACK
void receive_syn_ack() {
    int recv_sock;
    char buffer[4096];

    // Create raw socket to receive TCP packets
    if ((recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        perror("recv socket");
        exit(1);
    }

    while (1) {
        ssize_t data_size = recv(recv_sock, buffer, sizeof(buffer), 0);
        if (data_size < 0) {
            perror("recv");
            exit(1);
        }

        struct iphdr *iph = (struct iphdr *)buffer;
        // Check for TCP protocol
        if (iph->protocol != IPPROTO_TCP) {
            perror("non-tcp packet");
            close(recv_sock);
            exit(1);
        }
        struct tcphdr *tcph = (struct tcphdr *)(buffer + iph->ihl * 4);

        // checks: seq number 201, source port 12345, dest port 54321,
        // ack 1 and syn is 1
        if (ntohl(tcph->ack_seq) != 201) {
            fprintf(stderr, "bad packet, ack_seq is %u\n", ntohl(tcph->ack_seq));
            close(recv_sock);
            exit(1);
        }
        if (ntohl(tcph->seq) != 400) {
             fprintf(stderr, "client, syn-ack- unexpected seq %u\n", ntohl(tcph->seq));
             close(recv_sock);
             exit(1);
        }

        if (ntohs(tcph->source) == 12345 && ntohs(tcph->dest) == 54321 && tcph->syn && tcph->ack) {
            printf("Received SYN-ACK with sequence number: %u\n", ntohl(tcph->seq));
            break;
        }
        perror("strange packet");
    }

    close(recv_sock);
}

int main() {
    int sockfd;
    sleep(2);

    // Create raw socket for sending
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("send socket");
        exit(1);
    }

    // Send SYN packet
    send_raw_packet(sockfd, 200, 1, 0);

    // Receive SYN-ACK and print sequence number
    receive_syn_ack();

    // Send ACK packet, handshake completion
    send_raw_packet(sockfd, 600, 0, 1);

    close(sockfd);
    return 0;
}
