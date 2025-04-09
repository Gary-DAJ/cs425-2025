#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>


void send_raw_packet(int sock, int seq, int syn_flag, int ack_flag) {
    char packet[4096];
    memset(packet, 0, sizeof(packet));

    struct iphdr *iph = (struct iphdr *)packet;

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = 1000; // should be enough
    iph->protocol = IPPROTO_TCP;
    iph->daddr = inet_addr("127.0.0.1");

    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    tcph->dest = htons(12345);
    tcph->seq = htonl(seq);
    tcph->syn = syn_flag;
    tcph->ack = ack_flag;

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        exit(1);
    }
}

int main() {
    int sockfd;

    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        exit(1);
    }

    send_raw_packet(sockfd, 200, 1, 0);

    send_raw_packet(sockfd, 600, 0, 1);

    close(sockfd);
    
    return 0;
}
