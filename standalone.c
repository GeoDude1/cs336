#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>     
#include <string.h>           
#include <netdb.h>            
#include <sys/types.h>       
#include <sys/socket.h>    
#include <netinet/in.h>
#include <arpa/inet.h>      
#include <errno.h>
#include <time.h> 
#include <ctype.h>
#include <json-c/json.h>

#include "read_json.h"
#include "allocations.h"
#include "packet_setup.h"
#include "signal.h"

#define BUF_SIZE 2000

enum{THRESH=100, UDP_HDRLEN=8, ICMP_HDRLEN=8, TCP_HDRLEN=20, IP4_HDRLEN=20, TCP_FLAG_LEN=8};

int times_index = 0;
time_t times[4] = {0}; 

void 
my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body)
{

    time_t t = packet_header->ts.tv_sec;
    times[times_index++] = t;

    if (times_index == 4)
    {
        double low_entropy = (((double)times[1]) - ((double)times[0]));
        double high_entropy = (((double)times[3]) - ((double)times[2]));

        low_entropy *= 100;
        high_entropy *= 100;

        if ((high_entropy - low_entropy) > THRESH)
        {
            printf("COMPRESSION DETECTED\n");
        }
        else
        {
            printf("COMPRESSION NOT DETECTED\n");
        }

        exit(EXIT_SUCCESS);
    }
    
    return; 
}


int 
main(int argc, char **argv)
{
    FILE * fp;
    char buffer[BUF_SIZE],
    struct sockaddr_in server_address, client_address;
    struct json_object *parsed_json, *Server_IP_Address, *Source_Port_Number_UDP, *Destination_Port_Number_UDP,
    *Destination_Port_Number_TCP_Head, *Destination_Port_Number_TCP_Tail, *Port_Number_TCP, 
    *Size_UDP_Payload, *Inter_Measurement_Time, *Number_UDP_Packets, *TTL_UDP_Packets;

    //Check for proper usage
    if (argv[1] == NULL)
    {
        printf("ERROR!\nProper ussage ./'name of executable' 'my_config_file'.json\n");
        return EXIT_FAILURE;
    }

    //Open config file
    fp = fopen(argv[1],"r"); //opens the file myconfig.json
    if(fp == NULL)
    {
        printf("ERROR OPENNING FILE!\n"); //catch null pointer
        return EXIT_FAILURE;
    }
    printf("Parsing...\n");
    fread(buffer, BUF_SIZE, 1, fp); //reads files and puts contents inside buffer
    parsed_json = json_tokener_parse(buffer); //parse JSON file's contents and converts them into a JSON object

    //Store parsed data into variables
    json_object_object_get_ex(parsed_json, "Server_IP_Address", &Server_IP_Address);
    json_object_object_get_ex(parsed_json, "Source_Port_Number_UDP", &Source_Port_Number_UDP);
    json_object_object_get_ex(parsed_json, "Destination_Port_Number_UDP", &Destination_Port_Number_UDP);
    json_object_object_get_ex(parsed_json, "Destination_Port_Number_TCP_Head", &Destination_Port_Number_TCP_Head);
    json_object_object_get_ex(parsed_json, "Destination_Port_Number_TCP_Tail", &Destination_Port_Number_TCP_Tail);
    json_object_object_get_ex(parsed_json, "Port_Number_TCP", &Port_Number_TCP);
    json_object_object_get_ex(parsed_json, "Size_UDP_Payload", &Size_UDP_Payload);
    json_object_object_get_ex(parsed_json, "Inter_Measurement_Time", &Inter_Measurement_Time);
    json_object_object_get_ex(parsed_json, "Number_UDP_Packets", &Number_UDP_Packets);
    json_object_object_get_ex(parsed_json, "TTL_UDP_Packets", &TTL_UDP_Packets);
    printf("Parsing Successful\n");

    signal(SIGALRM, sigalarm_handler);
    alarm(300);
    /* 
        * unlike our server_cooperative/client_cooperative  we are using raw sockets for deeper control over the
            packet data specifications (layers and payload)
    */
    int bytes;

    if (argc < 2 || argc > 3)
    {
        fprintf (stderr, "ERROR: Too few or many arguments.\n");
        exit (EXIT_FAILURE);
    }
    unsigned int packet_id = 0;
    //read JSON file to obtain data (TTL will be our main variable)
    while (*json_object_get_string(Server_IP_Address) == ' ')
    {
        json_object_get_string(Server_IP_Address)++;
    }

    if (argc == 3)
    {
        json_object_get_int(TTL_UDP_Packets) = atoi(argv[2]);
    }

    pid_t child = fork();

    if (child == -1)
    {
        printf("Fork failed exiting...\n");
        exit(EXIT_FAILURE);
        return -1;
    }
    else if (child == 0)
    {
        char dev[] = "enp0s3";
        pcap_t *handle;
        char error_buffer[PCAP_ERRBUF_SIZE];
        struct bpf_program filter;

        char filter_exp[1000] = {0};
        sprintf(filter_exp, "(dst %s) && (src 192.168.86.211) && (tcp[tcpflags] & (tcp-rst) != 0) && ((port %d) || (port %d))", 
        json_object_get_string(Server_IP_Address), json_object_get_int(Destination_Port_Number_TCP_Head), json_object_get_int(Destination_Port_Number_TCP_Tail));
       
        bpf_u_int32 subnet_mask, ip;

        if (pcap_lookupnet(dev, &ip, &subnet_mask, error_buffer) == -1) {
            printf("Could not get information for device: %s\n", dev);
            ip = 0;
            subnet_mask = 0;
        }
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, error_buffer);
        if (handle == NULL) {
            printf("Could not open %s - %s\n", dev, error_buffer);
            return 2;
        }
        if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
            printf("Bad filter - %s\n", pcap_geterr(handle));
            return 2;
        }
        if (pcap_setfilter(handle, &filter) == -1) {
            printf("Error setting filter - %s\n", pcap_geterr(handle));
            return 2;
        }

        pcap_loop(handle, 0, my_packet_handler, NULL);

        pcap_close(handle);
    }
    else
    {
        int i, status, sd, *ip_flags, *tcp_flags;
        const int on = 1;
        char *interface, *target, *src_ip, *dst_ip;
        struct ip iphdr;
        struct tcphdr tcphdr;
        uint8_t *tcp_pkt_hd, *udp_pkt, *tcp_pkt_tl, *udp_pkt_2;
        struct addrinfo hints, *res;
        struct sockaddr_in *ipv4, sin;
        struct ifreq ifr;
        void *tmp;

        // Allocate memory for various arrays.
        tcp_pkt_hd = allocate_ustrmem (IP_MAXPACKET);
        tcp_pkt_tl = allocate_ustrmem (IP_MAXPACKET);
        interface = allocate_strmem (40);
        target = allocate_strmem (40);
        src_ip = allocate_strmem (INET_ADDRSTRLEN);
        dst_ip = allocate_strmem (INET_ADDRSTRLEN);
        ip_flags = allocate_intmem (4);
        tcp_flags = allocate_intmem (8);

        // Interface to send packet through.
        strcpy (interface, "enp0s3");
        sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
        // Submit request for a socket descriptor to look up interface.
        if (sd < 0) {
            perror ("socket() failed to get socket descriptor for using ioctl() ");
            exit (EXIT_FAILURE);
        }

        // Use ioctl() to look up interface index which we will use to
        // bind socket descriptor sd to specified interface with setsockopt() since
        // none of the other arguments of sendto() specify which interface to use.
        memset (&ifr, 0, sizeof (ifr));
        snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
        if (ioctl (sd, SIOCGIFINDEX, &ifr) < 0) {
            perror ("ioctl() failed to find interface ");
            return (EXIT_FAILURE);
        }
        close (sd);

        // Source IPv4 address: you need to fill this out
        strcpy (src_ip, "192.168.86.211");

        // Destination URL or IPv4 address: you need to fill this out
        strcpy (target, json_object_get_string(Server_IP_Address));

        // Fill out hints for getaddrinfo().
        memset (&hints, 0, sizeof (struct addrinfo));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = hints.ai_flags | AI_CANONNAME;
        status = getaddrinfo (target, NULL, &hints, &res);
        // Resolve target using getaddrinfo().
        if (status != 0) {
            fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
            exit (EXIT_FAILURE);
        }
        ipv4 = (struct sockaddr_in *) res->ai_addr;
        tmp = &(ipv4->sin_addr);
        if (inet_ntop (AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
            status = errno;
            fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
            exit (EXIT_FAILURE);
        }
        freeaddrinfo (res);

        // IPv4 header
        // IPv4 header length (4 bits): Number of 32-bit words in header = 5
        iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

        // Internet Protocol version (4 bits): IPv4
        iphdr.ip_v = 4;

        // Type of service (8 bits)
        iphdr.ip_tos = 0;

        // Total length of datagram (16 bits): IP header + TCP header
        iphdr.ip_len = htons (IP4_HDRLEN + TCP_HDRLEN);

        // ID sequence number (16 bits): unused, since single datagram
        iphdr.ip_id = htons (0);

        // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

        // Zero (1 bit)
        ip_flags[0] = 0;

        // Do not fragment flag (1 bit)
        ip_flags[1] = 0;

        // More fragments following flag (1 bit)
        ip_flags[2] = 0;

        // Fragmentation offset (13 bits)
        ip_flags[3] = 0;

        iphdr.ip_off = htons ((ip_flags[0] << 15)
                                                + (ip_flags[1] << 14)
                                                + (ip_flags[2] << 13)
                                                +  ip_flags[3]);

        // Time-to-Live (8 bits): default to maximum value
        iphdr.ip_ttl = 255;

        // Transport layer protocol (8 bits): 6 for TCP
        iphdr.ip_p = IPPROTO_TCP;
        status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src));
        // Source IPv4 address (32 bits)
        if (status != 1) {
            fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
            exit (EXIT_FAILURE);
        }

        status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst));
        // Destination IPv4 address (32 bits)
        if (status != 1) {
            fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
            exit (EXIT_FAILURE);
        }

        // IPv4 header checksum (16 bits): set to 0 when calculating checksum
        iphdr.ip_sum = 0;
        iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);

        // TCP header
        // Source port number (16 bits)
        tcphdr.th_sport = htons (8080);

        // Destination port number (16 bits)
        tcphdr.th_dport = htons (atoi(json_object_get_int(Destination_Port_Number_TCP_Head)));

        // Sequence number (32 bits)
        tcphdr.th_seq = htonl (0);

        // Acknowledgement number (32 bits): 0 in first packet of SYN/ACK process
        tcphdr.th_ack = htonl (0);

        // Reserved (4 bits): should be 0
        tcphdr.th_x2 = 0;

        // Data offset (4 bits): size of TCP header in 32-bit words
        tcphdr.th_off = TCP_HDRLEN / 4;

        // Flags (8 bits)

        // FIN flag (1 bit)
        tcp_flags[0] = 0;

        // SYN flag (1 bit): set to 1
        tcp_flags[1] = 1;

        // RST flag (1 bit)
        tcp_flags[2] = 1;

        // PSH flag (1 bit)
        tcp_flags[3] = 0;

        // ACK flag (1 bit)
        tcp_flags[4] = 0;

        // URG flag (1 bit)
        tcp_flags[5] = 0;

        // ECE flag (1 bit)
        tcp_flags[6] = 0;

        // CWR flag (1 bit)
        tcp_flags[7] = 0;

        tcphdr.th_flags = 0;

        for (i=0; i<8; i++) {
            tcphdr.th_flags += (tcp_flags[i] << i);
        }

        // Window size (16 bits)
        tcphdr.th_win = htons (65535);

        // Urgent pointer (16 bits): 0 (only valid if URG flag is set)
        tcphdr.th_urp = htons (0);

        // TCP checksum (16 bits)
        tcphdr.th_sum = tcp4_checksum (iphdr, tcphdr);

        // Prepare packet.

        // First part is an IPv4 header.
        memcpy (tcp_pkt_hd, &iphdr, IP4_HDRLEN * sizeof (uint8_t));

        // Next part of packet is upper layer protocol header.
        memcpy ((tcp_pkt_hd + IP4_HDRLEN), &tcphdr, TCP_HDRLEN * sizeof (uint8_t));

        tcphdr.th_dport = htons (atoi(json_object_get_int(Destination_Port_Number_TCP_Tail)));

        // TCP checksum (16 bits)
        tcphdr.th_sum = tcp4_checksum (iphdr, tcphdr);

        // First part is an IPv4 header.
        memcpy (tcp_pkt_tl, &iphdr, IP4_HDRLEN * sizeof (uint8_t));

        // Next part of packet is upper layer protocol header.
        memcpy ((tcp_pkt_tl + IP4_HDRLEN), &tcphdr, TCP_HDRLEN * sizeof (uint8_t));
        
        // The kernel is going to prepare layer 2 information (ethernet frame header) for us.
        // For that, we need to specify a destination for the kernel in order for it
        // to decide where to send the raw datagram. We fill in a struct in_addr with
        // the desired destination IP address, and pass this structure to the sendto() function.
        memset (&sin, 0, sizeof (struct sockaddr_in));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;
        sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
        // Submit request for a raw socket descriptor.
        if (sd < 0) {
            perror ("socket() failed ");
            exit (EXIT_FAILURE);
        }

        // Set flag so socket expects us to provide IPv4 header.
        if (setsockopt (sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
            perror ("setsockopt() failed to set IP_HDRINCL ");
            exit (EXIT_FAILURE);
        }

        // Bind socket to interface index.
        if (setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0) {
            perror ("setsockopt() failed to bind to interface ");
            exit (EXIT_FAILURE);
        }

        struct udphdr udphdr;

        uint8_t * data = allocate_ustrmem (json_object_get_int(Size_UDP_Payload));
            // UDP data
        int datalen = json_object_get_int(Size_UDP_Payload);
        memset (data, 0, json_object_get_int(Size_UDP_Payload));
        // Transport layer protocol (8 bits): 17 for UDP
        iphdr.ip_p = IPPROTO_UDP;
        iphdr.ip_ttl = json_object_get_int(TTL_UDP_Packets);


        // IPv4 header checksum (16 bits): set to 0 when calculating checksum
        iphdr.ip_sum = 0;
        iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);

        // UDP header

        // Source port number (16 bits): pick a number
        udphdr.source = htons (4950);

        // Destination port number (16 bits): pick a number
        udphdr.dest = htons (9999);

        // Length of UDP datagram (16 bits): UDP header + UDP data
        udphdr.len = htons (UDP_HDRLEN + datalen);

        // UDP checksum (16 bits)
        udphdr.check = udp4_checksum (iphdr, udphdr, data, datalen);

        // Fill out ethernet frame header.

        // Ethernet frame length = ethernet data (IP header + UDP header + UDP data)
        int frame_length = IP4_HDRLEN + UDP_HDRLEN + datalen;
        udp_pkt = allocate_ustrmem (IP_MAXPACKET);
        udp_pkt_2 = allocate_ustrmem (IP_MAXPACKET);

        // IPv4 header
        memcpy (udp_pkt, &iphdr, IP4_HDRLEN * sizeof (uint8_t));

        // UDP header
        memcpy (udp_pkt + IP4_HDRLEN, &udphdr, UDP_HDRLEN);

        // UDP data
        memcpy (udp_pkt + IP4_HDRLEN + UDP_HDRLEN, data, datalen);

        read_high_entropy_data(&data[16], json_object_get_int(Size_UDP_Payload)-16);


        // IPv4 header
        memcpy (udp_pkt_2, &iphdr, IP4_HDRLEN * sizeof (uint8_t));

        // UDP header
        memcpy (udp_pkt_2 + IP4_HDRLEN, &udphdr, UDP_HDRLEN);

        // UDP data
        memcpy (udp_pkt_2 + IP4_HDRLEN + UDP_HDRLEN, data, datalen);

        sleep(5);

        // Send packet.
        if (sendto (sd, tcp_pkt_hd, IP4_HDRLEN + TCP_HDRLEN, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)  {
            perror ("sendto() failed ");
            exit (EXIT_FAILURE);
        }

        for (int i = 0; i < json_object_get_int(Number_UDP_Packets); i++)
        {
            packet_id_setup(udp_pkt + IP4_HDRLEN + UDP_HDRLEN, packet_id++);
            // Send ethernet frame to socket.
            if ((bytes = sendto (sd, udp_pkt, frame_length, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr))) <= 0) {
                perror ("sendto() failed");
                exit (EXIT_FAILURE);
            }
        }

        if (sendto (sd, tcp_pkt_tl, IP4_HDRLEN + TCP_HDRLEN, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)  {
            perror ("sendto() failed ");
            exit (EXIT_FAILURE);
        }

        sleep(json_object_get_int(Inter_Measurement_Time));

            // Send packet.
        if (sendto (sd, tcp_pkt_hd, IP4_HDRLEN + TCP_HDRLEN, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)  {
            perror ("sendto() failed ");
            exit (EXIT_FAILURE);
        }

        for (int i = 0; i < json_object_get_int(Number_UDP_Packets); i++)
        {
            packet_id_setup(udp_pkt_2 + IP4_HDRLEN + UDP_HDRLEN, packet_id++);
            // Send ethernet frame to socket.
            if ((bytes = sendto (sd, udp_pkt_2, frame_length, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr))) <= 0) {
                perror ("sendto() failed");
                exit (EXIT_FAILURE);
            }
        }

        if (sendto (sd, tcp_pkt_tl, IP4_HDRLEN + TCP_HDRLEN, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)  {
            perror ("sendto() failed ");
            exit (EXIT_FAILURE);
        }

        printf("Parent finished sending all packets\n");

        int exit_status;
        waitpid(child, &exit_status, 0);

        // Close socket descriptor.
        close (sd);
        // Free allocated memory.
        free (tcp_pkt_hd);
        free (tcp_pkt_tl);
        free (udp_pkt);
        free (udp_pkt_2);
        free (data);
        free (interface);
        free (target);
        free (src_ip);
        free (dst_ip);
        free (ip_flags);
        free (tcp_flags);
        return (EXIT_SUCCESS);
    }
}
