/**
 * @file flow.c
 * @author Michal Uhrecký (xuhrec00)
 * @brief Netflow exportér
 * @date 2022-11-7
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <pcap.h>
#include <stdbool.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include "flow.h"

#define SIZE_ETHERNET 14
#define ACTIVE_TIMER_DEFAULT 60
#define INACTIVE_TIMER_DEFAULT 10
#define FLOW_CACHE_DEFAULT_SIZE 1024
#define __FAVOR_BSD
  
void print_help()
{   
    printf(" ./flow [-f <file>] [-c <netflow_collector:port>] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]\n");
    printf(" -f <file> name of pcap file, default is STDIN\n");
    printf(" -c <neflow_collector:port> IP address/hostname of collector and optionally UDP Port, default is 127.0.0.1:2055\n");
    printf(" -a <active_timer> interval in seconds, after this interval all active records exporter exports to collector, default is 60\n");
    printf(" -i <inactive_timer> interval in seconds , after this intervall all inactive records exporter exports to collector, default is 10\n");
    printf(" -m <count> flow-cache size, when flow-cache size is full, exporter exports oldest record, default is 1024\n");
}


char *parse_host(char *netflow_collector)
{
    char *host_name;
    int host_name_len = 0;
    for(int i = 0; netflow_collector[i] != ':' && netflow_collector[i] != '\0'; i++)
    {
        host_name_len++;
    }

    host_name = (char *) malloc(host_name_len + 1);
    strncpy(host_name, netflow_collector, host_name_len);

    return host_name;
}

char *parse_port(char *netflow_collector)
{   
    char *port;
    int host_name_len = 0;
    int port_len = 0;
    int i;
    for(i = 0; netflow_collector[i] != ':' && netflow_collector[i] != '\0'; i++)
    {
        host_name_len++;
    }
    
    if (netflow_collector[i] != ':')
    {
        return "2055";
    }

    for(i = host_name_len + 1; netflow_collector[i] != '\0'; i++)
    {
        port_len++;
    }

    port = (char *) malloc(port_len + 1);
    strcpy(port, netflow_collector + host_name_len + 1);

    return port;
}

int main(int argc, char *argv[])
{


    int sock; // socket descriptor
    struct sockaddr_in server; // address structures of the server and the client
    struct hostent *servent; // network host entry required by gethostbyname()    

    // pcap potrebné premenné na spracovanie packetu
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    u_char *packet;
    pcap_t *handle;

    // sieťové štruktúry
    const struct ether_header *ethernet;
    const struct iphdr *ip_hdr;  
    const struct udphdr *udp;
    const struct tcphdr *tcp;


    int cache_index = 0; // aktuálny index vo flow_cachi
    int layer3_bytes = 0; // bytes na ip vrstve
    int existing_flow_index; // pomocná premenná, kde sa ukladá existujúci index vo flow_cachi pri updatovaní flowu
    int tmp_flow_sequence = 0; // exportujem, potom inkrementujem
    int size_ip; // veľkost ip hlavičky
    int packet_counter = 0; // počítadlo packetov

    char *port = ""; // port
    char *host_name = ""; // adresa/hostname

    long long int first_packet_time; // čas úplne prvého packetu v súbore
    long long int current_packet_time_sec; // čas aktuálneho packetu v sekundách
    long long int current_packet_time_nsec; // čas aktuálneho packetu v nanosekundách

    u_int8_t tmp_prot; // pomocná premenná na protokol
    u_int8_t tmp_tcp_flags; // pomocná premenná na tcp_flags
    u_int16_t tmp_srcport; // pomocná premenná na source_port
    u_int16_t tmp_dstport; // pomocná premenná na destination_port
    u_int32_t tmp_SysUptime; // pomocná premenná na SysUptime
    char *file; // file descriptor pre pcap súbor
    bool stdin_flag = true; // flag na načítanie zo súbory alebo stdin
    bool skip_flow = false; // flag na preskočenie packetu v prípade neznámeho protokolu
    bool is_new_flow = true; // flag na zistenie nového flowu

    // inicializovanie východzích hodnôt
    char *netflow_collector = "127.0.0.1:2055";
    u_int32_t active_timer = ACTIVE_TIMER_DEFAULT;
    u_int32_t inactive_timer = INACTIVE_TIMER_DEFAULT;
    int flow_cache_size = FLOW_CACHE_DEFAULT_SIZE;

    // parsovanie argumentov
    for(int i = 1; i < argc; i++)
    {
		if(strcmp("-f", argv[i]) == 0)
        {
			file = argv[i+1];
            stdin_flag = false;
			i++;
		}
        else if(strcmp("-c", argv[i]) == 0)
        {
			netflow_collector = argv[i+1];
			i++;
        }
        else if(strcmp("-a", argv[i]) == 0)
        {
            active_timer = atoi(argv[i+1]);
            i++; 
        }
        else if(strcmp("-i",argv[i]) == 0)
        {
            inactive_timer = atoi(argv[i+1]);
			i++;
		}
        else if(strcmp("-m",argv[i]) == 0)
        {
            flow_cache_size = atoi(argv[i+1]);
			i++;
            if (flow_cache_size < 1)
            {
                fprintf(stderr,"Can not have count smaller than 1, -h or --help for more informations!\n");
                return 1;
            }
		}
        else if(strcmp("-h",argv[i]) == 0 || strcmp("--help",argv[i]) == 0)
        {
            print_help();
            return 1;
		}
        else
        {
            fprintf(stderr,"Problem with parsing arguments, -h or --help for more informations!\n");
            return 1;
        }
    }

    host_name = parse_host(netflow_collector);
    port = parse_port(netflow_collector);

    memset(&server,0,sizeof(server));
    server.sin_family = AF_INET;
    if ((servent = gethostbyname(host_name)) == NULL)
        fprintf(stderr,"gethostbyname() failed\n");

    memcpy(&server.sin_addr,servent->h_addr,servent->h_length);
    server.sin_port = htons(atoi(port)); 

    // Vytvorenie UDP socketu
    if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)   //create a client socket
        fprintf(stderr,"socket() failed\n");

    NET_FLOW_PACKET flow_cache[flow_cache_size];

    // otvorenie pcap súboru
    if (stdin_flag == true)
        handle = pcap_fopen_offline(stdin, errbuf);
    else
        handle = pcap_fopen_offline(fopen(file, "r"), errbuf);

    if (handle == NULL) 
    { 
        fprintf(stderr,"Couldn't open pcap file or read from stdin %s: %s\n", file, errbuf); 
        exit(1); 
    }

    // hlavný cyklus v ktorom načítavam packety po jednom
    while ((packet = (u_char *)pcap_next(handle,&header))) 
    {   
        ethernet = (struct ether_header*)(packet);
        
        // Ak to je iny prenos ako ip tak preskakujem packet
        if (htons(ethernet->ether_type) != ETHERTYPE_IP)
            continue; 

        ip_hdr = (struct iphdr*)(packet + SIZE_ETHERNET);
        size_ip = ip_hdr->ihl*4;

        // switch v ktorom zistujem protokol
        switch(ip_hdr->protocol)
         {
            case IPPROTO_TCP:
                tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);
                tmp_prot = IPPROTO_TCP; 
                tmp_srcport = ntohs(tcp->th_sport);
                tmp_dstport = ntohs(tcp->th_dport);
                tmp_tcp_flags = tcp->th_flags;
                break;
            case IPPROTO_UDP:
                udp = (struct udphdr*)(packet + SIZE_ETHERNET + size_ip);
                tmp_prot = IPPROTO_UDP;
                tmp_srcport = ntohs(udp->uh_sport);
                tmp_dstport = ntohs(udp->uh_dport);
                break;
            case IPPROTO_ICMP:
                tmp_prot = IPPROTO_ICMP;
                tmp_srcport = 0;
                tmp_dstport = 0;
                break;
            default:
                skip_flow = true;
                break;
        }

        // Neznámy protokol preskočím
        if(skip_flow == true)
        {
            skip_flow = false;
            continue;
        }

        layer3_bytes = htons(ip_hdr->tot_len);
        current_packet_time_sec = header.ts.tv_sec;
        current_packet_time_nsec = header.ts.tv_usec * 1000;

        // Nastavím čas 0 v prípade prvého packetu, inak aktualizuj SysUptime
        if (packet_counter == 0)
        {
            tmp_SysUptime = 0;
            first_packet_time = header.ts.tv_sec*1000 + header.ts.tv_usec/1000;
        }
        else
        {
            tmp_SysUptime = (u_int32_t) ((header.ts.tv_sec*1000 + header.ts.tv_usec/1000) - first_packet_time);
        }

        // Skontrolujem kazdy jeden flow v cykle
        for(int i = 0; i < cache_index; i++)
        {   
            // Kontrolujem oby dva timery, či netreba exportovať nejaký flow
            if (((tmp_SysUptime - flow_cache[i].record.First) > active_timer*1000) || ((tmp_SysUptime - flow_cache[i].record.Last) > inactive_timer*1000))
            {
                flow_cache[i].header.SysUptime = htonl(tmp_SysUptime);
                flow_cache[i].header.unix_secs = htonl(current_packet_time_sec);
                flow_cache[i].header.unix_nsecs = htonl(current_packet_time_nsec);
                flow_cache[i].header.flow_sequence = htonl(tmp_flow_sequence);
                flow_cache[i].record.srcport = htons(flow_cache[i].record.srcport);
                flow_cache[i].record.dstport = htons(flow_cache[i].record.dstport);
                flow_cache[i].record.First = htonl(flow_cache[i].record.First);
                flow_cache[i].record.Last = htonl(flow_cache[i].record.Last);
                flow_cache[i].record.dOctets = htonl(flow_cache[i].record.dOctets);
                flow_cache[i].record.dPkts = htonl(flow_cache[i].record.dPkts);

                // Exportuj flow
                sendto(sock, flow_cache + i, (sizeof(NETFLOW_HEADER) + sizeof(NETFLOW_V5_FLOW_FORMAT)), 0, (struct sockaddr *)&server, sizeof(struct sockaddr_in));
                tmp_flow_sequence++;

                // Preindexovanie od aktualneho indexu smerom do lava aby zaplnilo "dieru" ked vyexportovalo flow
                for (int j = i; j < cache_index; j++)
                {
                    flow_cache[j] = flow_cache[j+1];
                }
                cache_index--;

                // Ak zistim po preindexovani, že som už aktualne prešiel všetky flowy a.k.a napríklad aktuálna zdrojová adresa je nulová tak som skončil 
                if (flow_cache[i].record.srcaddr == 0)
                    break;

                i--; // Aby som znova začal na tom indexe po preindexovani, lebo sa posunu smerom do lava
            } 
            // Alebo kontrolujem či už flow pre aktualny packet existuje
            else if   
                (
                    ip_hdr->saddr == flow_cache[i].record.srcaddr &&
                    ip_hdr->daddr == flow_cache[i].record.dstaddr &&
                    tmp_srcport == flow_cache[i].record.srcport &&
                    tmp_dstport == flow_cache[i].record.dstport &&
                    tmp_prot == flow_cache[i].record.prot &&
                    ip_hdr->tos == flow_cache[i].record.tos
                )

                {
                    existing_flow_index = i;
                    is_new_flow = false;
                }

        }

        // Kontrola plnosti flow_cache
        if(cache_index == flow_cache_size && is_new_flow == true)
        {
            u_int32_t tmp_time = 0;

            // Zistenie najstaršieho flowu
            for(int i = 0; i < cache_index; i++)
            {
                if (i == 0)
                {
                    tmp_time = flow_cache[i].record.Last;
                }
                else if(flow_cache[i].record.Last < tmp_time)
                {
                    tmp_time = flow_cache[i].record.Last;
                }
            }

            for(int i = 0; i < cache_index; i++)
            {   
                // Export najstaršieho flowu
                if (tmp_time == flow_cache[i].record.Last)
                {
                    flow_cache[i].header.SysUptime = htonl(tmp_SysUptime);
                    flow_cache[i].header.unix_secs = htonl(current_packet_time_sec);
                    flow_cache[i].header.unix_nsecs = htonl(current_packet_time_nsec);
                    flow_cache[i].header.flow_sequence = htonl(tmp_flow_sequence);
                    flow_cache[i].record.srcport = htons(flow_cache[i].record.srcport);
                    flow_cache[i].record.dstport = htons(flow_cache[i].record.dstport);
                    flow_cache[i].record.First = htonl(flow_cache[i].record.First);
                    flow_cache[i].record.Last = htonl(flow_cache[i].record.Last);
                    flow_cache[i].record.dOctets = htonl(flow_cache[i].record.dOctets);
                    flow_cache[i].record.dPkts = htonl(flow_cache[i].record.dPkts);
                    sendto(sock, flow_cache + i, (sizeof(NETFLOW_HEADER) + sizeof(NETFLOW_V5_FLOW_FORMAT)), 0, (struct sockaddr *)&server, sizeof(struct sockaddr_in));
                    tmp_flow_sequence++;
                    for (int j = i; j < cache_index; j++)
                    {
                        flow_cache[j] = flow_cache[j+1]; // Preindexovanie od aktualneho indexu smerom do lava aby zaplnilo "dieru" ked vyexportovalo flow
                    }
                    cache_index--;
                    break; // Opustenie cyklu, ked som vyexportoval najstarší flow
                }
            }

        }

        // Vytvorenie noveho flowu
        if (is_new_flow == true)
        {
            flow_cache[cache_index].record.srcaddr = ip_hdr->saddr;
            flow_cache[cache_index].record.dstaddr = ip_hdr->daddr;
            flow_cache[cache_index].record.srcport = tmp_srcport;
            flow_cache[cache_index].record.dstport = tmp_dstport;
            flow_cache[cache_index].record.prot = tmp_prot;
            flow_cache[cache_index].record.tcp_flags = tmp_tcp_flags;
            flow_cache[cache_index].record.tos = ip_hdr->tos;
            flow_cache[cache_index].record.dOctets = layer3_bytes;
            flow_cache[cache_index].record.First = tmp_SysUptime;
            flow_cache[cache_index].record.Last = tmp_SysUptime;
            flow_cache[cache_index].record.dPkts = 1;
            flow_cache[cache_index].record.pad1 = 0;
            flow_cache[cache_index].record.pad2 = 0;
            flow_cache[cache_index].record.src_as = 0;
            flow_cache[cache_index].record.dst_as = 0;
            flow_cache[cache_index].record.nexthop = 0;
            flow_cache[cache_index].record.src_mask = 0;
            flow_cache[cache_index].record.dst_mask = 0;
            flow_cache[cache_index].record.input = 0;
            flow_cache[cache_index].record.output = 0;

            flow_cache[cache_index].header.version = htons(5);
            flow_cache[cache_index].header.count = htons(1);
            flow_cache[cache_index].header.SysUptime = tmp_SysUptime;
            flow_cache[cache_index].header.flow_sequence = tmp_flow_sequence;
            flow_cache[cache_index].header.engine_id = 0;
            flow_cache[cache_index].header.engine_type = 0;
            flow_cache[cache_index].header.sampling_interval = 0;
            cache_index++;
        }

        // Update existujuceho flowu 
        else
        {   
            flow_cache[existing_flow_index].record.dOctets += layer3_bytes; // updatnem bytes vo flowe
            flow_cache[existing_flow_index].record.Last = tmp_SysUptime; // updatnem cas posledneho paketu vo flowe
            flow_cache[existing_flow_index].record.dPkts++; // dalši paket vo flowe
            flow_cache[existing_flow_index].record.tcp_flags = flow_cache[existing_flow_index].record.tcp_flags | tmp_tcp_flags; // Cumulative OR of TCP flags
            flow_cache[existing_flow_index].header.SysUptime = tmp_SysUptime; // updatnem SysUptime
            is_new_flow = true;
        }
        packet_counter++;
    }

        
    // Export zvyšnych flowoch vo flow_cache
    for(int i = 0; i < cache_index; i++)
    {
        flow_cache[i].header.SysUptime = htonl(tmp_SysUptime);
        flow_cache[i].header.unix_secs = htonl(current_packet_time_sec);
        flow_cache[i].header.unix_nsecs = htonl(current_packet_time_nsec);
        flow_cache[i].header.flow_sequence = htonl(tmp_flow_sequence);
        flow_cache[i].record.srcport = htons(flow_cache[i].record.srcport);
        flow_cache[i].record.dstport = htons(flow_cache[i].record.dstport);
        flow_cache[i].record.First = htonl(flow_cache[i].record.First);
        flow_cache[i].record.Last = htonl(flow_cache[i].record.Last);
        flow_cache[i].record.dOctets = htonl(flow_cache[i].record.dOctets);
        flow_cache[i].record.dPkts = htonl(flow_cache[i].record.dPkts);
        sendto(sock, flow_cache + i, (sizeof(NETFLOW_HEADER) + sizeof(NETFLOW_V5_FLOW_FORMAT)), 0, (struct sockaddr *)&server, sizeof(struct sockaddr_in));
        tmp_flow_sequence++;
    }

    pcap_close(handle);

    return 0;
}
