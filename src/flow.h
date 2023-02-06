/**
 * @file flow.h
 * @author Michal Uhrecký (xuhrec00)
 * @brief Netflow exportér
 * @date 2022-11-7
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef FLOW_H
#define FLOW_H

/**
 * @brief Štruktúra netflow headeru
 */
typedef struct netflow_header
{
    u_int16_t version; // NetFlow export format version number (ja konkrétne 5)
    u_int16_t count; // Number of flows that are exported in this packet (1-30) (ja exportujem vždy iba 1 flow)
    u_int32_t SysUptime; // Current time in milliseconds since the export device started (čas od prvého paketu)
    u_int32_t unix_secs; // Current count of seconds since 0000 Coordinated Universal Time 1970
    u_int32_t unix_nsecs; // Residual nanoseconds since 0000 Coordinated Universal Time 1970
    u_int32_t flow_sequence; // Sequence counter of total flows seen
    u_int8_t engine_type; // Type of flow-switching engine (0)
    u_int8_t engine_id; // Slot number of the flow-switching engine (0)
    u_int16_t sampling_interval; // First two bits hold the sampling mode; remaining 14 bits hold value of sampling interval (0)
} NETFLOW_HEADER;

/**
 * @brief Štruktúra netflow recordu
 */
typedef struct netflow_v5_flow_format
{
    u_int32_t srcaddr; // Source IP address
    u_int32_t dstaddr; // Destination IP address
    u_int32_t nexthop; // IP address of next hop router (0)
    u_int16_t input; // SNMP index of input interface (0)
    u_int16_t output; // SNMP index of output interface (0)
    u_int32_t dPkts; // Packets in the flow
    u_int32_t dOctets; // Total number of Layer 3 bytes in the packets of the flow 
    u_int32_t First; // SysUptime at start of flow (čas prvého packetu vo flowe)
    u_int32_t Last; // SysUptime at the time the last packet of the flow was received (čas posledného packetu vo flowe)
    u_int16_t srcport; // TCP/UDP source port number or equivalent
    u_int16_t dstport; // TCP/UDP destination port number or equivalent
    u_int8_t pad1; // Unused (zero) byte (0)
    u_int8_t tcp_flags; // Cumulative OR of TCP flags
    u_int8_t prot; // IP protocol type (for example, TCP = 6; UDP = 17)
    u_int8_t tos; // IP type of service (ToS)
    u_int16_t src_as; // Autonomous system number of the source, either origin or peer (0)
    u_int16_t dst_as; // Autonomous system number of the destination, either origin or peer (0)
    u_int8_t src_mask; // Source address prefix mask bits(0)
    u_int8_t dst_mask; // Destination address prefix mask bits (0)
    u_int16_t pad2; // Unused (zero) bytes (0)

} NETFLOW_V5_FLOW_FORMAT;

/**
 * @brief Štruktúra netflow packetu
 */
typedef struct net_flow_packet
{
    NETFLOW_HEADER header;
    NETFLOW_V5_FLOW_FORMAT record;
} NET_FLOW_PACKET;

// Skopirovana struktura z hlavičky tcp.h kvôli preložitelnosti na merlinovi
typedef        u_int32_t tcp_seq;
/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcphdr
  {
    u_int16_t th_sport;                /* source port */
    u_int16_t th_dport;                /* destination port */
    tcp_seq th_seq;                /* sequence number */
    tcp_seq th_ack;                /* acknowledgement number */
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4;                /* (unused) */
    u_int8_t th_off:4;                /* data offset */
#  endif
#  if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t th_off:4;                /* data offset */
    u_int8_t th_x2:4;                /* (unused) */
#  endif
    u_int8_t th_flags;
#  define TH_FIN        0x01
#  define TH_SYN        0x02
#  define TH_RST        0x04
#  define TH_PUSH       0x08
#  define TH_ACK        0x10
#  define TH_URG        0x20
    u_int16_t th_win;                /* window */
    u_int16_t th_sum;                /* checksum */
    u_int16_t th_urp;                /* urgent pointer */
};

// Skopirovana struktura z hlavičky udp.h kvôli preložitelnosti na merlinovi
/* UDP header as specified by RFC 768, August 1980. */
struct udphdr
{
  u_int16_t uh_sport;                /* source port */
  u_int16_t uh_dport;                /* destination port */
  u_int16_t uh_ulen;                /* udp length */
  u_int16_t uh_sum;                /* udp checksum */
};




/**
 * @brief Vypíše help
 */
void print_help();

/**
 * @brief Získa ip/hostname
 * 
 * @param netflow_collector ip/hostname aj s portom
 */
char *parse_host(char *netflow_collector);

/**
 * @brief Získa port
 * 
 * @param netflow_collector ip/hostname aj s portom
 */
char *parse_port(char *netflow_collector);

#endif
