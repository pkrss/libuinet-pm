#include "pm_sock.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/tcp.h>    //Provides declarations for tcp header
#include <netinet/ip.h> //Provides declarations for ip header
#include <netinet/ether.h>
#include <ifaddrs.h>
#include <asm/types.h>
#include <linux/if_ether.h>
//#include <linux/if_arp.h>
#include <arpa/inet.h>  //htons etc
#include <time.h>
#include <linux/rtnetlink.h>

#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define BUF_SIZE 60
#define MAX_CONNECTIONS 10000

#define debug(x...) printf(x);printf("\n");
#define info(x...) printf(x);printf("\n");
#define warn(x...) printf(x);printf("\n");
#define err(x...) printf(x);printf("\n");

static char * str_devname= NULL;
static int mode_loss     = 0;
static int c_packet_sz   = 150;
static int c_packet_nb   = 1000;
static int c_buffer_sz   = 1024*8;
static int c_buffer_nb   = 1024;
static int c_sndbuf_sz   = 0;
static int c_send_mask   = 127;
static int c_error       = 0;
static int c_mtu         = 0;
static int mode_thread   = 0;

volatile int fd_socket[MAX_CONNECTIONS];
volatile int data_offset = 0;
volatile struct tpacket_hdr * ps_header_start;
volatile struct sockaddr_ll *ps_sockaddr = NULL;
volatile int shutdown_flag = 0;
int done = 0;
struct tpacket_req s_packet_req;
unsigned char buffer[BUF_SIZE];
struct arp_header *arp_resp = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
char ifname[512];
char ip[512];

/* 
    96 bit (12 bytes) pseudo header needed for tcp header checksum calculation 
*/
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};


struct arp_header {
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_len;
    unsigned char protocol_len;
    unsigned short opcode;
    unsigned char sender_mac[MAC_LENGTH];
    unsigned char sender_ip[IPV4_LENGTH];
    unsigned char target_mac[MAC_LENGTH];
    unsigned char target_ip[IPV4_LENGTH];
};

int rtnl_receive(int fd, struct msghdr *msg, int flags)
{
    int len;

    do { 
        len = recvmsg(fd, msg, flags);
    } while (len < 0 && (errno == EINTR || errno == EAGAIN));

    if (len < 0) {
        perror("Netlink receive failed");
        return -errno;
    }

    if (len == 0) { 
        perror("EOF on netlink");
        return -ENODATA;
    }

    return len;
}

static int rtnl_recvmsg(int fd, struct msghdr *msg, char **answer)
{
    struct iovec *iov = msg->msg_iov;
    char *buf;
    int len;

    iov->iov_base = NULL;
    iov->iov_len = 0;

    len = rtnl_receive(fd, msg, MSG_PEEK | MSG_TRUNC);

    if (len < 0) {
        return len;
    }

    buf = malloc(len);

    if (!buf) {
        perror("malloc failed");
        return -ENOMEM;
    }

    iov->iov_base = buf;
    iov->iov_len = len;

    len = rtnl_receive(fd, msg, 0);

    if (len < 0) {
        free(buf);
        return len;
    }

    *answer = buf;

    return len;
}

void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));

    while (RTA_OK(rta, len)) {
        if (rta->rta_type <= max) {
            tb[rta->rta_type] = rta;
        }

        rta = RTA_NEXT(rta,len);
    }
}

static inline int rtm_get_table(struct rtmsg *r, struct rtattr **tb)
{
    __u32 table = r->rtm_table;

    if (tb[RTA_TABLE]) {
        table = *(__u32 *)RTA_DATA(tb[RTA_TABLE]);
    }

    return table;
}

void print_route(struct nlmsghdr* nl_header_answer)
{
    struct rtmsg* r = NLMSG_DATA(nl_header_answer);
    int len = nl_header_answer->nlmsg_len;
    struct rtattr* tb[RTA_MAX+1];
    int table;
    char buf[256];

    len -= NLMSG_LENGTH(sizeof(*r));

    if (len < 0) {
        perror("Wrong message length");
        return;
    }
    
    parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);

    table = rtm_get_table(r, tb);

    if (r->rtm_family != AF_INET && table != RT_TABLE_MAIN) {
        return;
    }

    if (tb[RTA_DST]) {
        if ((r->rtm_dst_len != 24) && (r->rtm_dst_len != 16)) {
            return;
        }

        printf("%s/%u ", inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_DST]), buf, sizeof(buf)), r->rtm_dst_len);

    } else if (r->rtm_dst_len) {
        printf("0/%u ", r->rtm_dst_len);
    } else {
        printf("default ");
    }

    if (tb[RTA_GATEWAY]) {
        printf("via %s", inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_GATEWAY]), buf, sizeof(buf)));
        strcpy(ip, inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_GATEWAY]), buf, sizeof(buf)));
    }

    if (tb[RTA_OIF]) {
        char if_nam_buf[IF_NAMESIZE];
        int ifidx = *(__u32 *)RTA_DATA(tb[RTA_OIF]);

        printf(" dev %s", if_indextoname(ifidx, if_nam_buf));
    }

    if (tb[RTA_GATEWAY] && tb[RTA_OIF]) {
        char if_nam_buf[IF_NAMESIZE];
        int ifidx = *(__u32 *)RTA_DATA(tb[RTA_OIF]);

        strcpy(ifname, if_indextoname(ifidx, if_nam_buf));
    }

    if (tb[RTA_SRC]) {
        printf("src %s", inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_SRC]), buf, sizeof(buf)));
    }

    printf("\n");
}

int open_netlink()
{
    struct sockaddr_nl saddr;

    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

    if (sock < 0) {
        perror("Failed to open netlink socket");
        return -1;
    }

    memset(&saddr, 0, sizeof(saddr));

    saddr.nl_family = AF_NETLINK;
    saddr.nl_pid = getpid();

    if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        perror("Failed to bind to netlink socket");
        close(sock);
        return -1;
    }

    return sock;
}

int do_route_dump_requst(int sock)
{
    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
    } nl_request;

    nl_request.nlh.nlmsg_type = RTM_GETROUTE;
    nl_request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nl_request.nlh.nlmsg_len = sizeof(nl_request);
    nl_request.nlh.nlmsg_seq = time(NULL);
    nl_request.rtm.rtm_family = AF_INET;

    return send(sock, &nl_request, sizeof(nl_request), 0);
}

int get_route_dump_response(int sock)
{
    struct sockaddr_nl nladdr;
    struct iovec iov;
    struct msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    char *buf;
    int dump_intr = 0;

    int status = rtnl_recvmsg(sock, &msg, &buf);

    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    int msglen = status;

    printf("Main routing table IPv4\n");

    while (NLMSG_OK(h, msglen)) {
        if (h->nlmsg_flags & NLM_F_DUMP_INTR) {
            fprintf(stderr, "Dump was interrupted\n");
            free(buf);
            return -1;
        }

        if (nladdr.nl_pid != 0) {
            continue;
        }

        if (h->nlmsg_type == NLMSG_ERROR) {
            perror("netlink reported error");
            free(buf);
        }

        print_route(h);

        h = NLMSG_NEXT(h, msglen);
    }

    free(buf);

    return status;
}


/*
 * Converts struct sockaddr with an IPv4 address to network byte order uin32_t.
 * Returns 0 on success.
 */
int int_ip4(struct sockaddr *addr, uint32_t *ip)
{
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *i = (struct sockaddr_in *) addr;
        *ip = i->sin_addr.s_addr;
        return 0;
    } else {
        err("Not AF_INET");
        return 1;
    }
}

/*
 * Formats sockaddr containing IPv4 address as human readable string.
 * Returns 0 on success.
 */
int format_ip4(struct sockaddr *addr, char *out)
{
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *i = (struct sockaddr_in *) addr;
        const char *ip = inet_ntoa(i->sin_addr);
        if (!ip) {
            return -2;
        } else {
            strcpy(out, ip);
            return 0;
        }
    } else {
        return -1;
    }
}

/*
 * Writes interface IPv4 address as network byte order to ip.
 * Returns 0 on success.
 */
int get_if_ip4(int fd, const char *ifname, uint32_t *ip) {
    int err = -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    if (strlen(ifname) > (IFNAMSIZ - 1)) {
        err("Too long interface name");
        goto out;
    }

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("SIOCGIFADDR");
        goto out;
    }

    if (int_ip4(&ifr.ifr_addr, ip)) {
        goto out;
    }
    err = 0;
out:
    return err;
}

/*
 * Sends an ARP who-has request to dst_ip
 * on interface ifindex, using source mac src_mac and source ip src_ip.
 */
int send_arp(int fd, int ifindex, const unsigned char *src_mac, uint32_t src_ip, uint32_t dst_ip)
{
    int err = -1;
    unsigned char buffer[BUF_SIZE];
    memset(buffer, 0, sizeof(buffer));

    struct sockaddr_ll socket_address;
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_hatype = htons(ARPHRD_ETHER);
    socket_address.sll_pkttype = (PACKET_BROADCAST);
    socket_address.sll_halen = MAC_LENGTH;
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;

    struct ethhdr *send_req = (struct ethhdr *) buffer;
    struct arp_header *arp_req = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
    int index;
    ssize_t ret, length = 0;

    //Broadcast
    memset(send_req->h_dest, 0xff, MAC_LENGTH);

    //Target MAC zero
    memset(arp_req->target_mac, 0x00, MAC_LENGTH);

    //Set source mac to our MAC address
    memcpy(send_req->h_source, src_mac, MAC_LENGTH);
    memcpy(arp_req->sender_mac, src_mac, MAC_LENGTH);
    memcpy(socket_address.sll_addr, src_mac, MAC_LENGTH);

    /* Setting protocol of the packet */
    send_req->h_proto = htons(ETH_P_ARP);

    /* Creating ARP request */
    arp_req->hardware_type = htons(HW_TYPE);
    arp_req->protocol_type = htons(ETH_P_IP);
    arp_req->hardware_len = MAC_LENGTH;
    arp_req->protocol_len = IPV4_LENGTH;
    arp_req->opcode = htons(ARP_REQUEST);

    debug("Copy IP address to arp_req");
    memcpy(arp_req->sender_ip, &src_ip, sizeof(uint32_t));
    memcpy(arp_req->target_ip, &dst_ip, sizeof(uint32_t));

    ret = sendto(fd, buffer, 42, 0, (struct sockaddr *) &socket_address, sizeof(socket_address));
    if (ret == -1) {
        perror("sendto():");
        goto out;
    }
    err = 0;
out:
    return err;
}

/*
 * Gets interface information by name:
 * IPv4
 * MAC
 * ifindex
 */
int get_if_info(const char *ifname, uint32_t *ip, char *mac, int *ifindex)
{
    debug("get_if_info for %s", ifname);
    int err = -1;
    struct ifreq ifr;
    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sd <= 0) {
        perror("socket()");
        goto out;
    }
    if (strlen(ifname) > (IFNAMSIZ - 1)) {
        printf("Too long interface name, MAX=%i\n", IFNAMSIZ - 1);
        goto out;
    }

    strcpy(ifr.ifr_name, ifname);

    //Get interface index using name
    if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        goto out;
    }
    *ifindex = ifr.ifr_ifindex;
    printf("interface index is %d\n", *ifindex);

    //Get MAC address of the interface
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        goto out;
    }

    //Copy mac address to output
    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);

    if (get_if_ip4(sd, ifname, ip)) {
        goto out;
    }
    debug("get_if_info OK");

    err = 0;
out:
    if (sd > 0) {
        debug("Clean up temporary socket");
        close(sd);
    }
    return err;
}

/*
 * Creates a raw socket that listens for ARP traffic on specific ifindex.
 * Writes out the socket's FD.
 * Return 0 on success.
 */
int bind_arp(int ifindex, int *fd)
{
    debug("bind_arp: ifindex=%i", ifindex);
    int ret = -1;

    // Submit request for a raw socket descriptor.
    *fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (*fd < 1) {
        perror("socket()");
        goto out;
    }

    debug("Binding to ifindex %i", ifindex);
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    if (bind(*fd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0) {
        perror("bind");
        goto out;
    }

    ret = 0;
out:
    if (ret && *fd > 0) {
        debug("Cleanup socket");
        close(*fd);
    }
    return ret;
}

/*
 * Reads a single ARP reply from fd.
 * Return 0 on success.
 */
int read_arp(int fd)
{
    debug("read_arp");
    int ret = -1;
    ssize_t length = recvfrom(fd, buffer, BUF_SIZE, 0, NULL, NULL);
    int index;
    if (length == -1) {
        perror("recvfrom()");
        goto out;
    }
    struct ethhdr *rcv_resp = (struct ethhdr *) buffer;
    if (ntohs(rcv_resp->h_proto) != PROTO_ARP) {
        debug("Not an ARP packet");
        goto out;
    }
    if (ntohs(arp_resp->opcode) != ARP_REPLY) {
        debug("Not an ARP reply");
        goto out;
    }
    debug("received ARP len=%ld", length);
    struct in_addr sender_a;
    memset(&sender_a, 0, sizeof(struct in_addr));
    memcpy(&sender_a.s_addr, arp_resp->sender_ip, sizeof(uint32_t));
    debug("Sender IP: %s", inet_ntoa(sender_a));

    debug("Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X",
          arp_resp->sender_mac[0],
          arp_resp->sender_mac[1],
          arp_resp->sender_mac[2],
          arp_resp->sender_mac[3],
          arp_resp->sender_mac[4],
          arp_resp->sender_mac[5]);

    ret = 0;

out:
    return ret;
}

/*
 *
 * Sample code that sends an ARP who-has request on
 * interface <ifname> to IPv4 address <ip>.
 * Returns 0 on success.
 */
int test_arping(const char *ifname, const char *ip) {
    int ret = -1;
    uint32_t dst = inet_addr(ip);
    if (dst == 0 || dst == 0xffffffff) {
        printf("Invalid source IP\n");
        return 1;
    }

    int src;
    int ifindex;
    char mac[MAC_LENGTH];
    if (get_if_info(ifname, &src, mac, &ifindex)) {
        err("get_if_info failed, interface %s not found or no IP set?", ifname);
        goto out;
    }
    int arp_fd;
    if (bind_arp(ifindex, &arp_fd)) {
        err("Failed to bind_arp()");
        goto out;
    }

    if (send_arp(arp_fd, ifindex, mac, src, dst)) {
        err("Failed to send_arp");
        goto out;
    }

    while(1) {
        int r = read_arp(arp_fd);
        if (r == 0) {
            info("Got reply, break out");
            break;
        }
    }

    ret = 0;
out:
    if (arp_fd) {
        close(arp_fd);
        arp_fd = 0;
    }
    return ret;
}

/*
    Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
    
    return(answer);
}


int main( int argc, char ** argv )
{
    uint32_t size;
    struct sockaddr_ll my_addr[MAX_CONNECTIONS], peer_addr;
    int i_ifindex;
    int ec;
    struct ifreq s_ifr; /* points to one interface returned from ioctl */
    int tmp;
    FILE * fp;
    char server[254];
    int count = 0;
    int first_time = 1;
    int z;
    int first_mmap = 1;
    
    #define HWADDR_len 6
    #define IP_len 4
    int s,s2,i;
    struct ifreq ifr,ifr2;
    int ret = -1;
    // struct if_nameindex * ifni = if_nameindex();
    const char* target_ip = argc >= 2 ? argv[1] : "192.168.2.100";
    // if (argc != 2) {
    //     printf("Usage: %s <INPUT_FILE>\n", argv[0]);
    //     return 1;
    // }
//  const char *ifname = argv[2];
//  const char *ip = argv[3];
    int nl_sock = open_netlink();

    if (do_route_dump_requst(nl_sock) < 0) {
        perror("Failed to perfom request");
        close(nl_sock);
        return -1;
    }

    get_route_dump_response(nl_sock);

    close (nl_sock);
    
    test_arping(ifname, ip);

    
    s = socket(AF_INET, SOCK_DGRAM, 0);
    s2 = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, ifname);
    strcpy(ifr2.ifr_name, ifname);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    ioctl(s2, SIOCGIFADDR, &ifr2);
    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr2.ifr_addr;
    close(s);

    while (!done)
    {
        if (first_time)
        {
            if (count < MAX_CONNECTIONS) z = count;
        }

        count++;
        if (count == 10000) break;
    
        fp = fopen(target_ip, "r"); // argv[1]
        if (!fp)
            exit(EXIT_FAILURE);

        fd_socket[z] = socket(PF_PACKET, SOCK_RAW|SOCK_NONBLOCK, htons(ETH_P_ALL));
        if(fd_socket[z] == -1)
        {
            perror("socket");
            return EXIT_FAILURE;
        }
    
        /* clear structure */
        memset(&my_addr[z], 0, sizeof(struct sockaddr_ll));
        my_addr[z].sll_family = PF_PACKET;
        my_addr[z].sll_protocol = htons(ETH_P_ALL);
    
        str_devname = ifname;
        //strcpy (str_devname, ifname);
        
        /* initialize interface struct */
        strncpy (s_ifr.ifr_name, str_devname, sizeof(s_ifr.ifr_name));
    
        /* Get the broad cast address */
        ec = ioctl(fd_socket[z], SIOCGIFINDEX, &s_ifr);
        if(ec == -1)
        {
            perror("iotcl");
            return EXIT_FAILURE;
        }
    
        /* update with interface index */
        i_ifindex = s_ifr.ifr_ifindex;
    
        s_ifr.ifr_mtu = 7200;
        /* update the mtu through ioctl */
        ec = ioctl(fd_socket[z], SIOCSIFMTU, &s_ifr);
        if(ec == -1)
        {
            perror("iotcl");
            return EXIT_FAILURE;
        }
    
        /* set sockaddr info */
        memset(&my_addr[z], 0, sizeof(struct sockaddr_ll));
        my_addr[z].sll_family = AF_PACKET;
        my_addr[z].sll_protocol = ETH_P_ALL;
        my_addr[z].sll_ifindex = i_ifindex;
    
        /* bind port */
        if (bind(fd_socket[z], (struct sockaddr *)&my_addr[z], sizeof(struct sockaddr_ll)) == -1)
        {
            perror("bind");
            return EXIT_FAILURE;
        }
    
        /* prepare Tx ring request */
        s_packet_req.tp_block_size = c_buffer_sz;
        s_packet_req.tp_frame_size = c_buffer_sz;
        s_packet_req.tp_block_nr = c_buffer_nb;
        s_packet_req.tp_frame_nr = c_buffer_nb;
    
        /* calculate memory to mmap in the kernel */
        size = s_packet_req.tp_block_size * s_packet_req.tp_block_nr;
    
        /* set packet loss option */
        tmp = mode_loss;
        if (setsockopt(fd_socket[z], SOL_PACKET, PACKET_LOSS, (char *)&tmp, sizeof(tmp))<0)
        {
            perror("setsockopt: PACKET_LOSS");
            return EXIT_FAILURE;
        }
 
        /* send TX ring request */
        if (setsockopt(fd_socket[z], SOL_PACKET, PACKET_TX_RING, (char *)&s_packet_req, sizeof(s_packet_req))<0)
        {
            perror("setsockopt: PACKET_TX_RING");
            return EXIT_FAILURE;
        }
    
        /* change send buffer size */
        if(c_sndbuf_sz) {
            printf("send buff size = %d\n", c_sndbuf_sz);
            if (setsockopt(fd_socket[z], SOL_SOCKET, SO_SNDBUF, &c_sndbuf_sz, sizeof(c_sndbuf_sz))< 0)
            {
                perror("getsockopt: SO_SNDBUF");
                return EXIT_FAILURE;
            }
        }
    
        /* get data offset */
        data_offset = TPACKET_HDRLEN - sizeof(struct sockaddr_ll);
    
        /* mmap Tx ring buffers memory */
        ps_header_start = mmap(0, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd_socket[z], 0);
        if (ps_header_start == (void*)-1)
        {
            perror("mmap");
            return EXIT_FAILURE;
        }
    
    
        int i,j;
        int i_index = 0;
        char * data;
        int first_loop = 1;
        struct tpacket_hdr * ps_header;
        int ec_send = 0;
 
        for(i=1; i <= c_packet_nb; i++)
        {
            int i_index_start = i_index;
            int loop = 1;
 
            /* get free buffer */
            do {
                ps_header = ((struct tpacket_hdr *)((void *)ps_header_start + (c_buffer_sz*i_index)));
                data = ((void*) ps_header) + data_offset;
                switch((volatile uint32_t)ps_header->tp_status)
                {
                    case TP_STATUS_AVAILABLE:
                        /* fill data in buffer */
                        if(first_loop) {
                            //Datagram to represent the packet
                            char datagram[4096] , source_ip[32] , *data2, *pseudogram;
    
                            //zero out the packet buffer
                            memset (datagram, 0, 4096);
    
                            //Ethernet header
                            struct ether_header *eh = (struct ether_header *) datagram;
        
                            //IP header
                            struct iphdr *iph = (struct iphdr *) (datagram + sizeof (struct ether_header));
    
                            //TCP header
                            struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ether_header) + sizeof (struct ip));
                            struct sockaddr_in sin;
                            struct pseudo_header psh;
    
                            //Data part
                            data2 = datagram + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr);
                            strcpy(data2 , "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    
                            //some address resolution
                            strcpy(source_ip , inet_ntoa(ipaddr->sin_addr));
                            sin.sin_family = AF_INET;
                            sin.sin_port = htons(80);
                            if (fscanf(fp, "%253s", server) == 1)
                                sin.sin_addr.s_addr = inet_addr (server);   
                            else
                            {
                                done = 1;
                                break;
                            }
                        
                            //Fill in the Ethernet Header
                            //eh->ether_dhost[0] = 0x70;
                            //eh->ether_dhost[1] = 0x97;
                            //eh->ether_dhost[2] = 0x41;
                            //eh->ether_dhost[3] = 0x4b;
                            //eh->ether_dhost[4] = 0x1e;
                            //eh->ether_dhost[5] = 0xc2;
                            eh->ether_dhost[0] = arp_resp->sender_mac[0];
                            eh->ether_dhost[1] = arp_resp->sender_mac[1];
                            eh->ether_dhost[2] = arp_resp->sender_mac[2];
                            eh->ether_dhost[3] = arp_resp->sender_mac[3];
                            eh->ether_dhost[4] = arp_resp->sender_mac[4];
                            eh->ether_dhost[5] = arp_resp->sender_mac[5];

                            memcpy(eh->ether_shost, ifr.ifr_hwaddr.sa_data, HWADDR_len);
                            eh->ether_type = 0x0008;
    
                            //Fill in the IP Header
                            iph->ihl = 5;
                            iph->version = 4;
                            iph->tos = 0;
                            iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
                            iph->id = htonl (54321);    //Id of this packet
                            iph->frag_off = 0;
                            iph->ttl = 255;
                            iph->protocol = IPPROTO_TCP;
                            iph->check = 0;     //Set to 0 before calculating checksum
                            iph->saddr = inet_addr ( source_ip );   //Spoof the source ip address
                            iph->daddr = sin.sin_addr.s_addr;
    
                            //Ip checksum
                            iph->check = csum ((unsigned short *) datagram, iph->tot_len);
    
                            //TCP Header
                            tcph->source = htons (1234);
                            tcph->dest = htons (80);
                            tcph->seq = 0;
                            tcph->ack_seq = 0;
                            tcph->doff = 5; //tcp header size
                            tcph->fin=0;
                            tcph->syn=1;
                            tcph->rst=0;
                            tcph->psh=0;
                            tcph->ack=0;
                            tcph->urg=0;
                            tcph->window = htons (5840);    // maximum allowed window size 
                            tcph->check = 0;    //leave checksum 0 now, filled later by pseudo header
                            tcph->urg_ptr = 0;

                            //Now the TCP checksum
                            psh.source_address = inet_addr( source_ip );
                            psh.dest_address = sin.sin_addr.s_addr;
                            psh.placeholder = 0;
                            psh.protocol = IPPROTO_TCP;
                            psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data) );
    
                            int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
                            pseudogram = malloc(psize);
        
                            memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
                            memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + strlen(data));
    
                            tcph->check = csum( (unsigned short*) pseudogram , psize);
                        
                            memcpy(data, datagram, 4096);
                            free(pseudogram);
//                      for(j=0;j<c_packet_sz;j++)
//                          data[j] = j;
                        }
                        loop = 0;
                    break;
 
                    case TP_STATUS_WRONG_FORMAT:
                        printf("An error has occured during transfer\n");
                        exit(EXIT_FAILURE);
                    break;
 
                    default:
                        /* nothing to do => schedule : useful if no SMP */
                        usleep(0);
                        break;
                }
            }
            while(loop == 1);
 
            i_index ++;
            if(i_index >= c_buffer_nb)
            {
                i_index = 0;
                first_loop = 0;
            }
 
            /* update packet len */
            ps_header->tp_len = c_packet_sz;
            /* set header flag to USER (trigs xmit)*/
            ps_header->tp_status = TP_STATUS_SEND_REQUEST;
 
            /* if smp mode selected */
            if(!mode_thread)
            {
                /* send all packets */
                if( ((i&c_send_mask)==0) || (ec_send < 0) || (i == c_packet_nb) )
                {
                    /* send all buffers with TP_STATUS_SEND_REQUEST */
                    /* Don't wait end of transfer */
                    //ec_send = (int) task_send((void*)0);
                }
            }
            else if(c_error) {
 
                if(i == (c_packet_nb/2))
                {
                    int ec_close;
                
                    if(c_error == 1) {
                        ec_close = close(fd_socket[z]);
                    }
                    if(c_error == 2) {
                        if (setsockopt(fd_socket[z], SOL_PACKET, PACKET_TX_RING, (char *)&s_packet_req, sizeof(s_packet_req))<0)
                        {
                            perror("setsockopt: PACKET_TX_RING");
                            //return EXIT_FAILURE;
                        }
                    }
                    break;
                }
            }
        }
    
        //int ec_send;
        static int total=0;
        int blocking = 1;
        
        /* send all buffers with TP_STATUS_SEND_REQUEST */
        /* Wait end of transfer */
        ec_send = sendto(fd_socket[z],NULL,0,(blocking? 0 : MSG_DONTWAIT),(struct sockaddr *) ps_sockaddr,sizeof(struct sockaddr_ll));
        
        if(ec_send < 0) {
            perror("sendto");
        }
        else if ( ec_send == 0 ) {
            /* nothing to do => schedule : useful if no SMP */
            usleep(0);
        }
        else {
            total += ec_send/(c_packet_sz);
            printf("send %d packets (+%d bytes)\n",total, ec_send);
            fflush(0);
        }
        //ps_header_start = mmap(0, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd_socket[z], 0);
        if (munmap(ps_header_start, size) == -1)
        {
            perror("munmap");
            exit(EXIT_FAILURE);
        }       
    
        close(fd_socket[z]);
 
    }
    return 1;
}