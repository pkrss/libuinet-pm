
#include "pm_sock.h"

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <net/if.h> // if_nameindex()
#include <errno.h>
#include <assert.h>
#include "../libuinet/api_include/uinet_api.h"
#include <netdb.h> // NI_MAXHOST
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/socket.h>

/*
gcc -fdiagnostics-color=always -g pm_sock.c -o pm_sock.o -L../libuinet/ -llibuinet.a -lssl -lcrypto
*/
struct pm_instance {
    struct pm_params params;
    uinet_instance_t uinst;
    struct {
        int i_ifindex;
        struct pm_sockaddr_in local_adr;
        struct pm_sockaddr_in6 local_adr6;
        struct pm_sockaddr_in gw_adr;
        struct pm_sockaddr_in6 gw_adr6;
    } opt;
};

struct pm_socket {
    struct pm_instance* inst;
    struct uinet_socket* aso;
    int fd;
    
    unsigned int tp_rblock_num;
    unsigned int tp_wblock_num;
    struct iovec* tp_rd;
    struct iovec* tp_wd;
    uint8_t* tp_map;
    size_t tp_map_size;
};

void pm_log_printf_none(const char *fmt, ...){
    (void)fmt;
}

int pm_init(struct pm_instance** out, struct pm_params* p) {
    int found, family; // res
    struct if_nameindex* ifni;
    struct ifaddrs *ifaddr, *ifa;
    struct pm_instance* inst;
    // char host[NI_MAXHOST];

    inst = (struct pm_instance*)((p && p->mm_alloc ? p->mm_alloc : malloc)(sizeof(struct pm_instance)));
    memset(inst, 0, sizeof(struct pm_instance));

    if(p)
        inst->params = *p;
    p = &inst->params;

    if(!p->log_printf)
        p->log_printf = pm_log_printf_none;

    ifni = if_nameindex();
    // check netdev
    if(!p->netdev || !p->netdev[0]){
        while(ifni && ifni->if_name){
            if(ifni->if_name[0] == 'e') { // eth0 or ens5
                p->netdev = ifni->if_name;
                inst->opt.i_ifindex = if_nametoindex(ifni->if_name);
                p->log_printf("found netdev:%s\n", ifni->if_name);
                break;
            }
            ifni++;
        }
    }else{
        found = 0;
        while(ifni && ifni->if_name){
            if(0 == strcmp(p->netdev, ifni->if_name)) {
                found = 1;
                break;
            }
            ifni++;
        }
        if(!found){
            p->log_printf("unfound netdev in local interfaces:%s, exiting\n", p->netdev);
            goto failed;
        }
        inst->opt.i_ifindex = if_nametoindex(ifni->if_name);
        p->netdev = ifni->if_name;
    }

    if(p->local_adr)
        memcpy(&inst->opt.local_adr, p->local_adr, sizeof(struct pm_sockaddr_in));
    if(p->local_adr6)
        memcpy(&inst->opt.local_adr6, p->local_adr6, sizeof(struct pm_sockaddr_in6));
    if(p->gw_adr)
        memcpy(&inst->opt.gw_adr, p->gw_adr, sizeof(struct pm_sockaddr_in));
    if(p->gw_adr6)
        memcpy(&inst->opt.gw_adr6, p->gw_adr6, sizeof(struct pm_sockaddr_in6));

    // $ ip addr show  @see: https://www.man7.org/linux/man-pages/man3/getifaddrs.3.html
    if (getifaddrs(&ifaddr) == -1)
        goto failed;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if ((ifa->ifa_addr == NULL) || !(ifa->ifa_flags & IFF_RUNNING)) //  || !(ifa->ifa_flags & IFF_MULTICAST)
            continue;
        if(strcmp(p->netdev, ifa->ifa_name))
            continue;
        family = ifa->ifa_addr->sa_family;

        if ((family != AF_INET) && (family != AF_INET6))
            continue;

        // if ((res = getnameinfo(ifa->ifa_addr, family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST)) != 0) {
        //     p->log_printf("getnameinfo() failed: %s\n", gai_strerror(res));
        //     continue;
        // }
        // p->log_printf("getnameinfo() result: family:%d %s ifa_flags:0x%x \n", family, host, ifa->ifa_flags);     
        // IFF_POINTOPOINT
        // getnameinfo() result: family:2 172.30.36.220 ifa_flags:0x11043 
        // getnameinfo() result: family:10 fe80::215:5dff:fe0d:f0ab%eth0 ifa_flags:0x11043
        if(!p->local_adr && (family == AF_INET)){
            memcpy(&inst->opt.local_adr.sin_family, ifa->ifa_addr, sizeof(struct sockaddr_in));
            inst->opt.local_adr.sin_len = sizeof(struct pm_sockaddr_in);
            p->local_adr = &inst->opt.local_adr;
        }
        if(!p->local_adr6 && (family == AF_INET6)){
            memcpy(&inst->opt.local_adr6.sin6_family, ifa->ifa_addr, sizeof(struct sockaddr_in6));
            inst->opt.local_adr.sin_len = sizeof(struct pm_sockaddr_in6);
            p->local_adr6 = &inst->opt.local_adr6;
        }
        if(!p->gw_adr && (IFF_POINTOPOINT & ifa->ifa_flags) && (family == AF_INET)){
            memcpy(&inst->opt.gw_adr.sin_family, ifa->ifa_ifu.ifu_dstaddr, sizeof(struct sockaddr_in));
            inst->opt.local_adr.sin_len = sizeof(struct pm_sockaddr_in);
            p->gw_adr = &inst->opt.gw_adr;
        }
        if(!p->gw_adr6 && (IFF_POINTOPOINT & ifa->ifa_flags) && (family == AF_INET6)){
            memcpy(&inst->opt.gw_adr6.sin6_family, ifa->ifa_ifu.ifu_dstaddr, sizeof(struct sockaddr_in6));
            inst->opt.local_adr.sin_len = sizeof(struct pm_sockaddr_in6);
            p->gw_adr6 = &inst->opt.gw_adr6;
        }

        // if(bind_ip.empty() && (family == AF_INET) && ifa->ifa_flags){
        //     if ((res = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST)) != 0) {
        //         p->log_printf("getnameinfo() failed: %s\n", gai_strerror(res));
        //         continue;
        //     }
        //     bind_ip = host;
        // } else if(bind_ip6.empty() && (family == AF_INET6)){
        //     if ((res = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST)) != 0) {
        //         p->log_printf("getnameinfo() failed: %s\n", gai_strerror(res));
        //         continue;
        //     }
        //     bind_ip6 = host;
        // } 
        // if(gw_ip.empty() && (IFF_POINTOPOINT & ifa->ifa_flags) && (family == AF_INET)){
        //     if ((res = getnameinfo(ifa->ifa_ifu.ifu_dstaddr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST)) != 0) {
        //         p->log_printf("getnameinfo() failed: %s\n", gai_strerror(res));
        //         continue;
        //     }
        //     gw_ip = host;
        // } else if(gw_ip6.empty() && (IFF_POINTOPOINT & ifa->ifa_flags) && (family == AF_INET6)){
        //     if ((res = getnameinfo(ifa->ifa_ifu.ifu_dstaddr, sizeof(struct sockaddr_in6), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST)) != 0) {
        //         p->log_printf("getnameinfo() failed: %s\n", gai_strerror(res));
        //         continue;
        //     }
        //     gw_ip6 = host;
        // }
    }
    freeifaddrs(ifaddr);

    if(!p->local_port)
        p->local_port = 984;
        
    struct uinet_global_cfg cfg;
	uinet_default_cfg(&cfg, UINET_GLOBAL_CFG_MEDIUM);
	uinet_init(&cfg, NULL);
    inst->uinst = uinet_instance_create(NULL);

    if(!p->mm_alloc) // call p->mm_alloc() easy
        p->mm_alloc = malloc;
    if(!p->mm_free)
        p->mm_free = free;

    if(!p->mtu)
        p->mtu = 1500;

    if(!p->tp_block_size)
        p->tp_block_size = 40960;
    if(!p->tp_frame_size)
        p->tp_frame_size = (p->mtu / 1024 + 1) * 1024; // 2048        
    if(!p->tp_r_block_num)
        p->tp_r_block_num = 2;  
    if(!p->tp_w_block_num)
        p->tp_w_block_num = 1;

    *out = inst;
    return 0;
failed:
    pm_destroy(inst);
    return -1;
}

void pm_destroy(struct pm_instance* v){
    (v->params.mm_free ? v->params.mm_free : free)(v);
}

int pm_socreate(struct pm_instance* inst, struct pm_socket** out, int family, int type, int proto){
    int res;
    unsigned int i;
    struct sockaddr_ll my_addr;
    struct ifreq s_ifr;    
    struct tpacket_req3 req;
    struct pm_socket* sck = (struct pm_socket*)inst->params.mm_alloc(sizeof(struct pm_socket));
    memset(sck, 0, sizeof(struct pm_socket));
    sck->inst = inst;
    // switch(family){
    // case PF_INET:
    //     family = UINET_PF_INET;
    //     break;
    // case PF_INET6:
    //     family = UINET_PF_INET6;
    //     break;
    // }
    // switch(type){
    // case SOCK_STREAM:
    //     type = UINET_SOCK_STREAM;
    //     break;
    // case SOCK_DGRAM:
    //     type = UINET_SOCK_DGRAM;
    //     break;
    // }
    if((res = uinet_socreate(inst->uinst, family, &sck->aso, type, proto)) != 0)
        goto failed;
    if((sck->fd = socket(AF_PACKET, SOCK_RAW|SOCK_NONBLOCK, htons(ETH_P_ALL))) == -1)
        goto failed;

    res = TPACKET_V3;
    if(inst->params.tpacket_version == 1)
        res = TPACKET_V1;
    else if(inst->params.tpacket_version == 2)
        res = TPACKET_V2;
    if (setsockopt(sck->fd, SOL_PACKET, PACKET_VERSION, &res, sizeof(res)) < 0)
        goto failed;

    // res = (1<<6); // SOF_TIMESTAMPING_RAW_HARDWARE = (1<<6), TP_STATUS_TS_RAW_HARDWARE|TP_STATUS_TS_SOFTWARE;
    // if(setsockopt(sck->fd, SOL_PACKET, PACKET_TIMESTAMP, (void *)&res, sizeof(v)) < 0)
    //     goto failed;
    
    memset(&s_ifr, 0, sizeof(struct ifreq));
    // initialize interface struct
    strcpy(s_ifr.ifr_name, inst->params.netdev);
    s_ifr.ifr_ifindex = inst->opt.i_ifindex;

    // Get the broad cast address
    if((res = ioctl(sck->fd, SIOCGIFINDEX, &s_ifr)) == -1)
        goto failed;

    s_ifr.ifr_mtu = inst->params.mtu;
    // update the mtu through ioctl
    if((res = ioctl(sck->fd, SIOCSIFMTU, &s_ifr)) == -1)
        goto failed;

    // set sockaddr info
    memset(&my_addr, 0, sizeof(struct sockaddr_ll));
    my_addr.sll_family = AF_PACKET;
    my_addr.sll_protocol = ETH_P_ALL;
    my_addr.sll_ifindex = inst->opt.i_ifindex; // update with interface index

    // bind port
    if (bind(sck->fd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr_ll)) == -1)
        goto failed;

    // prepare Tx / Rx ring request
    memset(&req, 0, sizeof(struct tpacket_req3));
    req.tp_block_size = inst->params.tp_block_size;
    req.tp_frame_size = inst->params.tp_frame_size;
    req.tp_block_nr = inst->params.tp_r_block_num;
    req.tp_frame_nr = (inst->params.tp_block_size * inst->params.tp_r_block_num) / inst->params.tp_frame_size;
    assert((inst->params.tp_block_size * inst->params.tp_r_block_num) % inst->params.tp_frame_size == 0);
    req.tp_retire_blk_tov = 60;
    req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;
    if (setsockopt(sck->fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(struct tpacket_req3)) < 0)
        goto failed;

    req.tp_block_nr = inst->params.tp_w_block_num;
    req.tp_frame_nr = (inst->params.tp_block_size * inst->params.tp_w_block_num) / inst->params.tp_frame_size;
    assert((inst->params.tp_block_size * inst->params.tp_w_block_num) % inst->params.tp_frame_size == 0);
    req.tp_retire_blk_tov = 0;
    req.tp_feature_req_word = 0;
    if (setsockopt(sck->fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(struct tpacket_req3)) < 0)
        goto failed;

    // set packet loss option
    if((inst->params.tpacket_version == 1) || (inst->params.tpacket_version == 2)){
        res = 0;
        if (setsockopt(sck->fd, SOL_PACKET, PACKET_LOSS, (char *)&res, sizeof(res))<0)
            goto failed;
    }

    // change send buffer size
    // res = inst->params.tp_block_size * inst->params.tp_r_block_num;
    // if (setsockopt(sck->fd, SOL_SOCKET, SO_SNDBUF, (char *)&res, sizeof(res))<0)
    //     goto failed;

    // mmap memory in the kernel, send buffers after recv buffers
    sck->tp_map_size = inst->params.tp_block_size * (inst->params.tp_r_block_num + inst->params.tp_w_block_num);
    if ((sck->tp_map = (uint8_t*)mmap(NULL, sck->tp_map_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, sck->fd, 0)) == MAP_FAILED) 
        goto failed;
    sck->tp_rd = (struct iovec*)inst->params.mm_alloc(inst->params.tp_r_block_num * sizeof(struct iovec));
    for (i = 0; i < inst->params.tp_r_block_num; ++i) {
        sck->tp_rd[i].iov_base = sck->tp_map + (i * inst->params.tp_block_size);
        sck->tp_rd[i].iov_len = inst->params.tp_block_size;
    }
    sck->tp_wd = (struct iovec*)inst->params.mm_alloc(inst->params.tp_w_block_num * sizeof(struct iovec));
    for (i = 0; i < inst->params.tp_w_block_num; ++i) {
        sck->tp_wd[i].iov_base = sck->tp_map + ((i + inst->params.tp_r_block_num) * req.tp_block_size);
        sck->tp_wd[i].iov_len = inst->params.tp_block_size;
    }

    *out = sck;
    return 0;
failed:
    res = errno;
    if(!res)
        res = -1;
    if(inst->params.log_printf)
	    inst->params.log_printf("pm_socreate failed, %d %s", res, strerror(res));
    pm_close(sck);
    return res;
}

int pm_close(struct pm_socket *sck) {
    int res = 0;
    if(sck->aso)
        res = uinet_soclose(sck->aso);
    if(sck->fd)
        close(sck->fd);
    if(sck->tp_wd)
        sck->inst->params.mm_free(sck->tp_wd);
    if(sck->tp_rd)
        sck->inst->params.mm_free(sck->tp_rd);
    if(sck->tp_map)
        munmap(sck->tp_map, sck->tp_map_size);
    sck->inst->params.mm_free(sck);
    return res;
}

int pm_connect(struct pm_socket *sck, struct pm_sockaddr *adr){
    return uinet_pm_connect(sck->inst, sck->aso, adr);
}

int uinet_pm_connect(struct pm_instance* inst, struct uinet_socket *aso, struct pm_sockaddr *adr){
    int res;

    do{
        if((res=uinet_so_set_pm_info(aso, adr->sa_family == AF_INET ? (struct uinet_sockaddr*)&inst->opt.local_adr : (struct uinet_sockaddr*)&inst->opt.local_adr6, 
            htons(inst->params.local_port),
            adr->sa_family == AF_INET ? (struct uinet_sockaddr*)&inst->opt.gw_adr : (struct uinet_sockaddr*)&inst->opt.gw_adr6, inst->params.mtu)))
            break;
        adr->sa_len = (adr->sa_family == AF_INET ? sizeof(struct pm_sockaddr_in) : sizeof(struct pm_sockaddr_in6));
        res = uinet_soconnect(aso, (struct uinet_sockaddr*)adr);
    } while(0);

    return res;
}

struct uinet_instance* uinst_instance_get(struct pm_instance* inst) {
    return inst->uinst;
}