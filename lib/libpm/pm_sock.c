
#include "pm_sock_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <net/if.h> // if_nameindex()
#include <errno.h>
#include <assert.h>
// #include "../libuinet/api_include/uinet_api.h"
#include <netdb.h> // NI_MAXHOST
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/socket.h>

void pm_log_printf_none(const char *fmt, ...){
    int bufLen;
    char buf[256+1];

    va_list args1;
    va_start(args1, fmt);
    buf[256] = 0;
    bufLen = vsnprintf(buf, 256, fmt, args1);
    va_end(args1);
    if(bufLen > 0)
        print(buf);
}

int pm_init(struct pm_instance** out, struct pm_params* p) {
    int found, family, res = -1; // res
    struct if_nameindex* ifni;
    struct ifaddrs *ifaddr, *ifa;
    struct pm_instance* inst;
    int fd = -1;
    struct ifreq ifr;
    char* s;
    // char host[NI_MAXHOST];

    inst = (struct pm_instance*)((p && p->mm_alloc ? p->mm_alloc : malloc)(sizeof(struct pm_instance)));
    memset(inst, 0, sizeof(struct pm_instance));

    if(p)
        inst->params = *p;
    p = &inst->params;

    if(!p->mm_alloc) // call p->mm_alloc() easy
        p->mm_alloc = malloc;
    if(!p->mm_free)
        p->mm_free = free;

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
        memmove(&inst->opt.local_adr, p->local_adr, sizeof(struct sockaddr_in));
    if(p->local_adr6)
        memmove(&inst->opt.local_adr6, p->local_adr6, sizeof(struct sockaddr_in6));
    if(p->local_mac)
        pm_utils_mac_from_s(inst->opt.local_mac, p->local_mac);
        // memcpy(&inst->opt.local_mac, p->local_mac, ETH_ALEN);
    if(p->gw_mac)
        pm_utils_mac_from_s(inst->opt.gw_mac, p->gw_mac);
        // memcpy(&inst->opt.gw_mac, p->gw_mac, ETH_ALEN);

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
        if(!inst->opt.local_adr.sin_len && (family == AF_INET)){
            memmove(&inst->opt.local_adr.sin_family, ifa->ifa_addr, sizeof(struct sockaddr_in));
            inst->opt.local_adr.sin_len = sizeof(struct sockaddr_in);
        }
        if(!inst->opt.local_adr6.sin6_len && (family == AF_INET6)){
            memmove(&inst->opt.local_adr6.sin6_family, ifa->ifa_addr, sizeof(struct sockaddr_in6));
            inst->opt.local_adr6.sin6_len = sizeof(struct sockaddr_in6);
        }
        // if(!inst->opt.gw_adr.sin_len && (IFF_POINTOPOINT & ifa->ifa_flags) && (family == AF_INET)){
        //     memcpy(&inst->opt.gw_adr.sin_family, ifa->ifa_ifu.ifu_dstaddr, sizeof(struct sockaddr_in));
        //     inst->opt.gw_adr.sin_len = sizeof(struct sockaddr_in);
        // }
        // if(!inst->opt.gw_adr6.sin6_len && (IFF_POINTOPOINT & ifa->ifa_flags) && (family == AF_INET6)){
        //     memcpy(&inst->opt.gw_adr6.sin6_family, ifa->ifa_ifu.ifu_dstaddr, sizeof(struct sockaddr_in6));
        //     inst->opt.gw_adr6.sin6_len = sizeof(struct sockaddr_in6);
        // }
    }
    freeifaddrs(ifaddr);

    if(!p->local_port)
        p->local_port = 984;

    if(!p->tp_block_size)
        p->tp_block_size = 40960;
    if(!p->tp_frame_size)
        p->tp_frame_size = (p->mtu / 1024 + 1) * 1024; // 2048        
    if(!p->tp_r_block_num)
        p->tp_r_block_num = 2;  
    if(!p->tp_w_block_num)
        p->tp_w_block_num = 1;

    if((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP))==-1)
        goto failed;

    do {
        strcpy(ifr.ifr_name, p->netdev);

        if(pm_utils_is_mac_empty(inst->opt.local_mac)) {
            if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1)
                break;
            memcpy(inst->opt.local_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        }

        if(!p->mtu) {
            if (ioctl(fd, SIOCGIFMTU, &ifr) != -1)
                p->mtu = ifr.ifr_mtu;
        }

        if(pm_utils_is_mac_empty(inst->opt.gw_mac)) {
            // if arp had empty response, please ping gw's ip first
            s = (char*)p->mm_alloc(128);
            // sprintf(s, "arp -n | grep %s | awk '{print $3}' | tr -d :", p->netdev);
            // if((res = pm_utils_get_cmd_result(s, s, 128)) == 0){
            //     n64 = 0;
            //     if((res = sscanf(s, "%lx", &n64)) == 1){
            //         inst->opt.gw_mac[0] = (n64 >> 10) & 0xff;
            //         inst->opt.gw_mac[1] = (n64 >> 8) & 0xff;
            //         inst->opt.gw_mac[2] = (n64 >> 6) & 0xff;
            //         inst->opt.gw_mac[3] = (n64 >> 4) & 0xff;
            //         inst->opt.gw_mac[4] = (n64 >> 2) & 0xff;
            //         inst->opt.gw_mac[5] = (n64) & 0xff;   
            //     }
            // }
            sprintf(s, "arp -n | grep %s | awk '{print $3}'", p->netdev);
            if((res = pm_utils_get_cmd_result(s, s, 128)) == 0)
                pm_utils_mac_from_s(inst->opt.gw_mac, s);
            p->mm_free(s);
            s = NULL;
            res = 0;
        }
    } while(0);

    if(!p->mtu)
        p->mtu = 1500;

    *out = inst;
    res = 0;
failed:

    if (fd!=-1)
        pm_close_fd(fd);

    if(res)
        pm_destroy(inst);

    return res;
}

void pm_destroy(struct pm_instance* v){
    (v->params.mm_free ? v->params.mm_free : free)(v);
}

int pm_socreate(struct pm_instance* inst, struct pm_socket** out, struct pm_so_info* info){
    int res;
    unsigned int i;
    struct sockaddr_ll my_addr;
    struct ifreq s_ifr;    
    struct tpacket_req3 req;
    struct pm_socket* sck;

    sck = (struct pm_socket*)inst->params.mm_alloc(sizeof(struct pm_socket));
    memset(sck, 0, sizeof(struct pm_socket));
    sck->fd = -1;
    sck->inst = inst;

	// check 6 bytes mac is valid
	if(info->local_mac && (*(const int64_t*)info->local_mac & 0xFFFFFFFFFFFF0000))
		pm_opt->local_mac = info->local_mac;
	if(info->gw_mac && (*(const int64_t*)info->gw_mac & 0xFFFFFFFFFFFF0000))
		pm_opt->gw_mac = info->gw_mac;
	pm_opt->mtu = info->mtu;
	// int  ether_output(struct ifnet *, struct mbuf *, struct sockaddr *, struct route *);
	pm_opt->ip_output = &ether_output; // set to our cb functions
	pm_opt->if_transmit = &uinet_if_transmit;	

    if(!info->lport)
        info->lport = htons(inst->params.local_port);
    if(!info->local_mac)
        info->local_mac = (const char*)inst->opt.local_mac;
    if(!info->gw_mac)
        info->gw_mac = (const char*)inst->opt.gw_mac;
    if(!info->mtu)
        info->mtu = inst->params.mtu;
    // info.want_send)(void** buf, size_t n, struct pm_so_info* arg); // opt, prepare send buf, buf is out send buf
    // info.do_send)(const void* buf, size_t n, struct pm_so_info* arg); // opt, call user send
        

    // res = setuid(0);
    if((sck->fd = socket(AF_PACKET, SOCK_RAW|SOCK_NONBLOCK, htons(ETH_P_ALL))) == -1) { // ether_output
         // only for debug
        if(!inst->params.debug || (sck->fd = socket(info->family, SOCK_RAW|SOCK_NONBLOCK, IPPROTO_RAW)) == -1)
        // if((sck->fd = socket(info->family, SOCK_RAW|SOCK_NONBLOCK, IPPROTO_RAW)) == -1) // ip_output

            goto failed;
    }

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
    struct socket* aso;
    if(sck->aso){
        aso = (struct socket *)sck->aso;        
        if(aso->pm_opt){
            if(aso->pm_opt->user)
                free(aso->pm_opt->user, M_DEVBUF);
            free(aso->pm_opt, M_DEVBUF);
        }
        res = uinet_soclose(aso);
    }
    if(sck->fd != -1)
        pm_close_fd(sck->fd);
    if(sck->tp_wd)
        sck->inst->params.mm_free(sck->tp_wd);
    if(sck->tp_rd)
        sck->inst->params.mm_free(sck->tp_rd);
    if(sck->tp_map)
        munmap(sck->tp_map, sck->tp_map_size);
    sck->inst->params.mm_free(sck);
    return res;
}

int pm_connect(struct pm_socket *sck, struct sockaddr *adr){
    struct pm_instance* inst = sck->inst;
    // struct uinet_socket *aso = sck->aso;
    int res;
    struct pm_so_info* info;
    // struct inpcb *inp;
    // struct mbuf_pm_opt* pm_opt;
    // struct socket *so;

    do{
        adr->sa_len = (adr->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));

        inp = sotoinpcb(aso);
        // pm_opt  ->pm_opt;
        info = (pm_so_info*)(sck->info);
        // set addr to our addr, because uinet default use vnet route and addr, but our didn't want to use them        
        info.local_adr = (adr->sa_family == AF_INET ? (struct uinet_sockaddr*)&inst->opt.local_adr : (struct uinet_sockaddr*)&inst->opt.local_adr6);
        
        // if(info->local_adr->sa_family == AF_INET)
        //     memcpy(&inp->inp_laddr, &((struct sockaddr_in*)info->local_adr)->sin_addr, sizeof(struct in_addr));
        // else
        //     memcpy(&inp->in6p_laddr, &((struct sockaddr_in6*)info->local_adr)->sin6_addr, sizeof(struct in6_addr));
	    
        so = (struct socket *)aso;

        if (so->so_state & SS_ISCONNECTING) {
            res = EALREADY;
            break;
        }

        if ((res = soconnect(so, (struct sockaddr *)adr, curthread))){
            so->so_state &= ~SS_ISCONNECTING;
            if (res == ERESTART)
                res = EINTR;
            if(!res)
                res = -1;
            break;
        }  
            
        if ((so->so_state & SS_NBIO) && (so->so_state & SS_ISCONNECTING)) {
            res = EINPROGRESS;
            break;
        }
    } while(0);

    return res;
}

int pm_send(struct pm_socket *sck, struct sockaddr *addr, const void *buf, size_t n, int flags) {
    
    struct uinet_socket *aso = sck->aso;
    
    struct iovec iov[1];
	struct uio uio_internal;
	int res;

    iov[0].iov_base = (void*)buf;
    iov[0].iov_len = n;

	uio_internal.uio_iov = iov;
	uio_internal.uio_iovcnt = 1;
	uio_internal.uio_offset = 0;
	uio_internal.uio_resid = n;
	uio_internal.uio_segflg = UIO_SYSSPACE;
	uio_internal.uio_rw = UIO_WRITE;
	uio_internal.uio_td = curthread;

    if((res = sosend((struct socket *)aso, (struct sockaddr *)addr, &u, NULL, NULL, flags, curthread)) == 0)
        return n - u.uio_resid;
    return res > 0 : -res : res;
}

int pm_recv(struct pm_socket *sck, struct sockaddr *addr, void *buf, size_t n, int *flagsp) {
    struct uinet_socket *aso = sck->aso;
	struct iovec iov[1];
	struct uio uio_internal;
	int res;

    iov[0].iov_base = buf;
    iov[0].iov_len = n;
    
	uio_internal.uio_iov = iov;
	uio_internal.uio_iovcnt = 1;
	uio_internal.uio_offset = 0;
	uio_internal.uio_resid = n;
	uio_internal.uio_segflg = UIO_SYSSPACE;
	uio_internal.uio_rw = UIO_READ;
	uio_internal.uio_td = curthread;
	
    if((res = soreceive((struct socket *)aso, (struct sockaddr **)psa, &uio_internal, NULL, NULL, flagsp)) == 0)
        return n - uio_internal.uio_resid;
    return res > 0 : -res : res;
}

int pm_shutdown(struct pm_socket *sck, int how) {
	return soshutdown(sck->aso, how);
}

int pm_getpeeraddr(struct pm_socket *sck, struct sockaddr **sa) {
	struct socket *so_internal = (struct socket *)so;
	int rv;

	*sa = NULL;

	CURVNET_SET(so_internal->so_vnet);
	rv = (*so_internal->so_proto->pr_usrreqs->pru_peeraddr)(so_internal, (struct sockaddr **)sa);
	CURVNET_RESTORE();

	return (rv);
}

int uinet_if_transmit(struct ifnet *ifp, struct mbuf *m)
{
	int res = ENOBUFS;
	struct pm_so_info* info;
	struct inpcb *inp;
	void* snd_buf = NULL;

	do{
		if(!m->pm_opt || !(info = m->pm_opt->user))
			break;

		inp = sotoinpcb((struct socket *)info->uso);

		if(info->want_send && (0 != (*info->want_send)(&snd_buf, m->m_pkthdr.len, info)))
			break;
		
		// @todo: need optimize to zero copy, search: "MGETHDR(m,"
		m_copydata(m, 0, m->m_pkthdr.len, (caddr_t)snd_buf);

		if(info->do_send && (0 != (*info->do_send)(snd_buf, m->m_pkthdr.len, info)))
			break;

		res = 0;
	}while(0);
	
	return res;
}

int uinet_so_parse_rcv(struct uinet_socket *uso, const void* msg, size_t n) {
	
	struct socket *so = (struct socket *)uso;
	struct mbuf_pm_opt* pm_opt = so->pm_opt;
	struct mbuf *m;

	MGETHDR(m, M_DONTWAIT, MT_DATA);

	m_append(m, n, (c_caddr_t)msg);

	m->pm_opt = pm_opt;
	m->m_flags |= M_PKTHDR;

	ether_demux(NULL, m);

	// copy from so->so_rcv?

	return 0;
}