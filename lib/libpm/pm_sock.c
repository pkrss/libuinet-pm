#include "pm_sock.h"
#include <net/if.h> // if_nameindex()
#include <stdlib.h>
#include "../libuinet/api_include/uinet_api.h"

struct pm_instance {
    struct pm_params params;
    uinet_instance_t uinst;
    struct {
        int i_ifindex;
    } opt;
};

struct pm_socket {
    struct pm_instance* inst;
    struct uinet_socket* aso;
    struct socket* fd;
};

int pm_init(struct pm_instance** out, struct pm_params* p) {
    bool found;
    struct pm_params* p;
    struct if_nameindex* ifni;
    struct pm_instance* inst;

    inst = (struct pm_instance*)((p0 && p->mm_alloc ? p->mm_alloc : malloc)(sizeof(struct pm_instance)));
    memset(inst, 0, sizeof(pm_instance));

    inst->params = *p;
    p = &inst->params;

    ifni = if_nameindex();
    // check netdev
    if(!p->netdev || !p->netdev[0]){
        while(ifni && ifni->if_name){
            if(ifni->if_name[0] == 'e') { // eth0 or ens5
                p->netdev = ifni->if_name;
                inst->opt.i_ifindex = if_nametoindex(ifni->if_name);
                if(p->log_printf)
                    p->log_printf("found netdev:%s", ifni->if_name);
                break;
            }
            ifni++;
        }
    }else{
        found = false;
        while(ifni && ifni->if_name){
            if(0 == strcmp(p->netdev, ifni->if_name)) {
                found = true;
                break;
            }
            ifni++;
        }
        if(!found){
            if(p->log_printf)
                p->log_printf("unfound netdev in local interfaces:%s, exiting", p->netdev);
            goto failed;
        }
        inst->opt.i_ifindex = if_nametoindex(ifni->if_name);
        p->netdev = ifni->if_name;
    }

    struct uinet_global_cfg cfg;
	uinet_default_cfg(&cfg, UINET_GLOBAL_CFG_MEDIUM);
	uinet_init(&cfg, NULL);
    inst->uinst = uinet_instance_create(&cfg);

    if((p->tpacket_version != 1) && (p->tpacket_version != 2))
        p->tpacket_version = 3; // TPACKET_V3

    if(!p->mm_alloc) // call p->mm_alloc() easy
        p->mm_alloc = malloc;
    if(!p->mm_free)
        p->mm_free = free;
        
    *out = inst;
    return 0;
failed:
    pm_destroy(inst);
    return -1;
}

void pm_destroy(struct pm_instance* v){
    (v->params.mm_free : free)(v);
}

int pm_socreate(struct pm_instance* inst, struct pm_socket** out, int type, int proto){
    (void)type;
    (void)proto;
    int res;
    struct pm_socket* sck = (struct pm_socket*)inst->params->mm_alloc(sizeof(struct pm_socket));
    memset(sck, 0, sizeof(struct pm_socket));
    sck->inst = inst;
    if((res = uinet_socreate(inst->uinst, AF_PACKET, &sck->aso, SOCK_RAW|SOCK_NONBLOCK, htons(ETH_P_ALL))) != 0)
        goto failed;
    sck->fd = *(struct socket*)sc->aso;
    
    struct sockaddr_ll my_addr;
    memset(&my_addr, 0, sizeof(struct sockaddr_ll));
    my_addr.sll_family = PF_PACKET;
    my_addr.sll_protocol = htons(ETH_P_ALL);

    // initialize interface struct
    strcpy(s_ifr.ifr_name, inst->params.netdev);

    // Get the broad cast address
    if((res = ioctl(fd_socket[z], SIOCGIFINDEX, &s_ifr)) == -1)
        goto failed;

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

    *out = sck;
    return 0;
failed:
    return res;
}