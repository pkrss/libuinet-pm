

#ifndef PM_SOCK_H_
#define PM_SOCK_H_

/*
packet_mmap with libuinet(user tcp/ip stack)
*/
// #include "pm_inc.h"
#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

struct pm_params {
    int tpacket_version; // opt, 1:TPACKET_V1 2:TPACKET_V2 3(or else):TPACKET_V3
    int mtu; // opt, default 1500
    const char* netdev; // opt, eg: "eth0"
    
	unsigned int tp_block_size; // rcv/snd block size, defualt: 40960;
    unsigned int tp_frame_size; // rcv/snd frame size, defualt: 2048 for mtu 1500
	unsigned int tp_r_block_num; // rcv block num, defualt: 2
	unsigned int tp_w_block_num; // snd block num, defualt: 1
    
    void (*log_printf)(const char *fmt, ...); // opt, 

    void* (*mm_alloc)(size_t n); // opt, 
    void (*mm_free)(void*); // opt, 
    
	// int local_port; // opt, 
	// const char* local_ip; // opt, 
	// const char* local_ip6; // opt, 
	// const char* gateway_mac; // opt, 
};

struct pm_instance;
struct pm_socket;

int pm_init(struct pm_instance** out, struct pm_params* p);
void pm_destroy(struct pm_instance* v);

int pm_socreate(struct pm_instance* inst, struct pm_socket** out, int family, int type, int proto);
// void pm_shutdown(struct pm_socket* sck, int how);
// int pm_accept(struct pm_socket *listener, struct pm_sockaddr **adr, struct pm_socket **aso);
// int pm_bind(struct pm_socket *sck, struct pm_sockaddr *nam);
int pm_close(struct pm_socket *sck);
int pm_connect(struct pm_socket *sck, struct sockaddr_in *adr);

#ifdef __cplusplus
}
#endif

#endif
