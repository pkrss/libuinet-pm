

#ifndef PM_SOCK_H_
#define PM_SOCK_H_

/*
packet_mmap with libuinet(user tcp/ip stack)
*/
// #include "pm_inc.h"
#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h> // sockaddr
#include <netinet/in.h> // sockaddr_in

#ifdef __cplusplus
extern "C" {
#endif

// ** begin uinet internet style. **

// ** end uinet internet style. **

struct pm_params {
	int debug;
    int tpacket_version; // opt, 1:TPACKET_V1 2:TPACKET_V2 3(or else):TPACKET_V3
    int mtu; // opt, default 1500
    const char* netdev; // opt, eg: "eth0"
    
	unsigned int tp_block_size; // rcv/snd block size, default: 40960;
    unsigned int tp_frame_size; // rcv/snd frame size, default: 2048 for mtu 1500
	unsigned int tp_r_block_num; // rcv block num, default: 2
	unsigned int tp_w_block_num; // snd block num, default: 1
    
    void (*log_printf)(const char *fmt, ...); // opt, 

    void* (*mm_alloc)(size_t n); // opt, 
    void (*mm_free)(void*); // opt, 
    
	int local_port; // opt, 
	// const char* local_ip; // opt, 
	// const char* local_ip6; // opt, 
	// const char* gateway_mac; // opt, 
    struct sockaddr_in* local_adr; // opt
    struct sockaddr_in6* local_adr6; // opt
    const char* local_mac; // opt 6 bytes, eg: 01-02-03-04-05-06
    const char* gw_mac; // opt 6 bytes, eg: 01-02-03-04-05-06
};

struct pm_so_info {
	int family;
	int type;
	int proto;

	struct sockaddr* local_adr; // opt
	int lport; // opt
	const char* local_mac; // opt
	const char* gw_mac; // opt
	int mtu; // opt
	int so_with_lock; // opt
	int (*want_send)(void** buf, size_t n, struct pm_so_info* arg); // opt, prepare send buf, buf is out send buf
	int (*do_send)(const void* buf, size_t n, struct pm_so_info* arg); // opt, call user send
};

// struct pm_instance;
// struct pm_socket;

int pm_init(struct pm_instance** out, struct pm_params* p);
void pm_destroy(struct pm_instance* v);

int pm_socreate(struct pm_instance* inst, struct pm_socket** out, struct pm_so_info* info);
// void pm_shutdown(struct pm_socket* sck, int how);
// int pm_accept(struct pm_socket *listener, struct pm_sockaddr **adr, struct pm_socket **aso);
// int pm_bind(struct pm_socket *sck, struct pm_sockaddr *nam);
int pm_close(struct pm_socket *sck);
int pm_connect(struct pm_socket *sck, struct sockaddr *adr);
int pm_send(struct pm_socket *sck, struct sockaddr *addr, const void *buf, size_t n, int flags);
int pm_recv(struct pm_socket *sck, struct sockaddr *addr, void *buf, size_t n, int *flagsp);
int pm_shutdown(struct pm_socket *sck, int how);
// parse local and gw mac
// int pm_arp_parse_gw_mac(struct pm_instance* inst);

// get shell one line result, 0:ok, -1: failed
int pm_utils_get_cmd_result(const char* cmd, char* s, size_t s_len);

// string mac to bin mac, 0:ok, else: failed.
int pm_utils_mac_from_s(uint8_t* dst_mac, const char* mac_s);

// inline int pm_utils_is_mac_empty(const uint8_t* mac) {
// 	return !mac || !(*(const int64_t*)mac & 0xFFFFFFFFFFFF0000) ? -1 : 0;
// }
#define pm_utils_is_mac_empty(x) (!x || !(*(const int64_t*)x & 0xFFFFFFFFFFFF0000) ? -1 : 0)

#ifdef __cplusplus
}
#endif

#endif
