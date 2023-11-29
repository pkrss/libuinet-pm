

#ifndef PM_SOCK_H_
#define PM_SOCK_H_

/*
packet_mmap with libuinet(user tcp/ip stack)
*/
// #include "pm_inc.h"
#include <stdint.h>
#include <stddef.h>
// #include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

// ** begin uinet internet style. **

typedef	unsigned short		pm_sa_family_t;

typedef uint32_t pm_in_addr_t;
struct pm_in_addr
{
    pm_in_addr_t s_addr;
};

// Socket address, 
struct pm_sockaddr_in {
	uint8_t	sin_len;
	pm_sa_family_t sin_family;
	uint16_t	sin_port;
	struct	pm_in_addr sin_addr;
	char	sin_zero[8];
};

struct pm_in6_addr {
	union {
		uint8_t		__u6_addr8[16];
		uint16_t	__u6_addr16[8];
		uint32_t	__u6_addr32[4];
	} __u6_addr;			/* 128-bit IP6 address */
};
struct pm_sockaddr_in6 {
	uint8_t		sin6_len;	/* length of this struct */
	pm_sa_family_t	sin6_family;	/* AF_INET6 */
	uint16_t	sin6_port;	/* Transport layer port # */
	uint32_t	sin6_flowinfo;	/* IP6 flow information */
	struct pm_in6_addr	sin6_addr;	/* IP6 address */
	uint32_t	sin6_scope_id;	/* scope zone index */
};

struct pm_sockaddr {
	unsigned char		sa_len;		/* total length */
	pm_sa_family_t	    sa_family;	/* address family */
	char			sa_data[14];	/* actually longer; address value */
};

// ** end uinet internet style. **

struct pm_params {
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
    struct pm_sockaddr_in* local_adr; // opt
    struct pm_sockaddr_in6* local_adr6; // opt
    struct pm_sockaddr_in* gw_adr; // opt
    struct pm_sockaddr_in6* gw_adr6; // opt
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
int pm_connect(struct pm_socket *sck, struct pm_sockaddr *adr);

struct uinet_socket;
struct uinet_instance;
int uinet_pm_connect(struct pm_instance* inst, struct uinet_socket *aso, struct pm_sockaddr *adr);
struct uinet_instance* uinst_instance_get(struct pm_instance* inst);

#ifdef __cplusplus
}
#endif

#endif
