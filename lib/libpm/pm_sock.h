

#ifndef PM_SOCK_H_
#define PM_SOCK_H_

/*
packet_mmap with libuinet(user tcp/ip stack)
*/
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

struct pm_params {
    int tpacket_version; // opt, 1:TPACKET_V1 2:TPACKET_V2 3(or else):TPACKET_V3
    const char* netdev; // opt, eg: "eth0"
	int local_port; // opt, 
	const char* local_ip; // opt, 
	const char* local_ip6; // opt, 
	const char* gateway_mac; // opt, 

    void (*log_printf)(const char *fmt, ...); // opt, 

    void (*mm_alloc)(size_t n); // opt, 
    void (*mm_free)(void*); // opt, 
};

struct pm_instance;

int pm_init(struct pm_instance** out, struct pm_params* p);
void pm_destroy(struct pm_instance* v);

struct pm_socket;
int pm_socreate(struct pm_instance* inst, struct pm_socket** out, int type, int proto);
void pm_shutdown(struct pm_socket* fd, int how);
int pm_accept(struct pm_socket *listener, struct pm_sockaddr **nam, struct pm_socket **aso);
int pm_bind(struct pm_socket *so, struct pm_sockaddr *nam);
int pm_close(struct pm_socket *so);
int pm_connect(struct pm_socket *so, struct pm_sockaddr *nam);

#ifdef __cplusplus
}
#endif

#endif
