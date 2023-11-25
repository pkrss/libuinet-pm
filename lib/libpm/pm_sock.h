

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
    const char* netdev; //  = "eth0"
	int local_port;
	const char* local_ip;
	const char* local_ip6;
	const char* gateway_mac;

    void (*log_printf)(const char *fmt, ...);

    void (*mm_alloc)(size_t n);
    void (*mm_free)(void*);
};

struct pm_instance;

int pm_init(struct pm_instance** out, struct pm_params* p);
void pm_destroy(struct pm_instance* v);

struct pm_socket;
struct pm_socket* pm_socreate(struct pm_instance* i, int type, int proto);
void pm_shutdown(struct pm_socket* fd, int how);
int pm_accept(struct pm_socket *listener, struct pm_sockaddr **nam, struct pm_socket **aso);
int pm_bind(struct pm_socket *so, struct pm_sockaddr *nam);
int pm_close(struct pm_socket *so);
int pm_connect(struct pm_socket *so, struct pm_sockaddr *nam);

#ifdef __cplusplus
}
#endif

#endif
