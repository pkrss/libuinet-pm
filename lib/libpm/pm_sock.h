

#ifndef PM_SOCK_H_
#define PM_SOCK_H_

#ifdef __cplusplus
extern "C" {
#endif

struct pm_socket;

pm_socket* pm_socreate(int type, int proto);
void pm_shutdown(pm_socket* fd, int how);
int pm_accept(struct pm_socket *listener, struct pm_sockaddr **nam, struct pm_socket **aso);
int pm_bind(struct pm_socket *so, struct pm_sockaddr *nam);
int pm_close(struct pm_socket *so);
int pm_connect(struct pm_socket *so, struct pm_sockaddr *nam);

#ifdef __cplusplus
}
#endif

#endif
