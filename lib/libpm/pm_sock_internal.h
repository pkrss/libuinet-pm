

#ifndef PM_SOCK_INTERNAL_H_
#define PM_SOCK_INTERNAL_H_

#include "pm_sock.h"
#include <linux/if_ether.h> // ETH_ALEN

#ifdef __cplusplus
extern "C" {
#endif


struct pm_instance {
    struct pm_params params;
    struct {
        int i_ifindex;
        struct sockaddr_in local_adr;
        struct sockaddr_in6 local_adr6;        
        // struct sockaddr_in gw_adr;
        // struct sockaddr_in6 gw_adr6;
        unsigned char local_mac[ETH_ALEN+2];
        unsigned char gw_mac[ETH_ALEN+2];
    } opt;
};

struct pm_socket {
    struct pm_instance* inst;
    int fd;

	struct pm_so_info info;
    
    unsigned int tp_rblock_num;
    unsigned int tp_wblock_num;
    struct iovec* tp_rd;
    struct iovec* tp_wd;
    uint8_t* tp_map;
    size_t tp_map_size;
};

void pm_close_fd(int fd);

#ifdef __cplusplus
}
#endif

#endif
