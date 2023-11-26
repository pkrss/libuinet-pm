

#ifndef PM_INC_H_
#define PM_INC_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct pm_params {
    int tpacket_version; // opt, 1:TPACKET_V1 2:TPACKET_V2 3(or else):TPACKET_V3
    int mtu; // opt, default 1500
    const char* netdev; // opt, eg: "eth0"
    
	unsigned int tp_block_size; // defualt: 40960;
    unsigned int tp_frame_size; // defualt: 2048 for mtu 1500
	unsigned int tp_block_num; // defualt: 2
	unsigned int tp_w_block_num; // defualt: 1
    
    void (*log_printf)(const char *fmt, ...); // opt, 

    void* (*mm_alloc)(size_t n); // opt, 
    void (*mm_free)(void*); // opt, 
    
	// int local_port; // opt, 
	// const char* local_ip; // opt, 
	// const char* local_ip6; // opt, 
	// const char* gateway_mac; // opt, 
};

#ifdef __cplusplus
}
#endif

#endif
