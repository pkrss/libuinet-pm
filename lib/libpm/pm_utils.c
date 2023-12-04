
#include "pm_sock_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int pm_utils_get_cmd_result(const char* cmd, char* s, size_t s_len){
    FILE* fp;
    if ((fp = popen(cmd, "r")) == NULL)
        return -1;
    s[s_len-1] = 0;
    cmd = fgets(s, s_len-1, fp);
    pclose(fp);
    fp = NULL;
    return cmd ? 0 : -1;
}

int pm_utils_mac_from_s(uint8_t* dst_mac, const char* mac_s){
    int i1,i2,i3,i4,i5,i6;

    if(sscanf(mac_s, "%x:%x:%x:%x:%x:%x", &i1, &i2, &i3, &i4, &i5, &i6) != 6)
        return -1;

    dst_mac[0] = (uint8_t)i1;
    dst_mac[1] = (uint8_t)i2;
    dst_mac[2] = (uint8_t)i3;
    dst_mac[3] = (uint8_t)i4;
    dst_mac[4] = (uint8_t)i5;
    dst_mac[5] = (uint8_t)i6;
    return 0;
}

void pm_close_fd(int fd){
    // if(fd == -1)
    //     return;
#if defined(_WIN32)
    closesocket(fd);
#else
    close(fd);
#endif
}

const char* pm_err_msg(int e) {
    return (const char*)strerror(e);
}