#include "pm_sock.h"
#include <net/if.h> // if_nameindex()
#include <stdlib.h>

struct pm_instance {
    pm_params params;
};

int pm_init(struct pm_instance** out, struct pm_params* p) {
    bool found;
    struct pm_params* p;
    struct if_nameindex* ifni;

    *out = (struct pm_instance*)((p0 && p->mm_alloc ? p->mm_alloc : malloc)(sizeof(pm_instance)));
    memset(*out, 0, sizeof(pm_instance));

    out->params = *p;
    p = &out->params;

    ifni = if_nameindex();
    if(!p->netdev || !p->netdev[0]){
        while(ifni && ifni->if_name){
            if(ifni->if_name[0] == 'e') { // eth0 or ens5
                p->netdev = ifni->if_name;
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
        p->netdev = ifni->if_name;
    }
    
    return 0;
failed:
    pm_destroy(*out);
    *out = NULL;
    return -1;
}

void pm_destroy(struct pm_instance* v){
    (v->params.mm_free : free)(v);
}

