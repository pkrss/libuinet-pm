
#include "../lib/libpm/pm_sock.h"
#include "../lib/libuinet/api_include/uinet_api.h"
#include <string.h>
#include <arpa/inet.h> // inet_pton
#include <stdio.h> // printf
#include <errno.h>

// cd ../ && export UINET_DESTDIR=../../../../out/x64-linux-debug && export MY_CFLAGS="-g -O0" && make all && make install
// gcc -fdiagnostics-color=always -g pm_sock_test.c -o pm_sock_test -I../../../out/x64-linux-debug/include -L../../../out/x64-linux-debug/lib -lpm_s -luinet -lssl -lcrypto

// bool set_fd_ip(int fd, const char* netdev, char *ipaddr)
// {
//     struct sockaddr_in sin_set_ip;
//     struct ifreq ifr_set_ip;
   
//     // if(fd = socket(PF_INET, SOCK_STREAM, 0 ) == -1);
// 		// return -1;
  
//     memset(&sin_set_ip, 0, sizeof(sin_set_ip));
//     memset(&ifr_set_ip, 0, sizeof(ifr_set_ip));
//     strncpy(ifr_set_ip.ifr_name, netdev, sizeof(ifr_set_ip.ifr_name)-1);
//     sin_set_ip.sin_family = AF_INET;  
//     sin_set_ip.sin_addr.s_addr = inet_addr(ipaddr);  
//     memcpy( &ifr_set_ip.ifr_addr, &sin_set_ip, sizeof(sin_set_ip));  
  
//     if(uinet_ioctl(fd, SIOCSIFADDR, &ifr_set_ip) < 0)
// 		return -1;

//     ifr_set_ip.ifr_flags |= IFF_UP |IFF_RUNNING;
//     //get the status of the device  
//     if(uinet_ioctl(fd, SIOCSIFFLAGS, &ifr_set_ip) < 0)
// 		return -1;
//     // close( fd);   
//     return 0;  
// }

int test_uinet(int dst_family, struct sockaddr_in* dst_adr){
	int res;
	struct uinet_global_cfg cfg;
	struct uinet_socket* aso;
	uinet_instance_t uinst;
	struct uinet_sockaddr uadr;
	struct uinet_sockaddr_in uadr_local;
	uinet_if_t ifindex;
	const char* local_ip;
	int local_port;
	const char* netdev;
	struct uinet_if_cfg ifcfg;
	uinet_if_t uif;
	do {
		local_ip = "0.0.0.0";
		local_port = 984;
		netdev = "eth0";

		uinet_default_cfg(&cfg, UINET_GLOBAL_CFG_MEDIUM);
		uinet_init(&cfg, NULL);
		uinst = uinet_instance_create(NULL);

		memset(&ifcfg, 0, sizeof(ifcfg));
		ifcfg.configstr = netdev;
		ifcfg.alias = netdev;
		if((res = uinet_ifcreate(uinst, &ifcfg, &uif)))
			break;

		if((res = uinet_socreate(uinst, dst_family, &aso, SOCK_STREAM, 0)) != 0) // IPPROTO_TCP
			break;
			
		ifindex = uinet_iffind_byname(uinst, netdev);

		// if ((res = uinet_make_socket_promiscuous(aso, ifindex)))
		// 	break;
		
		// get_client_tuple(connscale, index, local_mac, foreign_mac, vlan, &local_ip, &local_port, &foreign_ip, &foreign_port);
		
		// if (connscale->vlans.size > 0) {
		// 	unsigned int vindex;
		// 	uint32_t ethertype;
				
		// 	tagstack.inl2t_cnt = connscale->vlans.size;
		// 	for (vindex = 0; vindex < connscale->vlans.size; vindex++) {
		// 		ethertype = (vindex == (connscale->vlans.size - 1)) ? 0x8100 : 0x88a8;
		// 		tagstack.inl2t_tags[vindex] = htonl((ethertype << 16) | vlan[vindex]);
		// 		tagstack.inl2t_masks[vindex] = (vlan[vindex] == 0) ? 0 : htonl(0x00000fff);
		// 	}
		// }
		// if ((res = uinet_setl2info2(aso, local_mac, foreign_mac, UINET_INL2I_TAG_ANY, NULL)))
		// 	break;
		if ((res = uinet_interface_up(uinst, netdev, 0, 0)))
			;// break;

		if ((res = uinet_interface_add_alias(uinst, netdev, "172.30.41.113", "172.30.47.255", "255.255.240.0")))
			break;

		// memset(&uadr_local, 0, sizeof(struct uinet_sockaddr_in));
		// uadr_local.sin_len = sizeof(struct uinet_sockaddr_in);
		// uadr_local.sin_family = UINET_AF_INET;
		// uadr_local.sin_addr.s_addr = inet_addr(local_ip);
		// uadr_local.sin_port = htons(local_port);
		// res = uinet_sobind(aso, (struct uinet_sockaddr *)&uadr_local);
		// if (0 != res) 
		// 	break;

		memset(&uadr, 0, sizeof(struct uinet_sockaddr));
		uadr.sa_len = sizeof(struct uinet_sockaddr);
		// uadr.sa_family = dst_adr->sin_family;
		memcpy(&uadr.sa_family, &dst_adr->sin_family, sizeof(struct sockaddr_in));
		if((res = uinet_soconnect(aso, &uadr)) != 0)
			break;
	}while(0);

	// if(res)
	// 	res = errno;
    // if(!res)
    //     res = -1;

    printf("test_uinet failed, %d %s", res, strerror(res));
	return res;
}

int test_pm(int dst_family, struct sockaddr_in* dst_adr){
	int res;
	struct pm_instance* inst;
	struct pm_params inst_p;
	struct pm_socket* sck;

	inst = NULL;
	sck = NULL;

	do {
		memset(&inst_p, 0, sizeof(struct pm_params));
		inst_p.log_printf = printf;

		if((res = pm_init(&inst, &inst_p)) != 0)
			break;

		if((res = pm_socreate(inst, &sck, dst_family, SOCK_STREAM, IPPROTO_TCP)) != 0)
			break;

		if((res = pm_connect(sck, dst_adr)) != 0)
			break;
	}while(0);

	if(sck)
		pm_close(sck);

	if(inst)
		pm_destroy(inst);

	return res;
}

int main (int argc, char **argv)
{
	int res;
	struct sockaddr_in dst_adr;
	const char* dst_ip;
	int dst_port;
	int dst_family;

	dst_family = AF_INET;
	dst_ip = "142.251.222.36";
	dst_port = 443;

	do {
		res = -1;

		memset(&dst_adr, 0, sizeof(struct sockaddr_in));
		if(inet_pton(dst_family, dst_ip, &dst_adr.sin_addr)==1){
			dst_adr.sin_family = dst_family;
			// dst_adr.sin_addr.s_addr = inet_addr(ip);
			dst_adr.sin_port = ntohs(dst_port);
		}else{
			break;
		}

		res = test_uinet(dst_family, &dst_adr);

		// res = test_pm(dst_family, &dst_adr);

	}while(0);

	return res;
}
