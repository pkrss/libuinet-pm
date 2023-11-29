
#include "../lib/libpm/pm_sock.h"
#include "../lib/libuinet/api_include/uinet_api.h"
#include <string.h>
#include <arpa/inet.h> // inet_pton
#include <stdio.h> // printf
#include <errno.h>
#include <netdb.h>

// build lib: cd ../ && export UINET_DESTDIR=../../../../out/x64-linux-debug && export MY_CFLAGS="-g -O0" && make all && make install
// build me: gcc -fdiagnostics-color=always -g pm_sock_test.c -o pm_sock_test -I../../../out/x64-linux-debug/include -L../../../out/x64-linux-debug/lib -lpm_s -luinet -lssl -lcrypto

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

// int test_uinet(int dst_family, struct sockaddr_in* local_adr, struct sockaddr_in* dst_adr){
// 	int res;
// 	struct uinet_global_cfg cfg;
// 	struct uinet_socket* aso;
// 	uinet_instance_t uinst;
// 	struct uinet_sockaddr uadr;
// 	struct uinet_sockaddr_in uadr_local;
// 	uinet_if_t ifindex;
// 	const char* local_ip;
// 	int local_port;
// 	const char* netdev;
// 	do {
// 		local_ip = "0.0.0.0";
// 		local_port = 984;
// 		netdev = "eth0";

// 		uinet_if_t uif;
// 		uinet_default_cfg(&cfg, UINET_GLOBAL_CFG_MEDIUM);
// 		uinet_init(&cfg, NULL);
// 		uinst = uinet_instance_create(NULL);

// 		if((res = uinet_socreate(uinst, dst_family, &aso, SOCK_STREAM, IPPROTO_TCP)) != 0) //
// 			break;

// 		// if(0){
// 		// struct uinet_if_cfg ifcfg;
// 		// memset(&ifcfg, 0, sizeof(ifcfg));
// 		// ifcfg.configstr = netdev;
// 		// ifcfg.alias = netdev;
// 		// if((res = uinet_ifcreate(uinst, &ifcfg, &uif)))
// 		// 	break;
// 		// ifindex = uinet_iffind_byname(uinst, netdev);
// 		// }

// 		// if(0){
// 		// 	if ((res = uinet_interface_up(uinst, netdev, 0, 0)))
// 		// 		;// break;

// 		// 	if ((res = uinet_interface_add_alias(uinst, netdev, "172.30.41.113", "172.30.47.255", "255.255.240.0")))
// 		// 		break;
// 		// }

// 		// memset(&uadr_local, 0, sizeof(struct uinet_sockaddr_in));
// 		// uadr_local.sin_len = sizeof(struct uinet_sockaddr_in);
// 		// uadr_local.sin_family = UINET_AF_INET;
// 		// uadr_local.sin_addr.s_addr = inet_addr(local_ip);
// 		// uadr_local.sin_port = htons(local_port);
// 		// res = uinet_sobind(aso, (struct uinet_sockaddr *)&uadr_local);
// 		// if (0 != res) 
// 		// 	break;

// 		if((res=uinet_so_set_pm_info(aso, local_adr, htons(local_port))))
// 			break;

// 		memset(&uadr, 0, sizeof(struct uinet_sockaddr));
// 		uadr.sa_len = sizeof(struct uinet_sockaddr);
// 		// uadr.sa_family = dst_adr->sin_family;
// 		memcpy(&uadr.sa_family, &dst_adr->sin_family, sizeof(struct sockaddr_in));
// 		if((res = uinet_soconnect(aso, &uadr)) != 0)
// 			break;
// 	}while(0);

// 	// if(res)
// 	// 	res = errno;
//     // if(!res)
//     //     res = -1;

//     printf("test_uinet failed, %d %s", res, strerror(res));
// 	return res;
// }

int test_pm(int dst_family, struct pm_sockaddr* dst_adr){
	int res;
	struct pm_instance* inst;
	struct pm_params inst_p;
	struct pm_socket* sck;

	struct uinet_instance* uinet_inst;
	struct uinet_socket *aso;

	inst = NULL;
	sck = NULL;

	do {
		memset(&inst_p, 0, sizeof(struct pm_params));
		inst_p.log_printf = printf;

		if((res = pm_init(&inst, &inst_p)) != 0)
			break;

		if(0){ // need root or cap_net_admin?
			if((res = pm_socreate(inst, &sck, dst_family, SOCK_STREAM, IPPROTO_TCP)) != 0)
				break;
			if((res = pm_connect(sck, dst_adr)) != 0)
				break;
		}else{ // only for debug
			uinet_inst = uinst_instance_get(inst);
			if((res = uinet_socreate(uinet_inst, dst_family, &aso, SOCK_STREAM|SOCK_NONBLOCK, IPPROTO_TCP)) != 0) //
				break;
			if((res = uinet_pm_connect(inst, aso, dst_adr)) != 0)
				break;
		}

	}while(0);

	if(sck)
		pm_close(sck);

	if(inst)
		pm_destroy(inst);

	return res;
}

int hostname_to_adr(int family, const char *hostname, struct in_addr *out_adr)
{
	// int sockfd;  
	struct addrinfo hints, *servinfo, *p;
	// struct sockaddr_in *h;
	int rv;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = family; // use AF_INET6 to force IPv6
	hints.ai_socktype = SOCK_STREAM;

	if ( (rv = getaddrinfo( hostname , "http" , &hints , &servinfo)) != 0) 
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return -1;
	}

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) 
	{
		*out_adr = ((struct sockaddr_in *)p->ai_addr)->sin_addr;
		// h = (struct sockaddr_in *) p->ai_addr;
		// strcpy(ip , inet_ntoa( h->sin_addr ) );
		break;
	}
	
	freeaddrinfo(servinfo); // all done with this structure
	return 0;
}

int main (int argc, char **argv)
{
	int res;
	struct pm_sockaddr_in dst_adr;
	int dst_family;

	dst_family = AF_INET;

	do {
		res = -1;
			
		memset(&dst_adr, 0, sizeof(dst_adr));
		dst_adr.sin_family = dst_family;
		// dst_adr.sin_addr.s_addr = inet_addr(ip);
		dst_adr.sin_port = ntohs(443);

		if(hostname_to_adr(dst_family, "www.google.com", (struct in_addr*)&dst_adr.sin_addr))
			break;

		// res = test_uinet(dst_family, NULL, &dst_adr);

		res = test_pm(dst_family, (struct pm_sockaddr*)&dst_adr);

	}while(0);

	return res;
}
