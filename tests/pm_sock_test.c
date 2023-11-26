
#include "../lib/libpm/pm_sock.h"
#include <string.h>
#include <arpa/inet.h> // inet_pton

// gcc -fdiagnostics-color=always -g pm_sock_test.c -o pm_sock_test -I../../../out/x64-linux-debug/include -L../../../out/x64-linux-debug/lib -lpm_s -luinet -lssl -lcrypto

int main (int argc, char **argv)
{
	int res;
	struct pm_instance* inst;
	struct pm_socket* sck;
	struct sockaddr_in dst_adr;
	const char* dst_ip;
	int dst_port;
	int dst_family;

	inst = NULL;
	sck = NULL;
	dst_family = AF_INET;
	dst_ip = "142.251.222.36";
	dst_port = 443;

	do {
		if((res = pm_init(&inst, NULL)) != 0)
			break;

		if((res = pm_socreate(inst, &sck, dst_family, SOCK_STREAM, IPPROTO_TCP)) != 0)
			break;

		memset(&dst_adr, 0, sizeof(struct sockaddr_in));
		if(inet_pton(dst_family, dst_ip, &dst_adr.sin_addr)==1){
			dst_adr.sin_family = dst_family;
			// dst_adr.sin_addr.s_addr = inet_addr(ip);
			dst_adr.sin_port = ntohs(dst_port);
		}else{
			break;
		}

		if((res = pm_connect(sck, &dst_adr)) != 0)
			break;

	}while(0);

	if(sck)
		pm_close(sck);

	if(inst)
		pm_destroy(inst);

	return res;
}
