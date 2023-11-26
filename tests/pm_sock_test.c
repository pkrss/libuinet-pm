
#include "../lib/libpm/pm_sock.h"

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

		if((res = pm_socreate(inst, &scp, dst_family, SOCK_STREAM, IPPROTO_TCP)) != 0)
			break;

		memset(&dst_adr, 0, sizeof(sockaddr_in));
		if(inet_pton(dst_family, dst_ip, &dst_adr.sa4.sin_addr)==1){
			dest.sa4.sin_family = dst_family;
			// dest.sa4.sin_addr.s_addr = inet_addr(ip);
			dest.sa4.sin_port = ntohs(dst_port);
		}else{
			break;
		}

		if((res = pm_connect(sck, &dst_adr)) != 0)
			break;

	}while(false);

	if(sck)
		pm_close(sck);

	if(inst)
		pm_destroy(inst);

	return res;
}
