#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <stdint.h> 
#include <arpa/inet.h>

int main ()
{
	char buf[100] = {0};
	struct sockaddr_in addr_s = {0};
	struct sockaddr_in addr_c = {0};
	int s = -1;
	int ret = 0;
	socklen_t len = sizeof(addr_s);

	if (s = socket(AF_INET, SOCK_DGRAM, 0) == -1)
	{
		printf("socket fail\n");
		return 1;
	}
	
	addr_s.sin_family = AF_INET;
	addr_s.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr_s.sin_port = htons(4444);

	if ((bind(s, (struct sockaddr *)&addr_s, len)) == -1)
	{
		printf("bind failed, s=%d\n", s);
		return 2;
	}

	recvfrom(s, buf, 1, 0, NULL, NULL);
	close(s);
	printf("%d\n", buf[0]);
	return 0;
}
