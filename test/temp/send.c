#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>


uint16_t checksum(uint16_t *buf, int32_t len)
{
	uint64_t sum = 0;
	while(len > 1) {
		sum += *buf++;
		len -= sizeof(uint16_t);
	}
	if(len)
		sum += *(uint16_t *)buf;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (uint16_t)(~sum);

}
typedef struct {
	uint32_t sip;
	uint32_t dip;
	uint8_t mbz;
	uint8_t ptcl;
	uint16_t len;
} vhd;

//int main(int argc, char *argv[])
//{
//	int s, i;
//	uint16_t j = 0;
//	char buf[32];
//	struct ip *ip = (struct ip *) buf;
//	struct udphdr *udp = (struct udphdr *) (buf+20);
//	struct hostent *hp, *hp2;
//	struct sockaddr_in dst;
//	int offset;
//	int on;
//
//	/* Loop based on the packet number */
//
//	printf("test\n");
//	on = 1;
//	bzero(buf, sizeof(buf));
//
//	/* 创建 RAW socket */
//
//	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
//		perror("socket() error");
//		/* If something wrong, just exit */
//		exit(1);
//	}
//
//	/* 使用socket options, 告诉系统 我们提供 IP structure */
//	/*Prototype: int setsockopt (int socket, int level, int optname, void *optval, socklen_t optlen)*/
//	if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)	{
//		perror("setsockopt() for IP_HDRINCL error");
//		exit(1);
//	}
//
//	/* gethostbyname()返回对应于给定主机名的包含主机名字和地址信息的hostent结构指针。 */
//	if ((ip->ip_dst.s_addr = inet_addr("127.0.0.1")) == -1) {
//		fprintf(stderr, "Can't resolve dst ip, unknown host.\n");
//		exit(1);
//	}
//
//	/* The following source address just redundant for target to collect */
//
//	if ((ip->ip_src.s_addr = inet_addr("192.168.1.254")) == -1) {
//		fprintf(stderr, "Can't resolve src ip, unknown host\n");
//		exit(1);
//	}
//
//	printf("Sending to %s from %s spoofed \n", inet_ntoa(ip->ip_dst), inet_ntoa(ip->ip_src));
//
//	/* Ip structure, check the ip.h */
//
//	for(j = 0; j < 65536; j++){
//
//		ip->ip_v = 4;
//		ip->ip_hl = sizeof *ip >> 2;
//		ip->ip_tos = 0;
//		ip->ip_len = htons(32);
//		ip->ip_id = htons(j);
//		ip->ip_off = 0;
//		ip->ip_ttl = 255;
//		ip->ip_p = 17;
//		ip->ip_sum = 0;
//		ip->ip_sum = checksum((uint16_t *)buf, 20);
//		//	ip->ip_sum = htons(checksum((uint16_t *)buf, 20));
//
//		udp->source = htons(7890);
//		udp->dest = htons(44444);
//		udp->len = htons(12);
//		udp->check = 0;
//
//		vhd hd = {0};
//		memcpy(&hd, buf+12, 8);
//		hd.ptcl = 17;
//		hd.len = htons(12);
//
//		buf[28] = 'a';
//		buf[29] = 's';
//		buf[30] = 'd';
//		buf[31] = '\n';
//
//		uint8_t buff[96] = {0};
//		memcpy(buff, &hd, 12);
//		memcpy(buff+12, buf+20, 12);
//		//	udp->check = htons(checksum((uint16_t *)(buff), 24));
//		udp->check = checksum((uint16_t *)(buff), 24);
//
//
//		dst.sin_family = AF_INET;
//		dst.sin_addr = ip->ip_dst;
//		dst.sin_port = udp->dest;
//
//		//	for(i = 0; i < 32; i++) {
//		//		printf("%2x\t", (uint8_t)buf[i]);
//		//		if (i%4 == 3)
//		//			printf("\n");
//		//	}
//
//		if (sendto(s, buf, sizeof(buf), 0, (struct sockaddr *) &dst,
//					sizeof(dst)) < 0) {
//			fprintf(stderr, "offset %d: ", offset);
//			perror("sendto() error");
//		}
//		else
//			printf("sendto() is OK.\n");
//	}
//
//	/* close socket */
//	close(s);
//
//	return 0;
//
//}

static uint16_t j = 0;

static uint8_t *add_head(uint8_t *buf, uint32_t len, char *dst_ip)
{
	uint8_t *new_buf = (uint8_t *)malloc(len+28);
	struct ip *ip = (struct ip *)new_buf;
	struct udphdr *udp = (struct udphdr *)(new_buf+20);
	uint8_t *vudp = (uint8_t *)malloc(len+sizeof(vhd)+8+1);
	vhd *hd = (vhd *)vudp;
	vudp[len+sizeof(vhd)+8] = 0;

	memcpy(new_buf+28, buf, len);
//	free(buf);

	ip->ip_v = 4;
	ip->ip_hl = sizeof *ip >> 2;
	ip->ip_tos = 0;
	ip->ip_len = htons(len+28);
	j = (j+1)%255;
	ip->ip_id = htons(j);
	ip->ip_off = htons(0);
	ip->ip_ttl = 255;
	ip->ip_p = 17;
	ip->ip_sum = 0;
	ip->ip_src.s_addr = inet_addr("192.168.1.253");
	ip->ip_dst.s_addr = inet_addr(dst_ip);
	ip->ip_sum = 0;
	ip->ip_sum = checksum((uint16_t *)new_buf, 20);

	memcpy(hd, new_buf+12, 8);
	hd->ptcl = 17;
	hd->len = htons(len+8);

	udp->source = htons(44444);
	udp->dest = htons(44444);
	udp->len = htons(len+8);
	udp->check = htons(0);

	memcpy(vudp+sizeof(vhd), new_buf+20, len+8);
	udp->check = checksum((uint16_t *)vudp, len+8+sizeof(vhd));
	free(vudp);

	return new_buf;
}

int main(int argc, char *argv[])
{
	int s, i;
	uint16_t j = 0;
	char buf[1600];
	uint8_t * data = 0;
	struct ip *ip = (struct ip *) buf;
	struct udphdr *udp = (struct udphdr *) (buf+20);
	struct hostent *hp, *hp2;
	struct sockaddr_in dst;
	int offset;
	int on;

	/* Loop based on the packet number */

	on = 1;
	bzero(buf, 1600);
	for (i = 0; i < 1600; i++) {
		buf[i] = 0xff;
	}

	/* 创建 RAW socket */

	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("socket() error");
		/* If something wrong, just exit */
		exit(1);
	}

	/* 使用socket options, 告诉系统 我们提供 IP structure */
	/*Prototype: int setsockopt (int socket, int level, int optname, void *optval, socklen_t optlen)*/
	if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)	{
		perror("setsockopt() for IP_HDRINCL error");
		exit(1);
	}
	buf[0] = 19;
	buf[1] = 1;
	buf[2] = 1;
	strcpy(buf+3, "10.10.10.253:5389");


		data = add_head(buf, 20, "192.168.1.9");



		if (sendto(s, data, 48, 0, (struct sockaddr *) &dst,
					sizeof(dst)) < 0) {
			fprintf(stderr, "offset %d: ", offset);
			perror("sendto() error");
		}

	/* close socket */
	close(s);

	return 0;
}


