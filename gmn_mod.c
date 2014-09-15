#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h> 
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h> 
#include <netinet/udp.h> 
#include <netdb.h> 
#include <pthread.h> 
#include <sys/ioctl.h> 
#include <linux/if.h> 
#include "gmn_mod.h"
#include "ftl_log.h" 
#include "ftl_msg.h"

#define GMN_LOG(data, ...) printf(data, ##__VA_ARGS__)
#define GMN_ERR(data, ...) printf(data, ##__VA_ARGS__)
#define DEBUG
#define ERROR_TOR 50

struct pthread_arg {
	int32_t  fd;
	uint32_t ip;
	uint16_t ue_id;
	uint8_t  rab_id;
};

typedef struct {
	uint32_t sip;
	uint32_t dip;
	uint8_t mbz;
	uint8_t ptcl;
	uint16_t len;
} vhd;

/*=======================================STATIC===============================*/

static uint16_t   gemini_init_flag_s     = 0;
static int32_t    listenfd_s             = -1;
static uint16_t   ue_port_s              = 44444;
static ue_info_t  *ue_info_head_s        = NULL; 
static uint32_t   gmn_wifi_ip_s          = 0;
static uint32_t   gmn_3g_ip_s            = 0;
static pthread_t  wifi_listen_p_s        = 0;
static uint32_t   flag_ip_s              = 0;
static uint16_t   ip_id_s                = 1;

/*=======================================DEBUG===============================*/

/**
 * \brief Show all ue information recorded in memory
 */
static void show_all_ue_info_d()
{
	ue_info_t *p = ue_info_head_s;
	int count = 0;
	GMN_LOG("%s", "[show all ue info in memory]======BEGIN=====\n");
	while (NULL != p) {
		GMN_LOG("%s%d%s", " ue: ",          ++count, "\n");
		GMN_LOG("%s%d%s", " ue_id: ",       p->ue_id, "\n");
		GMN_LOG("%s%d%s", " rab_id: ",      p->rab_id, "\n");
		GMN_LOG("%s%d%s", " rate: ",        p->rate, "\n");
		GMN_LOG("%s%d%s", " next_choice: ", p->next_choice, "\n");
		GMN_LOG("%s%d%s", " wifi_ip: ",     p->wifi_ip, "\n");
		GMN_LOG("%s%d%s", " ue_ip: ",       p->ue_ip, "\n");
		//		GMN_LOG("%s%d%s", " ue_fd: ",       p->ue_fd, "\n");
		GMN_LOG("%s%d%s", " wifi_fd: ",     p->wifi_fd, "\n");
		p = p->next;
	}
	GMN_LOG("%s","[show all ue info in memory]=======END======\n");
	return;
}

/*=======================================INIT===============================*/

/**
 * \brief try to get local wifi ip
 */
void get_ip()
{
	struct sockaddr_in ip_addr_t = {0};
	gmn_wifi_ip_s = inet_addr("10.10.10.254");
	gmn_3g_ip_s	  = inet_addr("10.10.10.253");
	flag_ip_s     = inet_addr("192.168.1.254");

	ip_addr_t.sin_addr.s_addr = gmn_3g_ip_s;
	GMN_LOG("%s%s%s", " 3G IP: ", inet_ntoa(ip_addr_t.sin_addr), "\n");
	ip_addr_t.sin_addr.s_addr = gmn_wifi_ip_s;
	GMN_LOG("%s%s%s", " Wi-Fi IP: ", inet_ntoa(ip_addr_t.sin_addr), "\n");
	ip_addr_t.sin_addr.s_addr = flag_ip_s;
	GMN_LOG("%s%s%s", " UDP's destination IP: ", inet_ntoa(ip_addr_t.sin_addr), "\n");
}

/**
 * \brief Stop the gemini module and free the resource.
 *
 * \param sig [in] type of signal. You can learn it from Linux man-pages.
 */
static void sig_handler(int sig)
{
    if(sig == SIGPIPE) {
        signal(sig, SIG_IGN);
        return;
    }
	signal(sig, SIG_DFL);
	gemini_stop();
	gemini_deinit();

	return; 
}

/**
 * \brief Initialize the 3g part of gemini module
 *
 * \return If all things are going successfully, zero is returned.
 *         On error, 1 is returned.
 */
static uint8_t gmn_3g_init()
{
	uint8_t ret = 0;

	if (FTL_MSG_RST_SUCCESS != ftl_msg_init()) {
		GMN_ERR("%s", " Initialize msg failed.\n");
		ret = 1;
	}
	GMN_LOG("%s", " Initialize 3G success.\n");

	return ret;
}

/**
 * \brief Initialize the wifi part of gemini module
 *
 * \return If all things are going successfully, zero is returned.
 *         On error, 1 or others is returned.
 */
static uint8_t gmn_wifi_init()
{
	struct sockaddr_in serveraddr;
	uint8_t ret = 0;

	get_ip();
	if (!gmn_3g_ip_s) {
		GMN_ERR("%s", "Don't know the gmn_wifi_ip\n");
		return 0;
	}

	if ((listenfd_s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		listenfd_s = -1;
		GMN_ERR("%s", "wifi listen failed\n");
		return 1;
	}

	bzero((void *) &serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	//serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_addr.s_addr = gmn_3g_ip_s;
    GMN_LOG("%s%s%s", "Wifi bind ip is: ", inet_ntoa(serveraddr.sin_addr), "\n");
	serveraddr.sin_port = htons((unsigned short)WIFI_PORT);
	if (bind(listenfd_s, (struct sockaddr *) &serveraddr, 
				sizeof(serveraddr)) < 0) {
		listenfd_s = -1;
        perror("Wifi bind failed\n");
		GMN_ERR("%s", "wifi bind failed\n");
		return 2;
	}
	GMN_LOG("%s", " Initialize wifi success\n");

	return ret;
}

/*=======================================START===============================*/

/**
 * \brief Send msg to another module
 *
 * \param data [in] the struct gtp_data_gemini_t
 * \param len [in] the length of extern data
 * \param mod_id [in] dest module id
 * \param msg_id [in] msgid of the message
 *
 * \return If all things are going successfully, zero is returned.
 *         On error, 1 is returned.
 */
static uint8_t send_msg(void *data, uint32_t len, uint32_t mod_id, uint32_t msg_id)
{
	uint8_t ret = 0;
	ftl_msg_t *msg = NULL;

	msg = ftl_msg_create_ex(sizeof(ftl_msg_t), GMN_MOD_ID, msg_id, NULL, NULL);
	ftl_msg_add_ext(msg, 1, len, data, FTL_MSG_EXT_FLAG_FREE);
	msg->flag |= FTL_MSG_PRI_DEFAULT;

	if (FTL_MSG_RST_SUCCESS != ftl_msg_send(mod_id,(struct ftl_msg *) msg)) {
		ftl_msg_delete((struct ftl_msg *)msg);
		ret = 1;
	}

	return ret;
}

/**
 * \brief get the ue information from memory. When we are going to divide data
 *        we need to know the fds about 3g and wifi connection and whether the
 *        phone has ability of two-tunnel
 * 
 * \param ue_id [in] the ue_id of the phone
 * \param rab_id [in] the rab_id of the phone
 *
 * \return the point of ue information 
 */
static ue_info_t *get_ue(uint16_t ue_id, uint8_t rab_id)
{
	ue_info_t *p = ue_info_head_s; 

	while (NULL != p) {
		if (ue_id == p->ue_id && rab_id == p->rab_id) {
			break;
		} 
		p = p->next;
	}

#ifdef DEBUG
	if (NULL == p) {
		GMN_LOG("%s", "Haven't found the ue from memory\n");
		return NULL;
	}
	GMN_LOG("%s", "get the ue from memory:\n");
	GMN_LOG("%s", "================================\n");
	GMN_LOG("%s%d%s", " ue_id: ",       p->ue_id, "\n");
	GMN_LOG("%s%d%s", " rab_id: ",      p->rab_id, "\n");
	GMN_LOG("%s%d%s", " rate: ",        p->rate, "\n");
	GMN_LOG("%s%d%s", " next_choice: ", p->next_choice, "\n");
	GMN_LOG("%s%d%s", " wifi_ip: ",     p->wifi_ip, "\n");
	GMN_LOG("%s%d%s", " ue_ip: ",       p->ue_ip, "\n");
	//	GMN_LOG("%s%d%s", " ue_fd: ",       p->ue_fd, "\n");
	GMN_LOG("%s%d%s", " wifi_fd: ",     p->wifi_fd, "\n");
	GMN_LOG("%s", "================================\n");
#endif
	return p;

}

static uint16_t checksum(uint16_t *buf, int32_t len)
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


static uint8_t *add_head(uint8_t *buf, uint32_t len, char *dst_ip)
{
	uint8_t *new_buf = (uint8_t *)malloc(len+28);
	struct ip *ip = (struct ip *)new_buf;
	struct udphdr *udp = (struct udphdr *)(new_buf+20);
	uint8_t *vudp = (uint8_t *)malloc(len+sizeof(vhd)+8+1);
	vhd *hd = (vhd *)vudp;
	vudp[len+sizeof(vhd)+8] = 0;

	memcpy(new_buf+28, buf, len);
	free(buf);

	ip->ip_v = 4;
	ip->ip_hl = sizeof *ip >> 2;
	ip->ip_tos = 0;
	ip->ip_len = htons(len+28);
    ip_id_s = (ip_id_s + 1)%65536;
	ip->ip_id = htons(ip_id_s);
	ip->ip_off = htons(0);
	ip->ip_ttl = 255;
	ip->ip_p = 17;
	ip->ip_sum = 0;
	ip->ip_src.s_addr = inet_addr("192.168.1.254");
	ip->ip_dst.s_addr = inet_addr(dst_ip);
	ip->ip_sum = 0;
	ip->ip_sum = checksum((uint16_t *)new_buf, 20);

	memcpy(hd, new_buf+12, 8);
	hd->ptcl = 17;
	hd->len = htons(len+8);

	udp->source = htons(ue_port_s);
	udp->dest = htons(ue_port_s);
	udp->len = htons(len+8);
	udp->check = htons(0);

	memcpy(vudp+sizeof(vhd), new_buf+20, len+8);
	// udp->check = checksum((uint16_t *)vudp, len+8+sizeof(vhd));
	free(vudp);

	return new_buf;
}

/**
 * \brief Forward the msg from UU to CN
 *
 * \param data [in] the sturct gtp_data_gemini_t
 *
 * \return If all things are going successfully, zero is returned.
 *         On error, 1 is returned.
 */
static uint8_t forward_msg(void *data)
{
	return send_msg(data, sizeof(gtp_data_gemini_t), FTL_MOD_ID_IUH, IUH_GMN_UL_IU_DATA);
}

/**
 * \brief divide the msg got from CN
 *
 * \param data [in] the struct gtp_data_gemini_t 
 *
 * \return If all things are going successfully, zero is returned.
 *         On error, 1 is returned.
 */
static uint8_t divide_msg(gtp_data_gemini_t *msg)
{
	ue_info_t *info = NULL;
	gtp_data_gemini_t *new_msg = NULL;
	uint8_t buf[2500] = {0};
	struct sockaddr_in sip = {0};
	uint32_t *temp = NULL;
	uint8_t *data = NULL;

	info = get_ue(msg->ue_id, msg->rab_id);
	if (info == NULL) {
		GMN_ERR("%s", "There is something wrong! Can't find the ue info in memory\n");
		GMN_ERR("%s%d%s%d", "The strange ue_id:",msg->ue_id,"\t,rab_id:",msg->rab_id);
		GMN_ERR("%s", "Here is our all ue info in memory\n");
		show_all_ue_info_d();
		new_msg = (gtp_data_gemini_t *)malloc(sizeof(gtp_data_gemini_t));
		new_msg->size = msg->size;
		new_msg->data = msg->data;
		new_msg->ue_id = msg->ue_id;
		new_msg->rab_id = msg->rab_id;
		return send_msg(new_msg, sizeof(gtp_data_gemini_t), IUH_MOD_ID, IUH_GMN_DL_UU_DATA);
	}
	if (info->wifi_fd > 0) {
#ifdef DEBUG
  //       uint8_t *d_buf = 0;
  //       uint32_t d_len = 1000;
  //       uint32_t * d_temp = 0;
  //       while(d_len < 1600) {

  //           sleep(1);
  //           gtp_data_gemini_t *d_msg = (gtp_data_gemini_t *)malloc(sizeof(gtp_data_gemini_t));
  //           d_buf =(uint8_t *)malloc(d_len);
  //           memset(d_buf, 0xff, d_len);
  //           d_buf[0] = 6;
  //           d_buf[1] = 1;
  //           d_buf[2] = 21;
  //           d_temp = (uint32_t *)(d_buf+3);
  //           *d_temp = d_len-7; 

  //           d_msg->size = d_len+28;
  //           d_msg->size = (d_msg->size)*8; //byte to bit
		// 	sip.sin_addr.s_addr = info->ue_ip;
  //           d_msg->data = add_head(d_buf, d_len++,inet_ntoa(sip.sin_addr));
  //           d_msg->rab_id = msg->rab_id;
  //           d_msg->ue_id = msg->ue_id;

  //           send_msg(d_msg, sizeof(gtp_data_gemini_t), IUH_MOD_ID, IUH_GMN_DL_UU_DATA);

  //           GMN_LOG("%d%s", ip_id_s, "\n");
  //           GMN_LOG("%d%s", d_len-1, "\n");
  //       }


  //       temp = (uint32_t *)(msg->data+12);
		// sip.sin_addr.s_addr = *temp;
		// GMN_LOG("%s%s%s", "source ip in IP head: ", inet_ntoa(sip.sin_addr), "\n");
		// temp = (uint32_t *)(msg->data+16);
		// sip.sin_addr.s_addr = *temp;
		// GMN_LOG("%s%s%s", "distination ip in IP head: ", inet_ntoa(sip.sin_addr), "\n");
#endif
		bzero(buf, 2500);
		buf[0] = 6;
		buf[1] = 1;
		buf[2] = 21;
		temp = (uint32_t *)(buf+3);
		*temp = (msg->size+7)>>3; //bit to byte
		memcpy(buf+7, msg->data, *temp);
		free(msg->data);
		info->next_choice = info->next_choice % 10;
		if (info->next_choice++ >= info->rate/10) {
#ifdef DEBUG
            GMN_LOG("%s","return data choose wifi\n");
            int i = 0;
            GMN_LOG("%s","the data returned is: ");
            for (i = 0; i < *temp+7; i++) {
                if (i%8 == 0)
                    GMN_LOG("%s", "\n");
                GMN_LOG("%x%s", buf[i], "\t");
            }
            GMN_LOG("%s", "\n");
#endif
			return send(info->wifi_fd, buf, *temp+7, 0);
		} else {
            GMN_LOG("%s","return data choose 3G\n");
			data = (uint8_t *)malloc(*temp+7);
            GMN_LOG("%s%d%s","malloc size is :", *temp+7, "\n");
			memcpy(data, buf, *temp+7);
            GMN_LOG("%s","free msg's data successfully \n");
			sip.sin_addr.s_addr = info->ue_ip;
			msg->data = add_head(data, *temp+7, inet_ntoa(sip.sin_addr));
			msg->size = msg->size+(7+28)*8; //byte to bit
            GMN_LOG("%s", "going to return data choose 3G\n");
		}
	}
	new_msg = (gtp_data_gemini_t *)malloc(sizeof(gtp_data_gemini_t));
	new_msg->size = msg->size;
	new_msg->data = msg->data;
	new_msg->ue_id = msg->ue_id;
	new_msg->rab_id = msg->rab_id;
	return send_msg(new_msg, sizeof(gtp_data_gemini_t), IUH_MOD_ID, IUH_GMN_DL_UU_DATA);
}

/**
 * \brief Send msg to RRM to update ue information
 *
 * \param ue_status [in] the information about ue
 *
 * \return If all things are going successfully, zero is returned.
 *         On error, 1 is returned.
 */
static uint8_t update_msg(gmn_ue_status_t *ue_status)
{
	return send_msg((void *)ue_status, sizeof(gmn_ue_status_t),
			RRM_MOD_ID, RRM_GMN_UE_INFO_UPDATE);
}

/**
 * \brief Add ue information into memory order by ue_id
 *
 * \param ue_status [in] some information about us status
 * \param ue_ip [in] ue's 3G ip address
 * \param ue_fd [in] the socket fd of 3G connection
 * \param wifi_fd [in] the socket fd of wifi connection
 *
 * \return On success, zero is returned
 *
 * \comment you should call ue_info_free_all() when the process is over
 *          because the data about ue_info was created by malloc()
 */
static uint8_t ue_info_create(gmn_ue_status_t *ue_status, uint32_t ue_ip,
		int32_t ue_fd, int32_t wifi_fd)
{
	ue_info_t *ue_info_node = NULL;
	ue_info_t *p = ue_info_head_s; 
	ue_info_t *q = ue_info_head_s;

	ue_info_node = malloc(sizeof(ue_info_t));

	ue_info_node->ue_id        = ue_status->ue_id;
	ue_info_node->rab_id       = ue_status->rab_id;
	ue_info_node->rate         = ue_status->rate;
	ue_info_node->next_choice  = 0;
	ue_info_node->wifi_ip      = ue_status->wifi_ip;
	ue_info_node->ue_ip        = ue_ip;
	//	ue_info_node->ue_fd        = ue_fd;
	ue_info_node->wifi_fd      = wifi_fd;
	ue_info_node->next         = NULL;

	if (NULL == ue_info_head_s) {
		ue_info_head_s = ue_info_node;
	} else {
		if (ue_status->ue_id > q->ue_id) {
			q = q->next;
		}
		while (NULL != q && ue_status->ue_id > q->ue_id) {
			q = q->next;
			p = p->next;
		}
		if (p == q) {
			ue_info_head_s = ue_info_node;
		} else {
			p->next = ue_info_node;
		}
		ue_info_node->next = q;
	}
	return 0;
}

/**
 * \brief Remove ue_info from memory where ue_id equal $ue_id
 */
static uint8_t ue_info_remove(uint16_t ue_id)
{
#ifdef DEBUG
	GMN_LOG("%s%d%s", "going to remove ue info from memory which ue_id is ", ue_id, "\n");
#endif
	ue_info_t *p = ue_info_head_s; 
	ue_info_t *q = ue_info_head_s;
	uint8_t ret = 1;

	if (NULL != ue_info_head_s) {
		while (p == q && NULL != q) {
			if (p->ue_id == ue_id) {
				ue_info_head_s = p->next;
				//				close(p->ue_fd);
				close(p->wifi_fd);
#ifdef DEBUG
				GMN_LOG("%s%d%s", "closed ", ue_id, "'s wifi and 3G connection fd\n"); 
#endif
				q = p->next;
				free(p);
				p = q;
				ret = 0;
				continue;
			}
			q = q->next;
		}
		while (NULL != q) {
			if (ue_id == q->ue_id) {
				q = q->next;
				//				close(p->next->ue_fd);
				close(p->next->wifi_fd);
#ifdef DEBUG
				GMN_LOG("%s%d%s", "closed ", ue_id, "'s wifi and 3G connection fd\n"); 
#endif
				free(p->next);
				p->next = q;
				ret = 0;
			} else if (ue_id > q->ue_id) {
				q = q->next;
				p = p->next;
			} else {
				break;
			}
		}
	}
#ifdef DEBUG
	GMN_LOG("%s%d%s","the result of remove is: ", ret, "\n");
#endif
	return ret;
}

/**
 * \brief Remove ue_info from memory where ue_ip equal $ue_ip
 */
static uint8_t ue_info_remove_by_ip(uint32_t ue_ip)
{
	uint8_t ret = 1;
	ue_info_t *p = ue_info_head_s; 
	gmn_ue_status_t ue_status = {0};

	while (NULL != p) {
		if (ue_ip == p->ue_ip) {
			ue_status.ue_id = p->ue_id;
			ue_status.rab_id = p->rab_id;
			ue_status.capability = 0x00;
			ue_status.rate = 100;
			ue_status.wifi_ip = 0;
			// update_msg(&ue_status);
			ret = 0;
			ue_info_remove(p->ue_id);
			break;
		} 
		p = p->next;
	}

	GMN_LOG("%s%u","[ue info remove by 3G ip]\tdel ue by 3G IP:", ue_ip);
	show_all_ue_info_d();
	return ret;
}

/**
 * \brief cancel wifi capability in memory and rrm where wifi_ip equal $wifi_ip
 */
static uint8_t close_wifi_capability(uint32_t wifi_ip)
{
    GMN_LOG("%s", "[close_wifi_capability] begin \n");
    GMN_LOG("%s%d%s", "[close_wifi_capability] wifi ip: ",wifi_ip,"\n");
#ifdef DEBUG
	GMN_LOG("%s", "before cancel wifi capabiliy\n");
	show_all_ue_info_d();
#endif
	uint8_t ret = 1;
	ue_info_t *p = ue_info_head_s; 
	gmn_ue_status_t ue_status = {0};

	while (NULL != p) {
		if (wifi_ip == p->wifi_ip) {
			p->next_choice = 0;
			p->wifi_ip = 0;
			p->wifi_fd = -1;
			p->rate = 100;
			ue_status.ue_id = p->ue_id;
			ue_status.rab_id = p->rab_id;
			ue_status.capability = 0x00;
			ue_status.rate = 100;
			ue_status.wifi_ip = 0;
			// update_msg(&ue_status);
			ret = 0;
			break;
		} 
		p = p->next;
	}

#ifdef DEBUG
	GMN_LOG("%s", "cancel wifi capabiliy\n");
	show_all_ue_info_d();
#endif
    GMN_LOG("%s", "[close_wifi_capability] end \n");
	return ret;
}

/**
 * \brief update ue information about wifi part in memory, and update rrm
 *
 * \param ue_ip [in] ue's 3G ip address
 * \param wifi_ip [in] ue's wifi ip address
 * \param clientfd [in] ue's wifi connection fd
 * \param ue_id [out] the ue_id of phone connection
 * \param rab_id [out]  the rab_id of phone connection
 *
 * \return On success, zero will be returned. On error, return one.
 */
static uint8_t update_ue_wifi_info(uint32_t ue_ip, uint32_t wifi_ip, 
		int32_t clientfd, uint16_t *ue_id, uint8_t *rab_id)
{
	uint8_t ret = 1;
	ue_info_t *p = ue_info_head_s; 
	gmn_ue_status_t ue_status = {0};

#ifdef DEBUG
    GMN_LOG("%s%d%s", "update_ue_wifi_info with ue_ip: ", ue_ip, "\n");
    GMN_LOG("%s%d%s", "update_ue_wifi_info with wifi_ip: ", wifi_ip, "\n");
    GMN_LOG("%s%d%s", "update_ue_wifi_info with wifi_fd: ", clientfd, "\n");
    GMN_LOG("%s", "after update ue wifi info\n");
    show_all_ue_info_d();
#endif

	while (NULL != p) {
		if (ue_ip == p->ue_ip) {
			p->wifi_ip      = wifi_ip;
			p->wifi_fd      = clientfd;
			*ue_id          = p->ue_id;
			*rab_id         = p->rab_id;

			ue_status.ue_id = p->ue_id;
			ue_status.rab_id = p->rab_id;
			ue_status.capability = 0x01;
			ue_status.rate = p->rate;
			ue_status.wifi_ip = wifi_ip;
			// update_msg(&ue_status);
			ret = 0;
		} 
		p = p->next;
	}

#ifdef DEBUG
	GMN_LOG("%s", "after update ue wifi info\n");
	show_all_ue_info_d();
#endif
	return ret;
}

/**
 * \brief update divide rate about 3g part in memory, and update rrm
 *
 * \param rate [in] the divide rate
 * \param ip [in] ue's 3G ip address
 *
 * \return On success, zero will be returned. On error, return one.
 */
static uint8_t update_ue_3g_info(uint8_t rate, uint32_t ip)
{
	uint8_t ret = 1;
	ue_info_t *p = ue_info_head_s; 
	gmn_ue_status_t ue_status = {0};

	while (NULL != p) {
		if (ip == p->ue_ip) {
			p->rate      = rate;

			ue_status.ue_id = p->ue_id;
			ue_status.rab_id = p->rab_id;
			ue_status.capability = 0x01;
			ue_status.rate = rate;
			ue_status.wifi_ip = p->wifi_ip;
			// update_msg(&ue_status);
			ret = 0;
		} 
		p = p->next;
	}

#ifdef DEBUG
	GMN_LOG("%s","update ue rate info\n");
	show_all_ue_info_d();
#endif
	return ret;
}

/**
 * \brief method from protocol, send close wifi connection info and update in 
 *        memory and rrm
 *
 * \param fd [in] the connection fd under wifi
 * \param ip [in] the wifi ip address
 */
static void close_wifi_connection_m(int32_t fd, uint32_t ip)
{
    GMN_LOG("%s", "[close wifi connection] begin\n");
	uint8_t buf[] = {2,3,4};
	send(fd, (void *)buf, 3, 0);
    GMN_LOG("%s", "finish sending and going to close fd");
	close(fd);
	close_wifi_capability(ip);
    GMN_LOG("%s", "[close wifi connection] end\n");
}

/**
 * \brief method from protocol, send local wifi ip to ue
 *
 * \param ip [in] the ue's ip address under 3g
 */
static void send_wifi_ip_m(uint32_t ip, uint8_t rab_id, uint16_t ue_id)
{
	uint8_t buf[64] = {0};
	struct in_addr temp = {0};
	uint32_t len = 0;
	uint8_t *data = NULL;
	gtp_data_gemini_t *msg = (gtp_data_gemini_t *)malloc(sizeof(gtp_data_gemini_t));
    bzero(buf,0);

	if (gmn_3g_ip_s) {
		temp.s_addr = gmn_3g_ip_s;
		len = strlen(strcpy((char *)(buf+3), inet_ntoa(temp)));
		buf[3+len] = ':';
		len += sprintf((char *)(buf+3+len+1), "%d", WIFI_PORT);
		len += 1;
		buf[0] = 2 + len;
		buf[1] = 1;
		buf[2] = 1;
	} else {
		buf[0] = 2;
		buf[1] = 1;
		buf[2] = 1;
	}
	data = (uint8_t *)malloc(3+len);
	memcpy(data, buf, 3+len);
	temp.s_addr = ip;
	data = add_head(data, 3+len, inet_ntoa(temp));
    GMN_LOG("%s%s%s","\ndata in defined head: ", data+28+3, "\n");
	msg->size = 3+len+28;
	msg->size = (msg->size)*8; //byte to bit
	msg->data = data;
	msg->rab_id = rab_id;
	msg->ue_id = ue_id;
	//forward_msg(msg);
	send_msg(msg, sizeof(gtp_data_gemini_t), IUH_MOD_ID, IUH_GMN_DL_UU_DATA);

	GMN_LOG("%s", "Send Wifi IP to UE\n");

	return;
}

/**
 * \brief method from protocol, send wifi connect request result to ue
 *
 * \param fd [in] the connection fd under wifi
 * \param flag [in] 0 means success while 1 means failure
 */
static void send_result_m(int32_t fd, uint8_t flag)
{
	uint8_t buf[] = {3, 3, 3, 0};

	if (flag) {
		buf[3] = 'F';
        GMN_LOG("%s", "send wifi connection result: Failure\n");
	} else {
		buf[3] = 'S';
        GMN_LOG("%s", "send wifi connection result: Succecc\n");
	}
	send(fd, (void *)&buf, buf[0]+1, 0);
    GMN_LOG("%s", "result sended\n");
}


/**
 * \brief method from protocol, ue send type-2 to gmn under wifi
 *
 * \param buf [in] the data ue send
 * \param arg->wifi_ip [in] ue's ip about wifi part
 * \param arg->wifi_fd [in] the connect fd about wifi part between ue and gmn
 * \param arg->ue_id [out] the ue_id of the phone connection
 * \param arg->rab_id [out] the rab_id of the phone connection
 *
 * \return 0 means success and others means something wrong
 */
static uint8_t check_wifi_connect_m(uint8_t *buf, struct pthread_arg *arg)
{
	//struct sockaddr_in ue_ip = {0};
    uint32_t ue_ip = 0;
	uint8_t ret = 0;

	GMN_LOG("%s%s","[check wifi connection]\tconnecting 3G IP: ", buf+3);

	//inet_aton((char *)(buf+3), (struct in_addr *)&ue_ip);
    ue_ip = inet_addr((char *)(buf+3));
	//ret = update_ue_wifi_info(ue_ip.sin_addr.s_addr, arg->ip, arg->fd, 
	ret = update_ue_wifi_info(ue_ip, arg->ip, arg->fd, 
			&(arg->ue_id), &(arg->rab_id));
	send_result_m(arg->fd, ret);
	if(ret)
		ret = ERROR_TOR;

	return ret;
}

/**
 * \brief method from protocol, ue send type-21 to gmn 
 *
 * \param buf [in] the data sent by ue
 * \param fd [in] the connect fd
 */
static void forward_data_m(uint8_t *buf, int32_t fd, uint16_t ue_id, 
		uint8_t rab_id)
{
	uint32_t data_len = 0;
	gtp_data_gemini_t *data = (gtp_data_gemini_t *)malloc(sizeof(gtp_data_gemini_t));

	if (ue_id == rab_id && ue_id == 0) {
		GMN_ERR("%s", "[forward CN]\tThere is no ue_id and rab_id when forward data\n");
		return;
	}

	data_len = (*(uint32_t *)(buf+3));
    GMN_LOG("%s%x%s%x%s%x%s", "the defined of head: ",*(buf+0),"\t",*(buf+1),"\t",*(buf+2),"\n");
    GMN_LOG("%s%x%s%x%s%x%s%x%s", "the hex of size: ",*(buf+3),"\t",*(buf+4),"\t",*(buf+5),"\t",*(buf+6),"\n");
	recv(fd, buf+7, data_len, 0);
#ifdef DEBUG
    int i = 0;
    GMN_LOG("%s","the data: ");
    for (i = 0; i < data_len; i++) {
        if (i%8 == 0)
            GMN_LOG("%s", "\n");
        GMN_LOG("%x%s", buf[7+i], "\t");
    }
    GMN_LOG("%s", "\n");
#endif
	data->size = data_len;
    GMN_LOG("%s%d%s","forward data's size is: ", data_len, "\n");
	data->data = buf+7;
	data->ue_id = ue_id;
	data->rab_id = rab_id;
	forward_msg(data);
}

/**
 * \brief method from protocol, ue send type-11 to gmn 
 *
 * \param buf [in] the data sent by ue
 * \param ip [in] the ue's 3g ip address
 */
static void update_divide_info_m(uint8_t *buf, uint32_t ip)
{
	int8_t i = 0;
	int8_t rate = 100;
	int8_t package_wifi = 0;
	int8_t package_3g   = 0;
	GMN_LOG("%s%s", "[3G updata rate]get divide rate info from ue: ", buf);
	while (':' != buf[i]) {
		package_3g = package_3g * 10 + buf[i++] - '0';
	}
	i++;
	while (buf[i]) {
		package_wifi = package_wifi * 10 + buf[i++] - '0';
	}

	rate = 100 * package_3g / (package_3g + package_wifi);
	GMN_LOG("%s%d", "[3G updata rate]the rate is ", rate);
	if(update_ue_3g_info(rate, ip) == 1)
		GMN_ERR("%s%d%s", "can't find the ue which ip is %d", ip, "\n");
}

/**
 * \brief pthread process, communicating with mobile phone under wifi 
 */
static void *connect_ue_wifi_p(void *arg)
{
	struct pthread_arg *arg_t = NULL;
	uint8_t buf[2500] = {0};
	uint8_t ret = 0;

	arg_t = (struct pthread_arg *)arg;
	GMN_LOG("%s", "[wifi]\tconnect a new ue under wifi\n");
	GMN_LOG("%s%d%s", "[wifi]\tThis connection fd: ", arg_t->fd, "\n");

	while (1) {
		if (ERROR_TOR <= ret) {
			GMN_ERR("%s", "wifi connection is going to close\n");
			break;
		}

		bzero(buf, 2500);
		if (recv(arg_t->fd, buf, 1, 0) <= 0 ) {
            perror("failed to recv from wifi -1-: ");
			ret++;
			continue;
		}
		if ( 2 > buf[0]) {
            GMN_ERR("%s","illegal data from wifi =1=\n");
			continue;
		}

		if (recv(arg_t->fd, buf+1, buf[0], 0) <= 0 ) {
            perror("failed to recv from wifi -2-: ");
			ret++;
			continue;
		}
		if ( 2 != buf[1]) {
            GMN_ERR("%s","illegal data from wifi =2=\n");
			continue;
		}
		switch (buf[2]) {
			case 2:
				ret = check_wifi_connect_m(buf, arg_t);
				if (ret == ERROR_TOR)
					GMN_ERR("%s", "check wifi connect failed\n");
				break;
			case 21:
                GMN_LOG("%s","[forward data to CN from wifi]\n");
				forward_data_m(buf, arg_t->fd, arg_t->ue_id, arg_t->rab_id);
				ret = 0;
				break;
			case 4:
				ret = ERROR_TOR;
			default:
				ret++;
				continue;
		}
	}
	close_wifi_connection_m(arg_t->fd, arg_t->ip);
	free(arg);

	return NULL;
}

/**
 * \brief Start listening wifi connection, and deal with the data.
 */
static void *wifi_listener_start_p(void *arg)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	int32_t clientfd = -1;
	pthread_t thread = 0;
	struct pthread_arg *wifi_arg = NULL;

	if (!gmn_3g_ip_s || -1 == listenfd_s) {
		GMN_ERR("%s", "wifi pthread is over due to the wifi hasn't been listened\n");
		return NULL;
	}

	if (listen(listenfd_s, SOMAXCONN) < 0) {
		GMN_ERR("%s", "wifi listen failed\n");
		return NULL;
	}

	while (1) {
		wifi_arg = malloc(sizeof(struct pthread_arg));
		clientfd = accept(listenfd_s, (struct sockaddr *)&addr, &len);
		if (clientfd < 0) {
			GMN_ERR("%s", "[wifi listening] accept failed\n");
			break;
		}
		wifi_arg->fd = clientfd;
		wifi_arg->ip = addr.sin_addr.s_addr;
		wifi_arg->ue_id = 0;
		wifi_arg->rab_id = 0;

		if (0 != pthread_create(&thread, NULL, connect_ue_wifi_p, (void *)wifi_arg)) {
			close(clientfd);
			break;
		} else {
			GMN_LOG("%s","[wifi listening] has created a wifi pthread\n");
			pthread_detach(thread);
		}
	}
	free(wifi_arg);

	return NULL;
}

/**
 * \brief A phone disconnected to station
 *
 * \param ue_info [in] information about the phone 
 *
 * \return If all things are going successfully, zero is returned.
 *         On error, 1 is returned.
 */
static uint8_t del_ue(gmn_ue_info_t *ue_info)
{
#ifdef DEBUG
	GMN_LOG("%s", "[del ue]\tbefore del ue\n");
	show_all_ue_info_d();
	GMN_LOG("%s%d%s%d%s", "[del ue]\tthe deleteing ue_id:", ue_info->ue_id, ",rab_id: ", ue_info->rab_id, "\n");
#endif
	gmn_ue_status_t ue_status;

	ue_status.ue_id = ue_info->ue_id;
	ue_status.rab_id = ue_info->rab_id;
	ue_status.capability = 0x00;
	ue_status.rate = 100;
	ue_status.wifi_ip = 0;

	// update_msg(&ue_status);

	ue_info_remove(ue_info->ue_id);

#ifdef DEBUG
	GMN_LOG("%s","[del ue]\tafter deleted\n");
	show_all_ue_info_d();
#endif
	return 0;
}

/**
 * \brief A new phone connected to station
 *
 * \param ue_info [in] information about new ue
 *
 * \return If all things are going successfully, zero is returned.
 *         On error, 1 is returned.
 */
static uint8_t add_ue(gmn_ue_info_t *ue_info)
{
	if (NULL == ue_info) {
		GMN_ERR("%s", "the msg data is NULL \n");
		return 1;
	}
	gmn_ue_status_t ue_status;

	GMN_LOG("%s", "[add ue]\t in add_ue \n");

	del_ue(ue_info);

	//send_wifi_ip_m(ue_info->ue_ip, ue_info->rab_id, ue_info->ue_id);

	ue_status.ue_id = ue_info->ue_id;
	ue_status.rab_id = ue_info->rab_id;
	ue_status.capability = 0x00;
	ue_status.rate = 100;
	ue_status.wifi_ip = 0;

	ue_info_create(&ue_status, ue_info->ue_ip, -1, -1);
	// update_msg(&ue_status);

#ifdef DEBUG
	GMN_LOG("%s", "[add ue]\tadded\n");
	show_all_ue_info_d();
#endif
	return 0;
}

//static void get_data(uint8_t *data, uint32_t *len, uint8_t rab_id, uint16_t ue_id)
static void get_data(gtp_data_gemini_t *data)
{
	uint32_t *temp = NULL;
	uint8_t swap_buf[2500] = {0};
	uint8_t *head_len = NULL;
	temp = (uint32_t *)(data->data+16);
	struct sockaddr_in dip = {0};
	dip.sin_addr.s_addr = *temp;
	GMN_LOG("%s%s", "destination ip in IP head: ", inet_ntoa(dip.sin_addr));

	struct sockaddr_in ip_addr_t = {0};
	ip_addr_t.sin_addr.s_addr = flag_ip_s;
	GMN_LOG("%s%s", " UDP's flag ip: ",	inet_ntoa(ip_addr_t.sin_addr));
	ip_addr_t.sin_addr.s_addr = *(uint32_t *)(data->data+12);
	GMN_LOG("%s%s%s", " source ip in IP head: ",	inet_ntoa(ip_addr_t.sin_addr), "\n");

	if (flag_ip_s == *temp)
		GMN_LOG("%s", "\n\n\n\nflag ip == dest ip\n\n\n\n");
	else 
	{
		GMN_LOG("%s", "flag ip != dest ip)");
		forward_msg(data);
		return;
	}

	GMN_LOG("%s", "Going to deal with the UDP data\n");
	switch (*(uint8_t *)(data->data+28+2)) {
		case 0:
            GMN_LOG("%s", "Get case 0, begin to send wifi ip to ue\n");
            int j = 0;
            for(j = 0; j < 30; j++) {
                send_wifi_ip_m(*(uint32_t *)(data->data+12), data->rab_id, data->ue_id);
            }
            free(data->data);
            break;
		case 11:
			update_divide_info_m(data->data+28+3, *(uint32_t *)(data->data+12));
			free(data->data);
			break;
		case 21: 
		    gtp_data_gemini_t *msg = (gtp_data_gemini_t *)malloc(sizeof(gtp_data_gemini_t));
			head_len = data->data+28;
#ifdef DEBUG
            int i = 0;
            GMN_LOG("%s","the defined head: ");
            for (i = 0; i < 28+1+*head_len; i++) {
                if (i%8 == 0)
                    GMN_LOG("%s", "\n");
                GMN_LOG("%x%s", data->data[i], "\t");
            }
            GMN_LOG("%s", "\n");
#endif
			data->size = data->size - 28 - 1 - *head_len;
            memcpy(swap_buf, data->data+28+1+*head_len, data->size);
            memcpy(data->data, swap_buf, data->size);
            msg->size = data->size;
            msg->ue_id = data->ue_id;
            msg_rab_id = data->rab_id;
            msg->data = data->data;
#ifdef DEBUG
            GMN_LOG("%s","[forward data to CN from 3G]\n");
            GMN_LOG("%s%d%s", "data size is :", msg->size, "\n");
            i = 0;
            GMN_LOG("%s","the data: ");
            for (i = 0; i < msg->size; i++) {
                if (i%8 == 0)
                    GMN_LOG("%s", "\n");
                GMN_LOG("%x%s", msg->data[i], "\t");
            }
            GMN_LOG("%s", "\n");
#endif
			forward_msg(msg);
			break;
		case 4:
			ue_info_remove_by_ip(*(uint32_t *)(data-28+12));
			free(data->data);
		default:
			GMN_ERR("%s", "There is something wrong dealing with the UDP data\n");
			break;
	}
	//head_len = data;
	//data = data + 1 + *head_len;

	//*len = *len - 28 - 1 - *head_len;
}

/**
 * \brief Get the message and deal with it.
 *
 * \param msg [in] Message received.
 */
static void msg_handler(struct ftl_msg *msg_p)
{
	ftl_msg_t *msg =(ftl_msg_t *)msg_p;
	uint32_t type = 1;
	gtp_data_gemini_t *data = NULL;

	GMN_LOG("%s%x", "[msg handler]\tGet message from mod: 0x", msg->mod);
	GMN_LOG("%s%x%s%u%s", " msgid: 0x", msg->msgid, ", msg len: ",  msg->len,"\n");
	switch (msg->msgid) {

		case GMN_IUH_UL_UU_DATA:
			GMN_LOG("%s", "GMN_IUH_UL_UU_DADTA\n");
			data = (gtp_data_gemini_t *)ftl_msg_get_ext((struct ftl_msg *)msg, type, NULL);
			if(data == NULL) {
				GMN_ERR("%s", "it is here,cannot get  msg.########\n");
				break;
			}
			get_data(data);
			//get_data(data->data, &(data->size), data->rab_id, data->ue_id);
			//forward_msg(data);

			GMN_LOG("%s", "Finish send GMN_IUH_UL_UU_DATA message!\n");

			break;

		case GMN_IUH_DL_IU_DATA:
			GMN_LOG("%s", "msg:GMN_IUH_DL_IU_DADTA\n");
			data = (gtp_data_gemini_t *)ftl_msg_get_ext((struct ftl_msg *)msg, type, NULL);
			if(data == NULL) {
				GMN_ERR("%s", "it is here,cannot get  msg.########\n");
				break;
			}
			divide_msg(data);
			break;

		case GMN_IUH_ADD_UE_INFO:

			GMN_LOG("%s", "GMN_IUH_ADD_UE_INFO\n");
			data = (gtp_data_gemini_t *)ftl_msg_get_ext((struct ftl_msg *)msg, type, NULL);
			add_ue((gmn_ue_info_t *)data);
			break;

		case GMN_IUH_DEL_UE_INFO:

			GMN_LOG("%s", "GMN_IUH_DEL_UE_INFO\n");
			data = (gtp_data_gemini_t *)ftl_msg_get_ext((struct ftl_msg *)msg, type, NULL);
			del_ue((gmn_ue_info_t *)data);
			break;

		default:
			break;
	}
}

/**
 * \brief Register gemini module into message framework.
 *
 * \return If all things are going successfully, zero is returned.
 *         On error, 1 is returned.
 */
static uint8_t gmn_mod_reg()
{
	ftl_msg_mod_cfg_t msg_cfg = {0};
	uint8_t ret = 0;

	msg_cfg.id = GMN_MOD_ID;
	msg_cfg.handler = msg_handler;
	msg_cfg.ident = NULL;
	msg_cfg.enable_ipc = 0;
	msg_cfg.name = "gemini_module";
	msg_cfg.module_priority = FTL_MSG_MODULE_PRIORITY_DEFAULT;

	if (FTL_MSG_RST_SUCCESS != ftl_msg_module_reg(&msg_cfg)) {
		GMN_ERR("%s", "msg framework reg failed\n");
		ret = 1;
	}

	return ret;
}

/*=======================================STOP===============================*/

/**
 * \brief Free all ue connection and close all socket
 */
static uint8_t ue_info_free_all(void)
{
	ue_info_t *back = NULL;

	while (NULL != ue_info_head_s) {
		back = ue_info_head_s;
		ue_info_head_s = back->next;
		//		close(back->ue_fd);
		close(back->wifi_fd);
		free(back);
	}

	return 0;
}

/*=======================================GLOBAL===============================*/

/**
 * \brief Initialize the gemini module, including 3g and wifi.
 */
gmn_mod_rst_t gemini_init(void)
{
	uint8_t ret = 0;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
    signal(SIGPIPE, sig_handler);

	ret = gmn_3g_init();
	ret += gmn_wifi_init();

	if (0 < ret) {
		GMN_ERR("%s%d%s", "the init return value: ", ret, "\n");
		GMN_ERR("%s", " Initialize gemini module failed.\n");
		return GMN_RST_INIT_FAILURE;
	}
	gemini_init_flag_s = 1;
	GMN_LOG("%s", " Initialize gemini module success.\n");
	return GMN_MOD_RST_SUCCESS;
}

/**
 * \brief Start gemini module.
 *
 * \return GMN_RST_NOT_INIT: Haven't exec gemini_init()
 *         GMN_MOD_RST_FAILURE: Register gemini module into msg framework failed
 *         GMN_MOD_RST_SUCCESS: Everything seems ok
 */
gmn_mod_rst_t gemini_start(void)
{
	if (0 == gemini_init_flag_s) {
		GMN_ERR("%s", "Gemini hasn't been inited");
		return GMN_RST_NOT_INIT;
	}

	if (0 != gmn_mod_reg()) {	
		GMN_ERR("%s"," Register gemini module into message framework failed.\n");
		return GMN_MOD_RST_FAILURE;
	}
	GMN_LOG("%s"," Register gemini module into message framework success.\n");

	if (0 != pthread_create(&wifi_listen_p_s, NULL, wifi_listener_start_p, NULL)) {
		wifi_listen_p_s =  0;
		GMN_ERR("%s"," Create pthread about Listening wifi failed.\n");
		return GMN_MOD_RST_FAILURE;
	} else {
		if (!gmn_3g_ip_s || -1 == listenfd_s) {
			GMN_LOG("%s","Not start wifi module\n");
		} else {
			GMN_LOG("%s","start listening wifi\n");
		}
		pthread_detach(wifi_listen_p_s);
	}
	GMN_LOG("%s", "gemini has been started\n");
	return GMN_MOD_RST_SUCCESS;
}

/**
 * \brief Stop gemini module.
 *
 * \return GMN_MOD_RST_FAILURE: Deregister gemini module failed.
 *         GMN_MOD_RST_SUCCESS: Everything seems ok.
 */
gmn_mod_rst_t gemini_stop(void)
{
	if (listenfd_s != -1) {
		close(listenfd_s);
		listenfd_s = -1;
	}

	ue_info_free_all();

	if (FTL_MSG_RST_SUCCESS != ftl_msg_module_dereg(GMN_MOD_ID)) {
		return GMN_MOD_RST_FAILURE;
	}

	return GMN_MOD_RST_SUCCESS;
}

/**
 * \brief Destory gemini module.
 *
 * \return GMN_MOD_RST_FAILURE: Deinit ftl msg failed.
 *         GMN_MOD_RST_SUCCESS: Everything seems ok.
 */
gmn_mod_rst_t gemini_deinit(void)
{
	ue_info_free_all();

	if (listenfd_s != -1) {
		close(listenfd_s);
		listenfd_s = -1;
	}

	if (FTL_MSG_RST_SUCCESS != ftl_msg_deinit()) {
		return GMN_MOD_RST_FAILURE;
	}

	return GMN_MOD_RST_SUCCESS;
}
/*
int32_t main(int argc, char *argv[])
{
	if (GMN_MOD_RST_SUCCESS != gemini_init()) {
		gemini_deinit();
		return(EXIT_FAILURE); 
	}

	if (GMN_MOD_RST_SUCCESS != gemini_start()) {
		gemini_stop();
		gemini_deinit();
		return(EXIT_FAILURE);
	}

	pause();

	return 0;
}

*/
