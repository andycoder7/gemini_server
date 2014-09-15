#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <signal.h>
#include "ftl_msg.h"
#include "gmn_mod.h"
#ifndef LIBSC_ERROR
#define LIBSC_ERROR printf
#endif

static int stop_send = 0;

struct g_sta {
    int msg_sent;
} g_sta = { .msg_sent = 0 };

struct g_conf {
    ftl_mod_id_t    src_mod;
    ftl_mod_id_t    dst_mod;
    uint32_t        msg_id;
    ftl_msg_pri_t   msg_pri;
    size_t          msg_body_size;
    size_t          send_msg_cnt;
    size_t          wait_interval;
    char            *p_idc_addr;
    uint8_t         idc_init : 1;
    uint8_t         uninterruped : 1;
} g_conf = { .src_mod = FTL_MOD_ID_UNKNOW,
             .dst_mod = FTL_MOD_ID_UNKNOW,
             .msg_id = 1,
             .msg_pri = FTL_MSG_PRI_DEFAULT,
             .msg_body_size = 0,
             .send_msg_cnt = 1,
             .wait_interval = 0,
             .p_idc_addr = NULL,
             .idc_init = 0,
             .uninterruped= 0
};

static void exit_hdl(void)
{
    if (g_conf.idc_init) {
        ftl_msg_idc_deinit();
    }

    ftl_msg_deinit();

    exit(EXIT_SUCCESS);
}

static void sig_hdl(int sig)
{
    signal(sig, SIG_DFL);
    stop_send = 1;
}

int main(int argc, char *argv[])
{
    struct ftl_msg *msg = NULL;
    int i;
    struct timeval time_before_sending, time_after_sending;

	printf("number of argument: %d\n", argc);
	if (argc < 2) {
		printf("please add argument about msgid!\n");
		return 0;
	}

    signal(SIGINT, sig_hdl);

	g_conf.src_mod = 1;
	g_conf.dst_mod = 35;
	g_conf.send_msg_cnt = 1;

    if (ftl_msg_init() != FTL_MSG_RST_SUCCESS) {
        LIBSC_ERROR(" Initialize msg failed.\n");
        exit(EXIT_FAILURE);
    }

    gettimeofday(&time_before_sending, NULL);
    for (i = 0; !stop_send && (g_conf.uninterruped || (i < g_conf.send_msg_cnt)); i++) {
		int msg_id = argv[1][0] - '0';
		char *test1 = "what the fuck!";
		char *test2 = "what the fuck!";
		gmn_ue_info_t test5 = {.ue_id = 88, .rab_id=55, .ue_ip=0 };
		gmn_ue_info_t test6 = {.ue_id = 88, .rab_id=66, .ue_ip=0 };
		switch (msg_id) {
		case 1: 
			printf("send msg with msgid %d %s\n", msg_id, test1);
			msg = ftl_msg_create_ex(strlen(test1)+1, g_conf.src_mod, msg_id, NULL, NULL);
			ftl_msg_add_ext(msg, 1, strlen(test1)+1, (void *)test1, 0);
			msg->flag |= g_conf.msg_pri;
			if (ftl_msg_send(g_conf.dst_mod, msg) == FTL_MSG_RST_SUCCESS) {
				g_sta.msg_sent++;
			} else {
				ftl_msg_delete(msg);
			}	
			break;
		case 3: 
			printf("send msg with msgid %d %s\n", msg_id, test2);
			msg = ftl_msg_create_ex(strlen(test2)+1, g_conf.src_mod, msg_id, NULL, NULL);
			ftl_msg_add_ext(msg, 1, strlen(test2)+1, (void *)test2, 0);
			msg->flag |= g_conf.msg_pri;
			if (ftl_msg_send(g_conf.dst_mod, msg) == FTL_MSG_RST_SUCCESS) {
				g_sta.msg_sent++;
			} else {
				ftl_msg_delete(msg);
			}
			break;
		case 5: 
			printf("send msg with msgid %d\n", msg_id);
			msg = ftl_msg_create_ex(sizeof(gmn_ue_info_t), g_conf.src_mod, msg_id, NULL, NULL);
			ftl_msg_add_ext(msg, 1, sizeof(gmn_ue_info_t), (void *)&test5, 0);
			msg->flag |= g_conf.msg_pri;
			if (ftl_msg_send(g_conf.dst_mod, msg) == FTL_MSG_RST_SUCCESS) {
				g_sta.msg_sent++;
			} else {
				ftl_msg_delete(msg);
			}
			break;
		case 6: 
			printf("send msg with msgid %d\n", msg_id);
			msg = ftl_msg_create_ex(sizeof(gmn_ue_info_t), g_conf.src_mod, msg_id, NULL, NULL);
			ftl_msg_add_ext(msg, 1, sizeof(gmn_ue_info_t), (void *)&test6, 0);
			msg->flag |= g_conf.msg_pri;
			if (ftl_msg_send(g_conf.dst_mod, msg) == FTL_MSG_RST_SUCCESS) {
				g_sta.msg_sent++;
			} else {
				ftl_msg_delete(msg);
			}
			break;
		default:
			printf("the msg id %d hasn't been defined\n", msg_id);
		}
    
    }
    gettimeofday(&time_after_sending, NULL);

    printf("Spend %ld us for sending %u message(s)\n",
            (1000000 * (time_after_sending.tv_sec - time_before_sending.tv_sec) + (time_after_sending.tv_usec - time_before_sending.tv_usec)),
            g_sta.msg_sent);

    /* Wait to send all message */
    sleep(1);

    exit_hdl();
    return 0;
}
