#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include "ftl_msg.h"
#include "gmn_mod.h" 
#ifndef LIBSC_ERROR
#define LIBSC_ERROR printf
#endif

struct g_sta {
    int msg_recved;
} g_sta = { .msg_recved = 0 };

struct g_conf {
    ftl_mod_id_t    mod;
    size_t          msg_excepted;
    int             hdl_delay;
    uint8_t         idc_init : 1;
    uint8_t         quiet : 1;
} g_conf = { .mod = 2,
             .msg_excepted = 0,
             .hdl_delay = 0,
             .idc_init = 0,
             .quiet = 0
};

static void sig_handler(int sig)
{
    printf("Totally received %d messages\n", g_sta.msg_recved);
    signal(sig, SIG_DFL);
    ftl_msg_module_dereg(g_conf.mod);
    ftl_msg_deinit();

    exit(EXIT_SUCCESS);
}

static void msg_handler(struct ftl_msg *msg)
{
    static unsigned int msg_received = 0;
	gmn_ue_status_t *data = NULL;
	uint32_t len = 0;

    g_sta.msg_recved++;

    if (g_conf.msg_excepted > 1) {
        msg_received++;
        if (1 == msg_received) {
            /* First message */
            return;
        } else if (msg_received < g_conf.msg_excepted) {
            return;
        } else {
            msg_received = 0;
        }
    } else {
        if (!g_conf.quiet) {
            printf("Get message from mod: 0x%02hhx, msgid: 0x%02hhx, msg len: %u\n",
                    msg->mod, msg->msgid, msg->len);
			data = (gmn_ue_status_t *)ftl_msg_get_ext(msg, 1, &len);
			printf("get update ue info request from gmn\n");
			printf("ue_id is: %d\n", data->ue_id);
			printf("rab_id is: %d\n", data->rab_id);
			printf("capability is: %d\n", data->capability);
			printf("rate is: %d\n", data->rate);
			printf("wifi_ip is: %d\n", data->wifi_ip);
        }
    }
}

static int mod_reg(void)
{
    ftl_msg_mod_cfg_t msg_cfg = {0};
    msg_cfg.id              = g_conf.mod;
    msg_cfg.handler         = msg_handler;
    msg_cfg.ident           = NULL;
    msg_cfg.enable_ipc      = 1;
    msg_cfg.name            = "msg_test";
    msg_cfg.module_priority = FTL_MSG_MODULE_PRIORITY_DEFAULT;

    if(ftl_msg_module_reg(&msg_cfg) != FTL_MSG_RST_SUCCESS)
    {
        LIBSC_ERROR(" Register module into message framework failed.\n");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (FTL_MOD_ID_UNKNOW == g_conf.mod) {
        fprintf(stderr, "Invalid module id\n");
        exit(EXIT_FAILURE);
    }

    if (ftl_msg_init() != FTL_MSG_RST_SUCCESS)
    {
        LIBSC_ERROR(" Initialize msg failed.\n");
        exit(EXIT_FAILURE);
    }

    if (mod_reg() != 0)
    {
        ftl_msg_deinit();
        exit(EXIT_FAILURE);
    }

    pause();

    return 0;
}
