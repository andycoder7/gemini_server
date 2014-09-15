/*
 * Copyright (c) 2010 SerComm Corporation. All Rights Reserved.
 *
 * SerComm Corporation reserves the right to make changes to this document
 * without notice. SerComm Corporation makes no warranty, representation or
 * guarantee regarding the suitability of its products for any particular
 * purpose. SerComm Corporation assumes no liability arising out of the
 * application or use of any product or circuit. SerComm Corporation
 * specifically disclaims any and all liability, including without limitation
 * consequential or incidental damages; neither does it convey any license
 * under its patent rights, nor the rights of others.
 */

/**
 * \file ftl_log.h
 *
 * APIs for ftl_log
 *
 * \author Jerry Hu <jerry_hu@sdc.sercomm.com>
 *
 * \date 2011-04-20
 */
#ifndef FTL_LOG_H
#define FTL_LOG_H

#include <stdint.h>

#include "ftl_generic.h"
#include "ftl_msg.h"

/**
 * \defgroup ftl_log [ftl_log] Log APIs.
 * @{
 */

/**
 * \brief Log module type.
 */
typedef uint32_t ftl_log_mod_id_t;

/**
 * \brief Allowed maximum number of log module.
 */
#define FTL_LOG_MOD_ID_NUM      (128)

/**
 * \brief Levels definition for log.
 *
 * Log level type is 16bit unsigned integer, the low bit is reserved for user
 * to define ones own level, the high type is for log level mask use, so one
 * can ORed different level together to show intentd log message.
 */
typedef enum ftl_log_lvl {
    FTL_LOG_LVL_DEBUG = 0x0100, /*!< debug level used for debug purpose
                                  information. */
    FTL_LOG_LVL_FUNC  = 0x0200, /*!< function level used for trace function
                                  call, etc */
    FTL_LOG_LVL_INFO  = 0x0400, /*!< information level used for general
                                  information */
    FTL_LOG_LVL_USER  = 0x0800, /*!< user defined level */
    FTL_LOG_LVL_WARN  = 0x1000, /*!< warnning message level */
    FTL_LOG_LVL_ERROR = 0x2000, /*!< error message level */
    FTL_LOG_LVL_PANIC = 0x4000, /*!< panic message level */
} ftl_log_lvl_t;

/**
 * \brief Second level tlv types for LOG tlv.
 */
/* FIXME this defintion could be defined private */
typedef enum ftl_log_tlv {
    FTL_LOG_TYPEID_MODULE = 0x1001, /*!< The tlv contains module information */
    FTL_LOG_TYPEID_LEVEL  = 0x1002, /*!< The tlv contains level information */
    FTL_LOG_TYPEID_TS_S   = 0x1003, /*!< The tlv contains timestamp(s)
                                      information */
    FTL_LOG_TYPEID_UEID   = 0x1004, /*!< the tlv contains ueid information */
    FTL_LOG_TYPEID_SEQ    = 0x1005, /*!< the tlv contains sequence information */
    FTL_LOG_TYPEID_CODE   = 0x1006, /*!< the tlv contains code information */
    FTL_LOG_TYPEID_TS_MS  = 0x1008, /*!< the tlv contains timestamp(ms) information */
} ftl_log_tlv_t;

/**
 * \brief Parameter types for LOG tlv.
 */
/* FIXME this defintion could be defined private */
typedef enum ftl_log_param {
    FTL_LOG_PARAM_STRING  = 0x1101, /*!< string parameter */
    FTL_LOG_PARAM_INTEGER = 0x1102, /*!< integer parameter */
    FTL_LOG_PARAM_FLOAT   = 0x1103, /*!< float parameter */
} ftl_log_param_t;

/**
 * \brief log API return result.
 */
typedef enum ftl_log_rst {
    FTL_LOG_RST_SUCCESS,
    FTL_LOG_RST_FAILURE,
} ftl_log_rst_t;

/**
 * \brief initialize log library.
 *
 * This function must be called before use any function this module provided.
 *
 * \return FTL_LOG_RST_SUCCESS on success, failed otherwise.
 */
ftl_log_rst_t ftl_log_init(void);

/**
 * \brief deinitialize log library.
 *
 * \return FTL_LOG_RST_SUCCESS on success, failed otherwise.
 */
ftl_log_rst_t ftl_log_deinit(void);

/**
 * \brief Get version information of this module.
 */
char *ftl_log_get_version(void);

/**
 * \brief API used for logging a loging message.
 *
 * \param mod [in] module id defined in ftl_general.h
 * \param code [in] code represent a tracing message.
 * \param level [in] tracing message level.
 * \param ueid [in] ue identity
 * \param param [in] printf like parameter transcode.
 * \param ... [in] real parameter specified in "param"
 */
#define FTL_LOG(mod, code, level, ueid, param, ...) \
    ftl_log_msg_commit(ftl_log_msg_new_ex(mod, code, level, ueid, param, ##__VA_ARGS__))

/**
 * \brief State & Information type.
 */
typedef enum {
    FTL_LOG_STAT_INFO_UNKNOW    = 0x0000,
    FTL_LOG_STAT_INFO_CPU       = 0x0001,     /*!< CPU usage information */
    FTL_LOG_STAT_INFO_MEM       = 0x0002,     /*!< MEM usage information */
    FTL_LOG_STAT_INFO_TUN       = 0x0003,     /*!< IPsec tunnel infomation */
    FTL_LOG_STAT_INFO_UE        = 0x0004,     /*!< UE state information */
    FTL_LOG_STAT_INFO_RTWP      = 0x0005,
    FTL_LOG_STAT_INFO_HNB_TX_CARRIER_POWER  = 0x0006,
    FTL_LOG_STAT_INFO_PCPICH_POWER          = 0x0007,
    FTL_LOG_STAT_INFO_IKE       = 0x0008,     /*!< IPsec IKE infomation */
    /**
     * This part were included in UE state.
     */
    FTL_LOG_STAT_INFO_UE_MEAS   = 0x0009,

    FTL_LOG_STAT_INFO_MAX
} ftl_log_stat_info_t;

/**
 * \brief CPU information.
 */
typedef struct ftl_log_cpu_info {
    uint8_t cpu0;                       /*!< CPU0 usage pecentage (0~100) */
} ftl_log_cpu_info_t;

/**
 * \brief MEM information.
 */
typedef struct ftl_log_mem_info {
    uint8_t total;                      /*!< Total memory installed(MB) */
    uint8_t used;                       /*!< Used memory(MB) */
} ftl_log_mem_info_t;

/**
 * \brief information for tunnel.
 *
 * used by ftl_log daemon itself to prepare for PDT TLV 
 * NOTE: differs from struct ftl_logd_ipsec_tun_info defined in ftl_log_daemon.h
 */
typedef struct ftl_log_tun_info {
    char    *spi;
    enum {
        FTL_LOG_ESP_ENCR_NULL              = 0,  /* NULL */
        FTL_LOG_ESP_ENCR_TripleDES_CBC     = 1,  /* tripleDES-CBC [RFC2451] */
        FTL_LOG_ESP_ENCR_AES_CBC           = 2,  /* AES-CBC [RFC3602] */
        FTL_LOG_ESP_ENCR_AES_CTR           = 3,  /* AES-CTR [RFC3686] */
        FTL_LOG_ESP_ENCR_DES_CBC           = 4,  /* DES-CBC [RFC2405] */
        FTL_LOG_ESP_ENCR_CAST5_CBC         = 5,  /* CAST5-CBC [RFC2144] */
        FTL_LOG_ESP_ENCR_BLOWFISH_CBC      = 6,  /* FLOWFISH-CBC [RFC2451] */
        FTL_LOG_ESP_ENCR_TWOFISH_CBC       = 7,  /* TWOFISH-CBC */
    } encr_alg;
    enum {
        FTL_LOG_ESP_AUTH_NULL              = 0,  /* NULL */
        FTL_LOG_ESP_AUTH_HMAC_SHA_1_96     = 1,  /* HMAC-SHA-1-96 [RFC2404] */
        FTL_LOG_ESP_AUTH_HMAC_SHA_256_96   = 2,  /* HMAC-SHA-256-96 [draft-ietf-ipsec-ciph-sha-256-00] */
        FTL_LOG_ESP_AUTH_HMAC_SHA_256_128  = 3,  /* HMAC-SHA-256-128 [RFC4868] */
        FTL_LOG_ESP_AUTH_HMAC_MD5_96       = 4,  /* HMAC-SHA-MD5-96 [RFC2403] */
        FTL_LOG_ESP_AUTH_MAC_RIPEMD_160_96 = 5,  /* MAC-RIPEMD-160-96 [RFC2857] */
        FTL_LOG_ESP_AUTH_ANY_96            = 6,  /* ANY 96 bit authentication [no-checking] */
        FTL_LOG_ESP_AUTH_ANY_128           = 7,  /* ANY 128 bit authentication [no-checking] */
        FTL_LOG_ESP_AUTH_ANY_192           = 8,  /* ANY 192 bit authentication [no-checking] */
        FTL_LOG_ESP_AUTH_ANY_256           = 9,  /* ANY 256 bit authentication [no-checking] */
    } auth_alg;
    char    *encr_key;
    char    *auth_key;
    int     type;
} ftl_log_tun_info_t;

/**
 * \brief information for IKE.
 *
 * used by ftl_log daemon itself to prepare for PDT TLV 
 * NOTE: differs from struct ftl_logd_ipsec_ike_info defined in ftl_log_daemon.h
 */
typedef struct ftl_log_ike_info {
    char    *spi_i;
    char    *spi_r;
    enum {
        FTL_LOG_IKE_ENC_TripleDES     = 0,  /* 3DES [RFC2451] */
        FTL_LOG_IKE_ENC_AES_CBC_128   = 1,  /* AES-CBC-128 [RFC3602] */
        FTL_LOG_IKE_ENC_AES_CBC_192   = 2,  /* AES-CBC-192 [RFC3602] */
        FTL_LOG_IKE_ENC_AES_CBC_256   = 3,  /* AES-CBC-256 [RFC3602] */
        FTL_LOG_IKE_ENC_NULL          = 4,  /* NULL */
    } enc_alg;
    enum {
        FTL_LOG_IKE_INT_HMAC_MD5_96   = 0,  /* HMAC-SHA-MD5-96 [RFC2403] */
        FTL_LOG_IKE_INT_HMAC_SHA_1_96 = 1,  /* HMAC-SHA-1-96 [RFC2404] */
        FTL_LOG_IKE_INT_NONE          = 2,  /* NONE[RFC4306] */
        FTL_LOG_IKE_INT_ANY_96        = 3,  /* ANY 96 bit authentication [no-checking] */
        FTL_LOG_IKE_INT_ANY_128       = 4,  /* ANY 128 bit authentication [no-checking] */
        FTL_LOG_IKE_INT_ANY_160       = 5,  /* ANY 160 bit authentication [no-checking] */
        FTL_LOG_IKE_INT_ANY_192       = 6,  /* ANY 192 bit authentication [no-checking] */
        FTL_LOG_IKE_INT_ANY_256       = 7,  /* ANY 256 bit authentication [no-checking] */
    } int_alg;
    char    *sk_ei;
    char    *sk_er;
    char    *sk_ai;
    char    *sk_ar;
} ftl_log_ike_info_t;
#if 0
typedef enum {
    FTL_LOG_UE_RAB_CS_12_2K         = 0,
    FTL_LOG_UE_RAB_CS_64K           = 1,
    FTL_LOG_UE_RAB_PS_32K           = 2,
    FTL_LOG_UE_RAB_PS_64K           = 3,
    FTL_LOG_UE_RAB_PS_128K          = 4,
    FTL_LOG_UE_RAB_PS_384K          = 5,
    FTL_LOG_UE_RAB_PS_HSDPA_3_6M    = 6,
    FTL_LOG_UE_RAB_PS_HSUPA_3_6M    = 7,
    FTL_LOG_UE_RAB_PS_HSDPA_5_4M    = 8,
    FTL_LOG_UE_RAB_PS_HSUPA_5_4M    = 9,
    FTL_LOG_UE_RAB_PS_HSDPA_7_2M    = 10,
    FTL_LOG_UE_RAB_PS_HSUPA_7_2M    = 11,
    FTL_LOG_UE_RAB_PS_HSDPA_10_8M   = 12,
    FTL_LOG_UE_RAB_PS_HSUPA_10_8M   = 13,
    FTL_LOG_UE_RAB_PS_HSDPA_14_4M   = 14,
    FTL_LOG_UE_RAB_PS_HSUPA_14_4M   = 15,
    FTL_LOG_UE_RAB_PS_16K           = 16,
    FTL_LOG_UE_RAB_CS_7_95K         = 17,
} ftl_log_ue_rab_type_e;/*removed,current supported ftl_log_ue_rab_type2_e*/
#endif

typedef enum {
    FTL_LOG_UE_RAB2_CS_12_2K         = 0,
    FTL_LOG_UE_RAB2_CS_64K,
    FTL_LOG_UE_RAB2_PS_32K,
    FTL_LOG_UE_RAB2_PS_64K,
    FTL_LOG_UE_RAB2_PS_128K,
    FTL_LOG_UE_RAB2_PS_384K,
    FTL_LOG_UE_RAB2_PS_8K,
    FTL_LOG_UE_RAB2_PS_16K,
    FTL_LOG_UE_RAB2_HSDPA_CAT1_1_2M = 20,
    FTL_LOG_UE_RAB2_HSDPA_CAT2_1_2M,
    FTL_LOG_UE_RAB2_HSDPA_CAT3_1_8M,
    FTL_LOG_UE_RAB2_HSDPA_CAT4_1_8M,
    FTL_LOG_UE_RAB2_HSDPA_CAT5_3_65M,
    FTL_LOG_UE_RAB2_HSDPA_CAT6_3_65M,
    FTL_LOG_UE_RAB2_HSDPA_CAT7_7_2M,
    FTL_LOG_UE_RAB2_HSDPA_CAT8_7_2M,
    FTL_LOG_UE_RAB2_HSDPA_CAT9_10_1M,
    FTL_LOG_UE_RAB2_HSDPA_CAT10_14_0M,
    FTL_LOG_UE_RAB2_HSDPA_CAT11_900K,
    FTL_LOG_UE_RAB2_HSDPA_CAT12_1_8M,
    FTL_LOG_UE_RAB2_HSDPA_CAT13_17_6M,
    FTL_LOG_UE_RAB2_HSDPA_CAT14_21_1M,
    FTL_LOG_UE_RAB2_HSDPA_CAT15_11_7M,
    FTL_LOG_UE_RAB2_HSDPA_CAT15_23_4M,
    FTL_LOG_UE_RAB2_HSDPA_CAT16_14_0M,
    FTL_LOG_UE_RAB2_HSDPA_CAT16_28_0M,
    FTL_LOG_UE_RAB2_HSDPA_CAT17_17_6M,
    FTL_LOG_UE_RAB2_HSDPA_CAT17_23_4M,
    FTL_LOG_UE_RAB2_HSDPA_CAT18_21_1M,
    FTL_LOG_UE_RAB2_HSDPA_CAT18_28_0M,
    FTL_LOG_UE_RAB2_HSDPA_CAT19_35_3M,
    FTL_LOG_UE_RAB2_HSDPA_CAT20_42_2M,
    FTL_LOG_UE_RAB2_HSDPA_CAT21_23_4M,
    FTL_LOG_UE_RAB2_HSDPA_CAT22_28_0M,
    FTL_LOG_UE_RAB2_HSDPA_CAT23_35_3M,
    FTL_LOG_UE_RAB2_HSDPA_CAT24_42_2M,
    FTL_LOG_UE_RAB2_HSDPA_CAT25_46_7M,
    FTL_LOG_UE_RAB2_HSDPA_CAT26_55_9M,
    FTL_LOG_UE_RAB2_HSDPA_CAT27_70_6M,
    FTL_LOG_UE_RAB2_HSDPA_CAT28_84_4M,
    FTL_LOG_UE_RAB2_HSUPA_CAT1_0_7M = 100,
    FTL_LOG_UE_RAB2_HSUPA_CAT2_1_4484M,
    FTL_LOG_UE_RAB2_HSUPA_CAT2_1_399M,
    FTL_LOG_UE_RAB2_HSUPA_CAT3_1_4484M,
    FTL_LOG_UE_RAB2_HSUPA_CAT4_2_0M,
    FTL_LOG_UE_RAB2_HSUPA_CAT4_2_2886M,
    FTL_LOG_UE_RAB2_HSUPA_CAT5_2_0M,
    FTL_LOG_UE_RAB2_HSUPA_CAT6_2_0M,
    FTL_LOG_UE_RAB2_HSUPA_CAT6_5_742M,
    FTL_LOG_UE_RAB2_HSUPA_CAT7_2_0M,
    FTL_LOG_UE_RAB2_HSUPA_CAT7_11_498M,
} ftl_log_ue_rab_type2_e;

/**
 * \brief UE status information.
 */
typedef struct ftl_log_ue_info {
    int     ueid;
    enum {
        FTL_LOG_UE_UEID   = 0x0001,
        FTL_LOG_UE_RAB    = 0x0002,
        FTL_LOG_UE_RRC    = 0x0003,
        FTL_LOG_UE_IMSI   = 0x0004,
        FTL_LOG_UE_RAB2   = 0x0005,
    } type;
    union {
        char    *imsi;
        enum {
            FTL_LOG_UE_RRC_IDLE      = 0,
            FTL_LOG_UE_RRC_CELL_DCH  = 1,
            FTL_LOG_UE_RRC_CELL_FACH = 2,
            FTL_LOG_UE_RRC_CELL_PCH  = 3,
            FTL_LOG_UE_RRC_URA_PCH   = 4,
            FTL_LOG_UE_RRC_REMOVED   = 5,
        } rrc;
        struct {
            int8_t   id;  /* -1 means this rab not present */
            uint16_t type;
        } rab[5];   /* rab[0] - CS, rab[1] - PS_UL, rab[2] - PS_DL rab[3] - PS_UL, rab[4] - PS_DL*/
    } info;
} ftl_log_ue_info_t;

/**
 * \brief UE measurement infomation.
 */
typedef struct ftl_log_ue_meas_info {
    int ueid;
    enum {
        FTL_LOG_UE_MEAS_UEID         = FTL_LOG_UE_UEID,
        FTL_LOG_UE_UL_CRC_ERR_RATIO  = 0x0002,
        FTL_LOG_UE_SIR_TARGET_CS     = 0x0003,
        FTL_LOG_UE_SIR_TARGET_PS     = 0x0004,
        FTL_LOG_UE_SIR_TARGET_SRB    = 0x0005,
        FTL_LOG_UE_SIR_ERROR         = 0x0006,
        FTL_LOG_UE_HNB_TX_CODE_POWER = 0x0007,
        FTL_LOG_UE_RRC_PATH_LOSS     = 0x0008,
        FTL_LOG_UE_EC_N0             = 0x0009,
        FTL_LOG_UE_RSCP              = 0x000A,
        FTL_LOG_UE_TX_CODE_POWER     = 0x000B,
        FTL_LOG_UE_SIR               = 0x000C
    } type;
    union {
        int16_t ul_crc_error_ratio;
        int16_t sir_target_cs;
        int16_t sir_target_ps;
        int16_t sir_target_srb;
        int16_t sir_error;
        int16_t hnb_tx_code_power;
        int16_t rrc_path_loss;
        int16_t ec_n0;
        int16_t rscp;
        int16_t ue_tx_code_power;
        int16_t ue_sir;
        int16_t int16_v;
    } info;
} ftl_log_ue_meas_info_t;

/**
 * \brief Log state & information.
 *
 * \param type [in] state & information type.
 * \param info [in] information accroding to type.
 *
 * \return FTL_LOG_RST_SUCCESS when success or FTL_LOG_RST_FAILURE when
 * failure.
 */
ftl_log_rst_t ftl_log_stat_info(int type, void *info);

/**
 * \brief Send ESP tunnel information to FDT.
 *
 * \param name [in] ESP tunnel name.
 */
int ftl_log_send_tunnel_info(char *name);

/////////////////////////////////////////////////////////////////////////////
// API defined below only for advanced use only.
// use these API unless you know what you are doing.

typedef struct ftl_tlv {
    uint16_t t;
    uint16_t l;
    uint8_t  v[0];
} __attribute__((packed)) ftl_tlv_t;
#define FTL_TLV(p)              ((struct ftl_tlv *)(p))
#define FTL_TLV_HLEN            (sizeof(struct ftl_tlv))
#define FTL_TLV_FIX_LEN(len) \
    ({ typeof(len) _len = (len); _len % 2 == 0 ? _len : ++_len; _len; })
#define FTL_TLV_ALEN_H(p) \
    (FTL_TLV_FIX_LEN(FTL_TLV(p)->l) + FTL_TLV_HLEN)
#define FTL_TLV_ALEN_N(p) \
    (FTL_TLV_FIX_LEN(ntohs(FTL_TLV(p)->l)) + FTL_TLV_HLEN)
#define FTL_TLV_NEXT_H(p) \
    (FTL_TLV(((int8_t *)(p) + FTL_TLV_ALEN_H(p)))) /* XXX: p evaluate twice */
#define FTL_TLV_NEXT_N(p) \
    (FTL_TLV(((int8_t *)(p) + FTL_TLV_ALEN_N(p)))) /* XXX: p evaluate twice */

void ftl_tlv_add_subtlv(struct ftl_tlv *p, uint16_t t, uint16_t l, void *v);

typedef struct ftl_log_msg {
    ftl_msg_t   base;
    uint32_t    flag;
    void        *priv;
#define FTL_LOG_MSG_FLAG_DROP   (1 << 0)
    uint16_t    head_used;
    uint16_t    tail_used;
    char        head_reserve[256];
    char        tail_reserve[512];
} ftl_log_msg_t;
#define FTL_LOG_MSG(p) ((struct ftl_log_msg *)(p))
#define FTL_LOG_MSG_HEAD(p) \
    ({\
     struct ftl_log_msg *_p = FTL_LOG_MSG(p);\
     void *_addr = _p->tail_reserve - _p->head_used;\
     _addr;\
     })
#define FTL_LOG_MSG_TAIL(p) \
    ({\
     struct ftl_log_msg *_p = FTL_LOG_MSG(p);\
     void *_addr = _p->tail_reserve + _p->tail_used;\
     _addr;\
     })
#define FTL_LOG_MSG_HEAD_FREE(p) ({256 - FTL_LOG_MSG(p)->head_used;})
#define FTL_LOG_MSG_TAIL_FREE(p) ({512 - FTL_LOG_MSG(p)->tail_used;})
#define FTL_LOG_MSG_TLV_SIZE(p) \
    ({\
     struct ftl_log_msg *_p = FTL_LOG_MSG(p);\
     int _size = _p->head_used + _p->tail_used;\
     _size;\
     })

typedef struct ftl_log_level_ctrl
{
    uint8_t debug; 
    uint8_t func;
    uint8_t info;
    uint8_t user;
    uint8_t warn;
    uint8_t error;
    uint8_t panic;
} ftl_log_level_ctrl_t;

typedef struct ftl_log_save_ctrl
{
    ftl_log_mod_id_t mod_id;
    ftl_log_level_ctrl_t level_ctrl;
}ftl_log_save_ctrl_t;

typedef struct ftl_log_raw_data_header
{
    uint16_t size;
    char reserved[6];
    struct timeval system_time;
}ftl_log_raw_data_header_t;

typedef enum ftl_log_msgid {
    FTL_LOG_MSGID_UNKNOW,
    FTL_LOG_MSGID_LOG,
    FTL_LOG_MSGID_STATE,
    FTL_LOG_MSGID_IPSEC,
    FTL_LOG_MSGID_MAX
} ftl_log_msgid_t;

ftl_log_msg_t* ftl_log_msg_new(void);

ftl_log_msg_t*
ftl_log_msg_new_ex(ftl_log_mod_id_t mod_id, uint16_t code, ftl_log_lvl_t level,
                   int16_t ueid, char *param,
                   ...) __attribute__((format(printf, 5, 6)));

/*
 * XXX: Value need to be network byte order. other paramter should use host
 * byte order.
 */
/*
ftl_log_rst_t ftl_log_msg_add_tlv_ex(ftl_log_msg_t *msg, uint16_t type,
                                     uint16_t len, void *value,
                                     bool append, bool check);
#define ftl_log_msg_add_tlv(msg, type, len, value, check) \
    ftl_log_msg_add_tlv_ex(msg, type, len, value, 1, check)

#define ftl_log_msg_add_tlv_in_head(msg, type, len, value, check) \
    ftl_log_msg_add_tlv_ex(msg, type, len, value, 0, check)
*/
/*
 */
ftl_log_rst_t ftl_log_msg_commit(ftl_log_msg_t *msg);

/**
 * @}
 */

#endif /* FTL_LOG_H */
