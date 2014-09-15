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
 * \file ftl_msg.h
 *
 * Message framework APIs
 *
 * \author Jerry Hu <jerry_hu@sdc.sercomm.com>
 *
 * \date 2011-04-20
 */
#ifndef FTL_MSG_H
#define FTL_MSG_H

#include "ftl_generic.h"

/**
 * \defgroup ftl_msg [ftl_msg] Message framework.
 * @{
 */

/**
 * \brief Allowed maxlength of a message
 */
#define FTL_MSG_MAX_LEN     (1024 * 32)

/**
 * \brief Communication port used for IDC
 */
#define FTL_MSG_IDC_PORT    (32)

/*
 * FIXME: the should defined private.
 */
#define FTL_MSG_SOCKET_DIR      "/var/ftl/msg/"

/**
 * \brief Message framework API call result value.
 */
typedef enum ftl_msg_rst {
    FTL_MSG_RST_SUCCESS = 0, /*!< success */
    FTL_MSG_RST_FAILURE, /*!< generic failed */
    FTL_MSG_RST_INVALID_CFG, /*!< invalid module configure */
    FTL_MSG_RST_INVALID_MOD_ID, /*!< invalid module id */
    FTL_MSG_RST_SOCKET_ERROR, /*!< socket releated error */
    FTL_MSG_RST_THREAD_ERROR, /*!< thread releated error */
} ftl_msg_rst_t;

/**
 * \brief bitmask flag of the message.
 *
 * - byte 1 - message priority
 * - byte 2 - bit 1 - IDC/IPC msg flag
 * - byte 3 - reserved
 * - byte 4 - bit 8 - print/no_print flag
 */
typedef uint32_t ftl_msg_flag_t;
#define FTL_MSG_PRIORITY_MASK   (0xFF)
#define FTL_MSG_IDC_MSG_MASK    (0x0100)
#define FTL_MSG_NO_PRINT_MASK   (0x80000000)
#define FTL_MSG_FLAG_NO_PRINT   (0x80000000)
#define FTL_MSG_FLAG_DEFAULT    (FTL_MSG_PRI_DEFAULT)

typedef uint32_t ftl_mod_id_t;

enum {
    FTL_MOD_ID_UNKNOW = 0,
    FTL_MOD_ID_CLI    = 1,
    FTL_MOD_ID_LOG    = 2,
    FTL_MOD_ID_TMR    = 3,
    FTL_MOD_ID_VI     = 4,
    FTL_MOD_ID_IDC    = 5,
    FTL_MOD_ID_EVENT  = 6,
    FTL_MOD_ID_USER   = 0x10,
};
#define FTL_MOD_MAX  32 /* MAX mod supported */

/*
 * Base message type for Femto use.
 */
#if __GNUC__ > 3
#pragma pack(push)
#endif
#pragma pack(4)
typedef struct ftl_msg {
    /*
     * Generic information
     */
    uint8_t      endian;
#define FTL_MSG_ENDIAN_BE   (0)
#define FTL_MSG_ENDIAN_LE   (1)

    ftl_mod_id_t src_id;
    ftl_mod_id_t dst_id;
    ftl_mod_id_t mod;    /* which mod this message belong to */
    uint32_t     msgid;  /* msg id, module releated. */
    uint32_t     len;    /* message body length */
    void (*destructor)(void *);
    void *free_ptr;
    uint32_t hold_cnt;
    ftl_msg_flag_t flag;
    struct ftl_msg *next;

    /*
     * external data
     */
    struct ftl_msg_ext {
        uint16_t t;
        uint16_t l;
        void    *p;
#define FTL_MSG_EXT_FLAG_NO_FREE    (0x01)
#define FTL_MSG_EXT_FLAG_FREE       (0x02)
        uint8_t  f;
        struct ftl_msg_ext *next;
        char     v[0];
    } *p_ext;
#define FTL_MSG_EXT(p) ((struct ftl_msg_ext *)(p))
    uint32_t ext_cnt;
    uint32_t ext_len;

    /*
     * Dummy message body
     */
    char body[0];
} ftl_msg_t;
#if __GNUC__ > 3
#pragma pack(pop)
#else
#pragma pack()
#endif

#define FTL_MSG(p)          ((struct ftl_msg *)(p))
#define FTL_MSG_MOD(p)      (FTL_MSG(p)->mod)
#define FTL_MSG_MSGID(p)    (FTL_MSG(p)->msgid)
#define FTL_MSG_LEN(p)      (FTL_MSG(p)->len)
#define FTL_MSG_DATA(p)     (FTL_MSG(p)->body)
#define FTL_MSG_SRC(p)      (FTL_MSG(p)->src_mod_id)
#define FTL_MSG_TOTAL_LEN(p)                \
    (sizeof(ftl_msg_t) + FTL_MSG_LEN(p) +   \
     FTL_MSG(p)->ext_cnt * sizeof(struct ftl_msg_ext) + FTL_MSG(p)->ext_len)

/**
 * \brief initialize message framework
 */
ftl_msg_rst_t ftl_msg_init(void);

/**
 * \brief de-initialize message framework
 */
ftl_msg_rst_t ftl_msg_deinit(void);


/**
 * \brief create new message
 *
 * The actual length of the message is len + sizeof(struct ftl_msg).
 */
struct ftl_msg* ftl_msg_new(uint32_t len);

/**
 * \brief Create a new message.
 *
 * The actual length of the message is len + sizeof(struct ftl_msg). If ptr is
 * NULL when create the message, it will pass the ftl_msg itself when call the
 * destructor.
 *
 * \param len [in] Message length requested
 * \param mod [in] Module id of the message.
 * \param msgid [in] Msgid of the message.
 * \param destructor [in] Message destructor.
 * \param ptr [in] parameter of destructor.
 */
struct ftl_msg* ftl_msg_new_ex(uint32_t len, ftl_mod_id_t mod, uint32_t msgid,
                               void (*destructor)(void *), void *ptr);

/**
 * \brief Add extern data
 *
 * \param msg [in] which message to operate on
 * \param type [in] type of extern data
 * \param len  [in] length of extern data
 * \param buf  [in] actual data attached into message.
 * \param flag [in] see define above.
 */
ftl_msg_rst_t ftl_msg_add_ext(struct ftl_msg *msg, uint16_t type, uint16_t len,
                              void *buf, uint8_t flag);

/**
 * \brief Create a new message
 *
 * The actual length of the message is len + sizeof(struct ftl_msg).
 * The header of message is initialized, but the body is not.
 */
struct ftl_msg *ftl_msg_create(uint32_t len);

/**
 * \brief Create a new message.
 *
 * The actual length of the message is len + sizeof(struct ftl_msg). The header
 * of message is initialized, but the body is not. If ptr is NULL when create
 * the message, it will pass the ftl_msg itself when call the destructor.
 *
 * \param len [in] Message length requested
 * \param mod [in] Module id of the message.
 * \param msgid [in] Msgid of the message.
 * \param destructor [in] Message destructor.
 * \param ptr [in] parameter of destructor.
 */
struct ftl_msg *ftl_msg_create_ex(uint32_t len, ftl_mod_id_t mod, uint32_t msgid,
                                  void (*destructor)(void *), void *ptr);

/**
 * \brief Get extern data from message
 *
 * \param msg [in] message to operate on
 * \param type [in] type of extern data to get
 * \param len [out] length of extern data get
 *
 * \return A pointer to data get, NULL if type was not found.
 */
void* ftl_msg_get_ext(struct ftl_msg *msg, uint16_t type, int *len);

/**
 * \brief delete message created by ftl_msg_new(ftl_msg_new_ex) function.
 */
void ftl_msg_delete(struct ftl_msg *msg);

/*
 * Hold a message
 * The message will not deleted until the hold reference count reachs 0.
 */
void ftl_msg_hold(struct ftl_msg *msg);

/*
 * Unhold a message
 * The message will deleted if the hold reference count reachs 0.
 */
void ftl_msg_unhold(struct ftl_msg *ftl_msg);

/**
 * \brief Femto message priority.
 */
typedef enum {
    FTL_MSG_PRI_HIGH        = 0,
    FTL_MSG_PRI_DEFAULT     = 3,
    FTL_MSG_PRI_LOW         = 6,
    FTL_MSG_PRI_MAX         = 9,
} ftl_msg_pri_t;

static inline ftl_msg_pri_t ftl_msg_flag_get_priority(ftl_msg_flag_t flag)
{
    return flag & FTL_MSG_PRIORITY_MASK;
}

/**
 * \brief get version information
 */
char *ftl_msg_get_version(void);

/**
 * \brief Prototype of femto message handler
 *
 * \param msg [in] The message to process.
 */
typedef void (*ftl_msg_handler_t)(struct ftl_msg *msg);

/**
 * \brief Prototype of femto message flag identifier.
 *
 * \param msg [in] The message to identify with.
 *
 * \return The identifier function should return the flag of the message.
 */
typedef ftl_msg_flag_t (*ftl_msg_ident)(struct ftl_msg *msg);

/**
 * \brief Register a module for communication.
 *
 * Any message send to the module will fail until one of process in FAP device
 * ininitize the module.
 * Message handler callback for the module can't be NULL, initialize will fail
 * otherwise.
 * Priority identifier can be NULL. Each message send to this module will have
 * the default priority in this case.
 * module_priority is 0-255, 0 is the lowest priority, and 255 is the highest
 * priority.
 *
 * \return 0 - success; otherwise - failed.
 */

#define FTL_MSG_MODULE_PRIORITY_LOWEST      (0)
#define FTL_MSG_MODULE_PRIORITY_DEFAULT     (100)
#define FTL_MSG_MODULE_PRIORITY_HIGHEST     (255)
typedef struct ftl_msg_mod_cfg {
    ftl_mod_id_t            id;
    ftl_msg_handler_t       handler;
    ftl_msg_ident           ident;
    uint16_t                q_size[FTL_MSG_PRI_MAX];
    uint8_t                 enable_ipc;
    uint8_t                 module_priority;
    char                    *name;
} ftl_msg_mod_cfg_t;

ftl_msg_rst_t ftl_msg_module_reg(ftl_msg_mod_cfg_t *cfg);

/**
 * \brief de-register a module.
 *
 * \param id [in] identity of the module to delete.
 */
ftl_msg_rst_t ftl_msg_module_dereg(ftl_mod_id_t id);

/**
 * \brief Set destnation ipaddress for inter-device-communication.
 *
 * \param id [in] destnation module id.
 * \param dst [in] ip address to communicate.
 */
ftl_msg_rst_t ftl_msg_module_set_dest(ftl_mod_id_t id, char *dst);

/**
 * \brief Send a message
 *
 * This function send a message to one module, the dest module can be the
 * module of itself or other module, depend on the module id of the dest
 * module.
 * If the dest module is in the same process with the sending module, msg will
 * put the message queue of the dest module directly without memory copy or
 * socket overhead.
 * This function will try to send the message to dest module over local socket
 * if the dest module is not initalized in the sending process.
 *
 * \param id [in] dest module id
 * \param msg [in] the message to send.
 *
 * \return 0 - success; otherwise - failed.
 */
ftl_msg_rst_t ftl_msg_send(ftl_mod_id_t id, struct ftl_msg *msg);

#if 0
/**
 * \brief Format message statistics information into buf.
 */
void ftl_msg_format_stat(char buf[], int *len);

/**
 * \brief Set verbose level of femtolite message framework.
 *
 * You could set the verbose level to see the inner-working of femtolite
 * message framework.<br>
 * verbose level defined as below:<br>
 * - 0 : <default> Only critical information will printed.
 * - 1 : Not so critical but still important information will printed.
 * - 2 : General information will printed, like function call trace.
 * - 3 : Even more information will printed, this may impact the framework
 *       performance, don't set to this level unless you are debuging the
 *       framework itself.
 *
 * \param verbose [in] Verbose level to set.
 *
 * \return FTL_MSG_RST_SUCCESS on success.<br>
 *         FTL_MSG_RST_FAILURE on failure.
 */
ftl_msg_rst_t ftl_msg_set_verbose(uint8_t verbose);
#endif

typedef struct ftl_msg_proc_q_info {
    ftl_mod_id_t    mod_id;
    struct {
        uint16_t    msg_max;
        uint16_t    msg_droped;
    } msg_q[FTL_MSG_PRI_MAX];
} ftl_msg_proc_q_info_t;

/**
 * \brief Qurey all message queue status in local process.
 *
 * \param info_lst  [out]   list of status info.
 * \param mod_num   [inout] size of array info_lst as an incoming param ,
 *                          actual number of module info as an outgoing param.
 *
 * \return FTL_MSG_RST_SUCCESS on success.
 *         FTL_MSG_RST_FAILURE on failure.
 */
ftl_msg_rst_t
ftl_msg_query_proc_q_info(ftl_msg_proc_q_info_t *info_lst, size_t *mod_num);

/**
 * \brief Initialize IDC message framework
 *
 * Call by each devices only once
 *
 * \return FTL_MSG_RST_SUCCESS on success.
 *         FTL_MSG_RST_FAILURE on failure.
 */
ftl_msg_rst_t ftl_msg_idc_init(void);


/**
 * \brief deinitialize IDC message framework
 *
 * Call by each devices only once
 *
 * \return FTL_MSG_RST_SUCCESS on success.
 *         FTL_MSG_RST_FAILURE on failure.
 */
ftl_msg_rst_t ftl_msg_idc_deinit(void);

/** @} */

#endif /* FAP_MSG_H */
