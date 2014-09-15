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
 * \file gmn_mod.h
 *
 * Gemini module APIs
 *
 * \author Andy yao <andy.at.working@gmail.com>
 *
 * \date 2014-03-10
 */
#ifndef GMN_MOD_H
#define GMN_MOD_H
#include "ftl_ctl.h"
#include "iuh_interface.h"
/**
 * \brief Gemini Module API call result value.
 */
typedef enum gmn_mod_rst {
	GMN_MOD_RST_SUCCESS = 0,        /*!< success */
	GMN_MOD_RST_FAILURE,            /*!< generic failed */
	GMN_RST_INIT_FAILURE,           /*!< gemini module init error */
	GMN_RST_NOT_INIT,               /*!< gemini module hasn't inited */
	GMN_RST_SOCKET_ERROR,           /*!< socket releated error */
	GMN_RST_PROCESS_CREATE_ERROR,   /*< create process error*/
	GMN_RST_PROCESS_RELEATE_ERROR,  /*!< process releated error */
} gmn_mod_rst_t;

/**
 * \brief The structure of data transmitted between IUH and GMN.
 */
typedef struct gtp_data_gemini {
	uint16_t  ue_id;
	uint8_t   rab_id;
	uint8_t   *data;
	uint32_t  size;
} gtp_data_gemini_t;

/**
 * \brief The structure about UE information.
 */
typedef struct {
	uint16_t  ue_id;
	uint8_t   rab_id;
	uint32_t  ue_ip;
} gmn_ue_info_t;

/**
 * \brief The structure about UE information 
 *        transmitted between RRM and GMN.
 */
typedef struct {
	uint16_t  ue_id;
	uint8_t   rab_id;
	uint8_t   capability;
	uint8_t   rate;
	uint32_t  wifi_ip;
} gmn_ue_status_t;

/**
 * \brief The structure about ue information used by gemini module
 */
typedef struct ue_info {
	uint16_t  ue_id;
	uint8_t   rab_id;
	uint8_t   rate;
	uint8_t   next_choice;
	uint32_t  wifi_ip;
	uint32_t  ue_ip;
	int32_t   ue_fd;
	int32_t   wifi_fd;
	struct ue_info   *next;
} ue_info_t;

#ifndef GMN_MOD_ID
#define GMN_MOD_ID FTL_MOD_ID_GMN 
#endif

#ifndef IUH_MOD_ID
#define IUH_MOD_ID FTL_MOD_ID_IUH
#endif

#ifndef RRM_MOD_ID
#define RRM_MOD_ID FTL_MOD_ID_RRM
#endif

#ifndef GMN_IUH_UL_UU_DATA
#define GMN_IUH_UL_UU_DATA 1
#endif

#ifndef IUH_GMN_UL_IU_DATA
#define IUH_GMN_UL_IU_DATA 2
#endif

#ifndef GMN_IUH_DL_IU_DATA
#define GMN_IUH_DL_IU_DATA 3
#endif

#ifndef IUH_GMN_DL_UU_DATA
#define IUH_GMN_DL_UU_DATA 4
#endif

#ifndef GMN_IUH_ADD_UE_INFO
#define GMN_IUH_ADD_UE_INFO 5
#endif

#ifndef GMN_IUH_DEL_UE_INFO
#define GMN_IUH_DEL_UE_INFO 6
#endif

#ifndef RRM_GMN_UE_INFO_UPDATE
#define RRM_GMN_UE_INFO_UPDATE 1
#endif

#ifndef WIFI_PORT
#define WIFI_PORT 5388
#endif

/**
 * \brief Initialize gemini module
 */
gmn_mod_rst_t gemini_init(void);

/**
 * \brief Start gemini module 
 */
gmn_mod_rst_t gemini_start(void);

/**
 * \brief Stop gemini module
 */
gmn_mod_rst_t gemini_stop(void);

/**
 * \brief Destroy gemini module
 */
gmn_mod_rst_t gemini_deinit(void);

#endif /* GMN_MOD_H */
