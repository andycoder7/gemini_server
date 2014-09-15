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
 * \file ftl_generic.h
 *
 * Generic definition for ftl_ series of APIs.
 *
 * \auth Jerry Hu <jerry_hu@sdc.sercomm.com>
 *
 * \date 2011-04-20
 */
#ifndef FTL_GENERIC_H
#define FTL_GENERIC_H

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <arpa/inet.h>

/**
 * some libc function declared here
 */
/* Similar to `strstr' but this function ignores the case of both strings.  */
extern char *strcasestr (__const char *__haystack, __const char *__needle);

/**
 * \brief ftl_ API return result.
 */
typedef enum ftl_rst {
    FTL_RST_SUCCESS,
    FTL_RST_FAILURE,
} ftl_rst_t;

/**
 * \brief Convert network byte order long integer into host byte order.
 *
 * This funtion works like ntohl, it implement use MACRO so it can be used to
 * convert float.
 */
#define NTOHL(x) do {                        \
    if(ntohs(0x0001) != 0x0001) {            \
        char b;                              \
        b = ((char *)(x))[0];                \
        ((char *)(x))[0] = ((char *)(x))[3]; \
        ((char *)(x))[3] = b;                \
        b = ((char *)(x))[1];                \
        ((char *)(x))[1] = ((char *)(x))[2]; \
        ((char *)(x))[2] = b;                \
    }                                        \
} while(0)

/**
 * \brief Convert host type order long integer into network byte order.
 *
 * \see NTOHL
 */
#define HTONL(x) NTOHL(x)

/**
 * \brief Return the minimum value of x and y.
 *
 * x and y can be any type support comparsion. This MACRO implemented has no
 * side effect. x and y will not evalate twice.
 */
#define FTL_MIN(x, y) \
    ({ typeof(x) _x = (x); typeof(y) _y = (y); _x < _y ? _x : _y;})

/**
 * \brief Return the maximum value of x and y.
 *
 * x and y can be any type support comparsion. This MACRO implemented has no
 * side effect. x and y will not evalate twice.
 */
#define FTL_MAX(x, y) \
    ({ typeof(x) _x = (x); typeof(y) _y = (y); _x > _y ? _x : _y;})

/**
 * \brief Print unimplemented function warning to console.
 *
 * You could use this MACRO to print a warnning message on console if your
 * function not implemented yet.
 */
#define __unimplemented_function \
    do { \
        fprintf(stderr, "%s unimplemented yet.\n", __FUNCTION__); \
    } while(0)

/**
 * \brief Output DEBUG message on console.
 */
#define FTL_DEBUG(...) \
    do { \
        fprintf(stderr, "[FTL][DEBUG]"); \
        fprintf(stderr, __VA_ARGS__); \
    } while(0)

/**
 * \brief Output INFO message on console.
 */
#define FTL_INFO(...) \
    do { \
        fprintf(stderr, "[FTL][INFO]"); \
        fprintf(stderr, __VA_ARGS__); \
    } while(0)

/**
 * \brief Output WARN message on console.
 */
#define FTL_WARN(...) \
    do { \
        fprintf(stderr, "[FTL][WARN]"); \
        fprintf(stderr, __VA_ARGS__); \
    } while(0)

/**
 * \brief Output ERROR message on console.
 */
#define FTL_ERROR(...) \
    do { \
        fprintf(stderr, "[FTL][ERROR]"); \
        fprintf(stderr, __VA_ARGS__); \
    } while(0)

/**
 * \brief Output PANIC message on console.
 */
#define FTL_PANIC(...) \
    do { \
        fprintf(stderr, "[FTL][PANIC]"); \
        fprintf(stderr, __VA_ARGS__); \
        exit(-1); \
    } while(0)

/**
 * \brief Output BUG message on console.
 */
#define FTL_BUG(...) \
    do { \
        fprintf(stderr, "[FTL][BUGS]"); \
        fprintf(stderr, __VA_ARGS__); \
    } while(0)

#endif /* FTL_GENERIC_H */
