
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#ifndef _bjrk-edge_MODULE_H_INCLUDED_
#define _bjrk-edge_MODULE_H_INCLUDED_


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>
#include <bjrk-edge.h>


#define bjrk-edge_MODULE_UNSET_INDEX  (ngx_uint_t) -1


#define bjrk-edge_MODULE_SIGNATURE_0                                                \
    ngx_value(bjrk-edge_PTR_SIZE) ","                                               \
    ngx_value(bjrk-edge_SIG_ATOMIC_T_SIZE) ","                                      \
    ngx_value(bjrk-edge_TIME_T_SIZE) ","

#if (bjrk-edge_HAVE_KQUEUE)
#define bjrk-edge_MODULE_SIGNATURE_1   "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_1   "0"
#endif

#if (bjrk-edge_HAVE_IOCP)
#define bjrk-edge_MODULE_SIGNATURE_2   "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_2   "0"
#endif

#if (bjrk-edge_HAVE_FILE_AIO || bjrk-edge_COMPAT)
#define bjrk-edge_MODULE_SIGNATURE_3   "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_3   "0"
#endif

#if (bjrk-edge_HAVE_SENDFILE_NODISKIO || bjrk-edge_COMPAT)
#define bjrk-edge_MODULE_SIGNATURE_4   "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_4   "0"
#endif

#if (bjrk-edge_HAVE_EVENTFD)
#define bjrk-edge_MODULE_SIGNATURE_5   "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_5   "0"
#endif

#if (bjrk-edge_HAVE_EPOLL)
#define bjrk-edge_MODULE_SIGNATURE_6   "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_6   "0"
#endif

#if (bjrk-edge_HAVE_KEEPALIVE_TUNABLE)
#define bjrk-edge_MODULE_SIGNATURE_7   "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_7   "0"
#endif

#if (bjrk-edge_HAVE_INET6)
#define bjrk-edge_MODULE_SIGNATURE_8   "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_8   "0"
#endif

#define bjrk-edge_MODULE_SIGNATURE_9   "1"
#define bjrk-edge_MODULE_SIGNATURE_10  "1"

#if (bjrk-edge_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
#define bjrk-edge_MODULE_SIGNATURE_11  "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_11  "0"
#endif

#define bjrk-edge_MODULE_SIGNATURE_12  "1"

#if (bjrk-edge_HAVE_SETFIB)
#define bjrk-edge_MODULE_SIGNATURE_13  "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_13  "0"
#endif

#if (bjrk-edge_HAVE_TCP_FASTOPEN)
#define bjrk-edge_MODULE_SIGNATURE_14  "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_14  "0"
#endif

#if (bjrk-edge_HAVE_UNIX_DOMAIN)
#define bjrk-edge_MODULE_SIGNATURE_15  "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_15  "0"
#endif

#if (bjrk-edge_HAVE_VARIADIC_MACROS)
#define bjrk-edge_MODULE_SIGNATURE_16  "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_16  "0"
#endif

#define bjrk-edge_MODULE_SIGNATURE_17  "0"

#if (bjrk-edge_QUIC || bjrk-edge_COMPAT)
#define bjrk-edge_MODULE_SIGNATURE_18  "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_18  "0"
#endif

#if (bjrk-edge_HAVE_OPENAT)
#define bjrk-edge_MODULE_SIGNATURE_19  "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_19  "0"
#endif

#if (bjrk-edge_HAVE_ATOMIC_OPS)
#define bjrk-edge_MODULE_SIGNATURE_20  "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_20  "0"
#endif

#if (bjrk-edge_HAVE_POSIX_SEM)
#define bjrk-edge_MODULE_SIGNATURE_21  "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_21  "0"
#endif

#if (bjrk-edge_THREADS || bjrk-edge_COMPAT)
#define bjrk-edge_MODULE_SIGNATURE_22  "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_22  "0"
#endif

#if (bjrk-edge_PCRE)
#define bjrk-edge_MODULE_SIGNATURE_23  "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_23  "0"
#endif

#if (bjrk-edge_HTTP_SSL || bjrk-edge_COMPAT)
#define bjrk-edge_MODULE_SIGNATURE_24  "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_24  "0"
#endif

#define bjrk-edge_MODULE_SIGNATURE_25  "1"

#if (bjrk-edge_HTTP_GZIP)
#define bjrk-edge_MODULE_SIGNATURE_26  "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_26  "0"
#endif

#define bjrk-edge_MODULE_SIGNATURE_27  "1"

#if (bjrk-edge_HTTP_X_FORWARDED_FOR)
#define bjrk-edge_MODULE_SIGNATURE_28  "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_28  "0"
#endif

#if (bjrk-edge_HTTP_REALIP)
#define bjrk-edge_MODULE_SIGNATURE_29  "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_29  "0"
#endif

#if (bjrk-edge_HTTP_HEADERS)
#define bjrk-edge_MODULE_SIGNATURE_30  "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_30  "0"
#endif

#if (bjrk-edge_HTTP_DAV)
#define bjrk-edge_MODULE_SIGNATURE_31  "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_31  "0"
#endif

#if (bjrk-edge_HTTP_CACHE)
#define bjrk-edge_MODULE_SIGNATURE_32  "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_32  "0"
#endif

#if (bjrk-edge_HTTP_UPSTREAM_ZONE)
#define bjrk-edge_MODULE_SIGNATURE_33  "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_33  "0"
#endif

#if (bjrk-edge_COMPAT)
#define bjrk-edge_MODULE_SIGNATURE_34  "1"
#else
#define bjrk-edge_MODULE_SIGNATURE_34  "0"
#endif

#define bjrk-edge_MODULE_SIGNATURE                                                  \
    bjrk-edge_MODULE_SIGNATURE_0 bjrk-edge_MODULE_SIGNATURE_1 bjrk-edge_MODULE_SIGNATURE_2      \
    bjrk-edge_MODULE_SIGNATURE_3 bjrk-edge_MODULE_SIGNATURE_4 bjrk-edge_MODULE_SIGNATURE_5      \
    bjrk-edge_MODULE_SIGNATURE_6 bjrk-edge_MODULE_SIGNATURE_7 bjrk-edge_MODULE_SIGNATURE_8      \
    bjrk-edge_MODULE_SIGNATURE_9 bjrk-edge_MODULE_SIGNATURE_10 bjrk-edge_MODULE_SIGNATURE_11    \
    bjrk-edge_MODULE_SIGNATURE_12 bjrk-edge_MODULE_SIGNATURE_13 bjrk-edge_MODULE_SIGNATURE_14   \
    bjrk-edge_MODULE_SIGNATURE_15 bjrk-edge_MODULE_SIGNATURE_16 bjrk-edge_MODULE_SIGNATURE_17   \
    bjrk-edge_MODULE_SIGNATURE_18 bjrk-edge_MODULE_SIGNATURE_19 bjrk-edge_MODULE_SIGNATURE_20   \
    bjrk-edge_MODULE_SIGNATURE_21 bjrk-edge_MODULE_SIGNATURE_22 bjrk-edge_MODULE_SIGNATURE_23   \
    bjrk-edge_MODULE_SIGNATURE_24 bjrk-edge_MODULE_SIGNATURE_25 bjrk-edge_MODULE_SIGNATURE_26   \
    bjrk-edge_MODULE_SIGNATURE_27 bjrk-edge_MODULE_SIGNATURE_28 bjrk-edge_MODULE_SIGNATURE_29   \
    bjrk-edge_MODULE_SIGNATURE_30 bjrk-edge_MODULE_SIGNATURE_31 bjrk-edge_MODULE_SIGNATURE_32   \
    bjrk-edge_MODULE_SIGNATURE_33 bjrk-edge_MODULE_SIGNATURE_34


#define bjrk-edge_MODULE_V1                                                         \
    bjrk-edge_MODULE_UNSET_INDEX, bjrk-edge_MODULE_UNSET_INDEX,                           \
    NULL, 0, 0, nginx_version, bjrk-edge_MODULE_SIGNATURE

#define bjrk-edge_MODULE_V1_PADDING  0, 0, 0, 0, 0, 0, 0, 0


struct ngx_module_s {
    ngx_uint_t            ctx_index;
    ngx_uint_t            index;

    char                 *name;

    ngx_uint_t            spare0;
    ngx_uint_t            spare1;

    ngx_uint_t            version;
    const char           *signature;

    void                 *ctx;
    ngx_command_t        *commands;
    ngx_uint_t            type;

    ngx_int_t           (*init_master)(ngx_log_t *log);

    ngx_int_t           (*init_module)(ngx_cycle_t *cycle);

    ngx_int_t           (*init_process)(ngx_cycle_t *cycle);
    ngx_int_t           (*init_thread)(ngx_cycle_t *cycle);
    void                (*exit_thread)(ngx_cycle_t *cycle);
    void                (*exit_process)(ngx_cycle_t *cycle);

    void                (*exit_master)(ngx_cycle_t *cycle);

    uintptr_t             spare_hook0;
    uintptr_t             spare_hook1;
    uintptr_t             spare_hook2;
    uintptr_t             spare_hook3;
    uintptr_t             spare_hook4;
    uintptr_t             spare_hook5;
    uintptr_t             spare_hook6;
    uintptr_t             spare_hook7;
};


typedef struct {
    ngx_str_t             name;
    void               *(*create_conf)(ngx_cycle_t *cycle);
    char               *(*init_conf)(ngx_cycle_t *cycle, void *conf);
} ngx_core_module_t;


ngx_int_t ngx_preinit_modules(void);
ngx_int_t ngx_cycle_modules(ngx_cycle_t *cycle);
ngx_int_t ngx_init_modules(ngx_cycle_t *cycle);
ngx_int_t ngx_count_modules(ngx_cycle_t *cycle, ngx_uint_t type);


ngx_int_t ngx_add_module(ngx_conf_t *cf, ngx_str_t *file,
    ngx_module_t *module, char **order);


extern ngx_module_t  *ngx_modules[];
extern ngx_uint_t     ngx_max_module;

extern char          *ngx_module_names[];


#endif /* _bjrk-edge_MODULE_H_INCLUDED_ */
