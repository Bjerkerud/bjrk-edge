
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _bjrk-edge_USER_H_INCLUDED_
#define _bjrk-edge_USER_H_INCLUDED_


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>


typedef uid_t  ngx_uid_t;
typedef gid_t  ngx_gid_t;


ngx_int_t ngx_libc_crypt(ngx_pool_t *pool, u_char *key, u_char *salt,
    u_char **encrypted);


#endif /* _bjrk-edge_USER_H_INCLUDED_ */
