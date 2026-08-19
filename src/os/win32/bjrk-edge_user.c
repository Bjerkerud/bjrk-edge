/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>


#if (bjrk-edge_CRYPT)

ngx_int_t
ngx_libc_crypt(ngx_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    /* STUB: a plain text password */

    *encrypted = key;

    return bjrk-edge_OK;
}

#endif /* bjrk-edge_CRYPT */
