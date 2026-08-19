
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _bjrk-edge_MD5_H_INCLUDED_
#define _bjrk-edge_MD5_H_INCLUDED_


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>


typedef struct {
    uint64_t  bytes;
    uint32_t  a, b, c, d;
    u_char    buffer[64];
} ngx_md5_t;


void ngx_md5_init(ngx_md5_t *ctx);
void ngx_md5_update(ngx_md5_t *ctx, const void *data, size_t size);
void ngx_md5_final(u_char result[16], ngx_md5_t *ctx);


#endif /* _bjrk-edge_MD5_H_INCLUDED_ */
