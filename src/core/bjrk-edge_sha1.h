
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _bjrk-edge_SHA1_H_INCLUDED_
#define _bjrk-edge_SHA1_H_INCLUDED_


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>


typedef struct {
    uint64_t  bytes;
    uint32_t  a, b, c, d, e, f;
    u_char    buffer[64];
} ngx_sha1_t;


void ngx_sha1_init(ngx_sha1_t *ctx);
void ngx_sha1_update(ngx_sha1_t *ctx, const void *data, size_t size);
void ngx_sha1_final(u_char result[20], ngx_sha1_t *ctx);


#endif /* _bjrk-edge_SHA1_H_INCLUDED_ */
