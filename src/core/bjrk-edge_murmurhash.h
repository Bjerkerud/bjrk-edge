
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _bjrk-edge_MURMURHASH_H_INCLUDED_
#define _bjrk-edge_MURMURHASH_H_INCLUDED_


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>


uint32_t ngx_murmur_hash2(u_char *data, size_t len);


#endif /* _bjrk-edge_MURMURHASH_H_INCLUDED_ */
