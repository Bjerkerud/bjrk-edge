
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _bjrk-edge_SIPHASH_H_INCLUDED_
#define _bjrk-edge_SIPHASH_H_INCLUDED_


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>


uint64_t ngx_siphash(uint64_t k0, uint64_t k1, u_char *data, size_t len);


#endif /* _bjrk-edge_SIPHASH_H_INCLUDED_ */
