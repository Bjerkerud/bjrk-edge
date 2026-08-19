
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _bjrk-edge_ALLOC_H_INCLUDED_
#define _bjrk-edge_ALLOC_H_INCLUDED_


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>


void *ngx_alloc(size_t size, ngx_log_t *log);
void *ngx_calloc(size_t size, ngx_log_t *log);

#define ngx_free          free
#define ngx_memalign(alignment, size, log)  ngx_alloc(size, log)

extern ngx_uint_t  ngx_pagesize;
extern ngx_uint_t  ngx_pagesize_shift;
extern ngx_uint_t  ngx_cacheline_size;


#endif /* _bjrk-edge_ALLOC_H_INCLUDED_ */
