
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _bjrk-edge_PARSE_H_INCLUDED_
#define _bjrk-edge_PARSE_H_INCLUDED_


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>


ssize_t ngx_parse_size(ngx_str_t *line);
off_t ngx_parse_offset(ngx_str_t *line);
ngx_int_t ngx_parse_time(ngx_str_t *line, ngx_uint_t is_sec);


#endif /* _bjrk-edge_PARSE_H_INCLUDED_ */
