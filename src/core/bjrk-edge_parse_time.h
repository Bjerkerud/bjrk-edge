
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _bjrk-edge_PARSE_TIME_H_INCLUDED_
#define _bjrk-edge_PARSE_TIME_H_INCLUDED_


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>


time_t ngx_parse_http_time(u_char *value, size_t len);

/* compatibility */
#define ngx_http_parse_time(value, len)  ngx_parse_http_time(value, len)


#endif /* _bjrk-edge_PARSE_TIME_H_INCLUDED_ */
