
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _bjrk-edge_JSON_H_INCLUDED_
#define _bjrk-edge_JSON_H_INCLUDED_


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>


ngx_buf_t *ngx_json_render(ngx_pool_t *pool, ngx_data_item_t *item);


#endif /* _bjrk-edge_JSON_H_INCLUDED_ */
