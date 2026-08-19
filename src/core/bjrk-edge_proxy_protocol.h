
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#ifndef _bjrk-edge_PROXY_PROTOCOL_H_INCLUDED_
#define _bjrk-edge_PROXY_PROTOCOL_H_INCLUDED_


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>


#define bjrk-edge_PROXY_PROTOCOL_V1_MAX_HEADER  107
#define bjrk-edge_PROXY_PROTOCOL_MAX_HEADER     4096


struct ngx_proxy_protocol_s {
    ngx_str_t           src_addr;
    ngx_str_t           dst_addr;
    in_port_t           src_port;
    in_port_t           dst_port;
    ngx_str_t           tlvs;
};


u_char *ngx_proxy_protocol_read(ngx_connection_t *c, u_char *buf,
    u_char *last);
u_char *ngx_proxy_protocol_write(ngx_connection_t *c, u_char *buf,
    u_char *last);
u_char *ngx_proxy_protocol_v2_write(ngx_connection_t *c, u_char *buf,
    u_char *last, ngx_array_t *tlvs);
ngx_int_t ngx_proxy_protocol_get_tlv(ngx_connection_t *c, ngx_str_t *name,
    ngx_str_t *value);


#endif /* _bjrk-edge_PROXY_PROTOCOL_H_INCLUDED_ */
