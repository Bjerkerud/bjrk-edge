
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _bjrk-edge_EVENT_QUIC_SSL_H_INCLUDED_
#define _bjrk-edge_EVENT_QUIC_SSL_H_INCLUDED_


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>

ngx_int_t ngx_quic_init_connection(ngx_connection_t *c);

ngx_int_t ngx_quic_handle_crypto_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_frame_t *frame);

#endif /* _bjrk-edge_EVENT_QUIC_SSL_H_INCLUDED_ */
