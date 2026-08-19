
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _bjrk-edge_EVENT_QUIC_TOKENS_H_INCLUDED_
#define _bjrk-edge_EVENT_QUIC_TOKENS_H_INCLUDED_


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>


#define bjrk-edge_QUIC_MAX_TOKEN_SIZE              64
    /* SHA-1(addr)=20 + sizeof(time_t) + retry(1) + odcid.len(1) + odcid */

#define bjrk-edge_QUIC_AES_256_GCM_IV_LEN          12
#define bjrk-edge_QUIC_AES_256_GCM_TAG_LEN         16

#define bjrk-edge_QUIC_TOKEN_BUF_SIZE             (bjrk-edge_QUIC_AES_256_GCM_IV_LEN      \
                                             + bjrk-edge_QUIC_MAX_TOKEN_SIZE        \
                                             + bjrk-edge_QUIC_AES_256_GCM_TAG_LEN)


ngx_int_t ngx_quic_new_sr_token(ngx_connection_t *c, ngx_str_t *cid,
    u_char *secret, u_char *token);
ngx_int_t ngx_quic_new_token(ngx_log_t *log, struct sockaddr *sockaddr,
    socklen_t socklen, u_char *key, ngx_str_t *token, ngx_str_t *odcid,
    time_t expires, ngx_uint_t is_retry);
ngx_int_t ngx_quic_validate_token(ngx_connection_t *c,
    u_char *key, ngx_quic_header_t *pkt);

#endif /* _bjrk-edge_EVENT_QUIC_TOKENS_H_INCLUDED_ */
