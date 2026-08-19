
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>
#include <bjrk-edge_stream.h>


typedef struct {
    ngx_addr_t                      *addr;
    ngx_stream_complex_value_t      *value;
#if (bjrk-edge_HAVE_TRANSPARENT_PROXY)
    ngx_uint_t                       transparent; /* unsigned  transparent:1; */
#endif
} ngx_stream_upstream_local_t;


typedef struct {
    ngx_msec_t                       connect_timeout;
    ngx_msec_t                       timeout;
    ngx_msec_t                       next_upstream_timeout;
    size_t                           buffer_size;
    ngx_stream_complex_value_t      *upload_rate;
    ngx_stream_complex_value_t      *download_rate;
    ngx_uint_t                       requests;
    ngx_uint_t                       responses;
    ngx_uint_t                       next_upstream_tries;
    ngx_flag_t                       next_upstream;
    ngx_uint_t                       proxy_protocol;
    ngx_flag_t                       half_close;
    ngx_stream_upstream_local_t     *local;
    ngx_flag_t                       socket_keepalive;
    size_t                           socket_rcvbuf;
    size_t                           socket_sndbuf;

#if (bjrk-edge_STREAM_SSL)
    ngx_flag_t                       ssl_enable;
    ngx_flag_t                       ssl_session_reuse;
    ngx_uint_t                       ssl_protocols;
    ngx_str_t                        ssl_ciphers;
    ngx_stream_complex_value_t      *ssl_name;
    ngx_flag_t                       ssl_server_name;
    ngx_array_t                     *ssl_alpn;

    ngx_flag_t                       ssl_verify;
    ngx_uint_t                       ssl_verify_depth;
    ngx_str_t                        ssl_trusted_certificate;
    ngx_str_t                        ssl_crl;
    ngx_stream_complex_value_t      *ssl_certificate;
    ngx_stream_complex_value_t      *ssl_certificate_key;
    ngx_ssl_cache_t                 *ssl_certificate_cache;
    ngx_array_t                     *ssl_passwords;
    ngx_array_t                     *ssl_conf_commands;

    ngx_ssl_t                       *ssl;
#endif

    ngx_stream_upstream_srv_conf_t  *upstream;
    ngx_stream_complex_value_t      *upstream_value;
} ngx_stream_proxy_srv_conf_t;


static void ngx_stream_proxy_handler(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_proxy_eval(ngx_stream_session_t *s,
    ngx_stream_proxy_srv_conf_t *pscf);
static ngx_int_t ngx_stream_proxy_set_local(ngx_stream_session_t *s,
    ngx_stream_upstream_t *u, ngx_stream_upstream_local_t *local);
static void ngx_stream_proxy_connect(ngx_stream_session_t *s);
static void ngx_stream_proxy_init_upstream(ngx_stream_session_t *s);
static void ngx_stream_proxy_resolve_handler(ngx_resolver_ctx_t *ctx);
static void ngx_stream_proxy_upstream_handler(ngx_event_t *ev);
static void ngx_stream_proxy_downstream_handler(ngx_event_t *ev);
static void ngx_stream_proxy_process_connection(ngx_event_t *ev,
    ngx_uint_t from_upstream);
static void ngx_stream_proxy_connect_handler(ngx_event_t *ev);
static ngx_int_t ngx_stream_proxy_test_connect(ngx_connection_t *c);
static void ngx_stream_proxy_process(ngx_stream_session_t *s,
    ngx_uint_t from_upstream, ngx_uint_t do_write);
static ngx_int_t ngx_stream_proxy_test_finalize(ngx_stream_session_t *s,
    ngx_uint_t from_upstream);
static void ngx_stream_proxy_next_upstream(ngx_stream_session_t *s);
static void ngx_stream_proxy_finalize(ngx_stream_session_t *s, ngx_uint_t rc);
static u_char *ngx_stream_proxy_log_error(ngx_log_t *log, u_char *buf,
    size_t len);

static void *ngx_stream_proxy_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_proxy_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_stream_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_proxy_bind(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

#if (bjrk-edge_STREAM_SSL)

static ngx_int_t ngx_stream_proxy_send_proxy_protocol(ngx_stream_session_t *s);
static char *ngx_stream_proxy_ssl_alpn_set_slot(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_proxy_ssl_certificate_cache(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_proxy_ssl_password_file(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_proxy_ssl_conf_command_check(ngx_conf_t *cf, void *post,
    void *data);
static void ngx_stream_proxy_ssl_init_connection(ngx_stream_session_t *s);
static void ngx_stream_proxy_ssl_handshake(ngx_connection_t *pc);
static void ngx_stream_proxy_ssl_save_session(ngx_connection_t *c);
static ngx_int_t ngx_stream_proxy_ssl_name(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_proxy_ssl_alpn(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_proxy_ssl_certificate(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_proxy_merge_ssl(ngx_conf_t *cf,
    ngx_stream_proxy_srv_conf_t *conf, ngx_stream_proxy_srv_conf_t *prev);
static ngx_int_t ngx_stream_proxy_merge_ssl_passwords(ngx_conf_t *cf,
    ngx_stream_proxy_srv_conf_t *conf, ngx_stream_proxy_srv_conf_t *prev);
static ngx_int_t ngx_stream_proxy_set_ssl(ngx_conf_t *cf,
    ngx_stream_proxy_srv_conf_t *pscf);


static ngx_conf_bitmask_t  ngx_stream_proxy_ssl_protocols[] = {
    { ngx_string("SSLv2"), bjrk-edge_SSL_SSLv2 },
    { ngx_string("SSLv3"), bjrk-edge_SSL_SSLv3 },
    { ngx_string("TLSv1"), bjrk-edge_SSL_TLSv1 },
    { ngx_string("TLSv1.1"), bjrk-edge_SSL_TLSv1_1 },
    { ngx_string("TLSv1.2"), bjrk-edge_SSL_TLSv1_2 },
    { ngx_string("TLSv1.3"), bjrk-edge_SSL_TLSv1_3 },
    { ngx_null_string, 0 }
};

static ngx_conf_post_t  ngx_stream_proxy_ssl_conf_command_post =
    { ngx_stream_proxy_ssl_conf_command_check };

#endif


static ngx_conf_deprecated_t  ngx_conf_deprecated_proxy_downstream_buffer = {
    ngx_conf_deprecated, "proxy_downstream_buffer", "proxy_buffer_size"
};

static ngx_conf_deprecated_t  ngx_conf_deprecated_proxy_upstream_buffer = {
    ngx_conf_deprecated, "proxy_upstream_buffer", "proxy_buffer_size"
};


static ngx_conf_enum_t  ngx_stream_proxy_protocol_versions[] = {
    { ngx_string("off"), 0 },
    { ngx_string("on"), 1 },
    { ngx_string("v2"), 2 },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_stream_proxy_commands[] = {

    { ngx_string("proxy_pass"),
      bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE1,
      ngx_stream_proxy_pass,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_bind"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE12,
      ngx_stream_proxy_bind,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_socket_keepalive"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_FLAG,
      ngx_conf_set_flag_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, socket_keepalive),
      NULL },

    { ngx_string("proxy_socket_rcvbuf"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE1,
      ngx_conf_set_size_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, socket_rcvbuf),
      NULL },

    { ngx_string("proxy_socket_sndbuf"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE1,
      ngx_conf_set_size_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, socket_sndbuf),
      NULL },

    { ngx_string("proxy_connect_timeout"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, connect_timeout),
      NULL },

    { ngx_string("proxy_timeout"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, timeout),
      NULL },

    { ngx_string("proxy_buffer_size"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE1,
      ngx_conf_set_size_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, buffer_size),
      NULL },

    { ngx_string("proxy_downstream_buffer"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE1,
      ngx_conf_set_size_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, buffer_size),
      &ngx_conf_deprecated_proxy_downstream_buffer },

    { ngx_string("proxy_upstream_buffer"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE1,
      ngx_conf_set_size_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, buffer_size),
      &ngx_conf_deprecated_proxy_upstream_buffer },

    { ngx_string("proxy_upload_rate"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE1,
      ngx_stream_set_complex_value_size_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, upload_rate),
      NULL },

    { ngx_string("proxy_download_rate"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE1,
      ngx_stream_set_complex_value_size_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, download_rate),
      NULL },

    { ngx_string("proxy_requests"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE1,
      ngx_conf_set_num_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, requests),
      NULL },

    { ngx_string("proxy_responses"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE1,
      ngx_conf_set_num_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, responses),
      NULL },

    { ngx_string("proxy_next_upstream"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_FLAG,
      ngx_conf_set_flag_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, next_upstream),
      NULL },

    { ngx_string("proxy_next_upstream_tries"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE1,
      ngx_conf_set_num_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, next_upstream_tries),
      NULL },

    { ngx_string("proxy_next_upstream_timeout"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, next_upstream_timeout),
      NULL },

    { ngx_string("proxy_protocol"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, proxy_protocol),
      &ngx_stream_proxy_protocol_versions },

    { ngx_string("proxy_half_close"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_FLAG,
      ngx_conf_set_flag_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, half_close),
      NULL },

#if (bjrk-edge_STREAM_SSL)

    { ngx_string("proxy_ssl"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_FLAG,
      ngx_conf_set_flag_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_enable),
      NULL },

    { ngx_string("proxy_ssl_session_reuse"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_FLAG,
      ngx_conf_set_flag_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_session_reuse),
      NULL },

    { ngx_string("proxy_ssl_protocols"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_protocols),
      &ngx_stream_proxy_ssl_protocols },

    { ngx_string("proxy_ssl_ciphers"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE1,
      ngx_conf_set_str_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_ciphers),
      NULL },

    { ngx_string("proxy_ssl_name"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE1,
      ngx_stream_set_complex_value_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_name),
      NULL },

    { ngx_string("proxy_ssl_server_name"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_FLAG,
      ngx_conf_set_flag_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_server_name),
      NULL },

    { ngx_string("proxy_ssl_alpn"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_1MORE,
      ngx_stream_proxy_ssl_alpn_set_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_ssl_verify"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_FLAG,
      ngx_conf_set_flag_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_verify),
      NULL },

    { ngx_string("proxy_ssl_verify_depth"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE1,
      ngx_conf_set_num_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_verify_depth),
      NULL },

    { ngx_string("proxy_ssl_trusted_certificate"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE1,
      ngx_conf_set_str_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_trusted_certificate),
      NULL },

    { ngx_string("proxy_ssl_crl"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE1,
      ngx_conf_set_str_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_crl),
      NULL },

    { ngx_string("proxy_ssl_certificate"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE1,
      ngx_stream_set_complex_value_zero_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_certificate),
      NULL },

    { ngx_string("proxy_ssl_certificate_key"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE1,
      ngx_stream_set_complex_value_zero_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_certificate_key),
      NULL },

    { ngx_string("proxy_ssl_certificate_cache"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE123,
      ngx_stream_proxy_ssl_certificate_cache,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_ssl_password_file"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE1,
      ngx_stream_proxy_ssl_password_file,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_ssl_conf_command"),
      bjrk-edge_STREAM_MAIN_CONF|bjrk-edge_STREAM_SRV_CONF|bjrk-edge_CONF_TAKE2,
      ngx_conf_set_keyval_slot,
      bjrk-edge_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_conf_commands),
      &ngx_stream_proxy_ssl_conf_command_post },

#endif

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_proxy_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_proxy_create_srv_conf,      /* create server configuration */
    ngx_stream_proxy_merge_srv_conf        /* merge server configuration */
};


ngx_module_t  ngx_stream_proxy_module = {
    bjrk-edge_MODULE_V1,
    &ngx_stream_proxy_module_ctx,          /* module context */
    ngx_stream_proxy_commands,             /* module directives */
    bjrk-edge_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    bjrk-edge_MODULE_V1_PADDING
};


static void
ngx_stream_proxy_handler(ngx_stream_session_t *s)
{
    u_char                           *p;
    ngx_str_t                        *host;
    ngx_uint_t                        i;
    ngx_connection_t                 *c;
    ngx_resolver_ctx_t               *ctx, temp;
    ngx_stream_upstream_t            *u;
    ngx_stream_core_srv_conf_t       *cscf;
    ngx_stream_proxy_srv_conf_t      *pscf;
    ngx_stream_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_stream_upstream_main_conf_t  *umcf;

    c = s->connection;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    ngx_log_debug0(bjrk-edge_LOG_DEBUG_STREAM, c->log, 0,
                   "proxy connection handler");

    u = ngx_pcalloc(c->pool, sizeof(ngx_stream_upstream_t));
    if (u == NULL) {
        ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    s->upstream = u;

    s->log_handler = ngx_stream_proxy_log_error;

    u->requests = 1;

    u->peer.log = c->log;
    u->peer.log_error = bjrk-edge_ERROR_ERR;

    if (ngx_stream_proxy_set_local(s, u, pscf->local) != bjrk-edge_OK) {
        ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (pscf->socket_keepalive) {
        u->peer.so_keepalive = 1;
    }

    if (pscf->socket_rcvbuf) {
        u->peer.rcvbuf = (int) pscf->socket_rcvbuf;
    }

    if (pscf->socket_sndbuf) {
        u->peer.sndbuf = (int) pscf->socket_sndbuf;
    }

    u->peer.type = c->type;
    u->start_sec = ngx_time();

    c->write->handler = ngx_stream_proxy_downstream_handler;
    c->read->handler = ngx_stream_proxy_downstream_handler;

    s->upstream_states = ngx_array_create(c->pool, 1,
                                          sizeof(ngx_stream_upstream_state_t));
    if (s->upstream_states == NULL) {
        ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    p = ngx_pnalloc(c->pool, pscf->buffer_size);
    if (p == NULL) {
        ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->downstream_buf.start = p;
    u->downstream_buf.end = p + pscf->buffer_size;
    u->downstream_buf.pos = p;
    u->downstream_buf.last = p;

    if (c->read->ready) {
        ngx_post_event(c->read, &ngx_posted_events);
    }

    if (pscf->upstream_value) {
        if (ngx_stream_proxy_eval(s, pscf) != bjrk-edge_OK) {
            ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (u->resolved == NULL) {

        uscf = pscf->upstream;

    } else {

#if (bjrk-edge_STREAM_SSL)
        u->ssl_name = u->resolved->host;
#endif

        host = &u->resolved->host;

        umcf = ngx_stream_get_module_main_conf(s, ngx_stream_upstream_module);

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {

            uscf = uscfp[i];

            if (uscf->host.len == host->len
                && ((uscf->port == 0 && u->resolved->no_port)
                     || uscf->port == u->resolved->port)
                && ngx_strncasecmp(uscf->host.data, host->data, host->len) == 0)
            {
                goto found;
            }
        }

        if (u->resolved->sockaddr) {

            if (u->resolved->port == 0
                && u->resolved->sockaddr->sa_family != AF_UNIX)
            {
                ngx_log_error(bjrk-edge_LOG_ERR, c->log, 0,
                              "no port in upstream \"%V\"", host);
                ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            if (ngx_stream_upstream_create_round_robin_peer(s, u->resolved)
                != bjrk-edge_OK)
            {
                ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            ngx_stream_proxy_connect(s);

            return;
        }

        if (u->resolved->port == 0) {
            ngx_log_error(bjrk-edge_LOG_ERR, c->log, 0,
                          "no port in upstream \"%V\"", host);
            ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        temp.name = *host;

        cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);

        ctx = ngx_resolve_start(cscf->resolver, &temp);
        if (ctx == NULL) {
            ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        if (ctx == bjrk-edge_NO_RESOLVER) {
            ngx_log_error(bjrk-edge_LOG_ERR, c->log, 0,
                          "no resolver defined to resolve %V", host);
            ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        ctx->name = *host;
        ctx->handler = ngx_stream_proxy_resolve_handler;
        ctx->data = s;
        ctx->timeout = cscf->resolver_timeout;

        u->resolved->ctx = ctx;

        if (ngx_resolve_name(ctx) != bjrk-edge_OK) {
            u->resolved->ctx = NULL;
            ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

found:

    if (uscf == NULL) {
        ngx_log_error(bjrk-edge_LOG_ALERT, c->log, 0, "no upstream configuration");
        ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->upstream = uscf;

#if (bjrk-edge_STREAM_SSL)
    u->ssl_name = uscf->host;
#endif

    if (uscf->peer.init(s, uscf) != bjrk-edge_OK) {
        ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->peer.start_time = ngx_current_msec;

    if (pscf->next_upstream_tries
        && u->peer.tries > pscf->next_upstream_tries)
    {
        u->peer.tries = pscf->next_upstream_tries;
    }

    ngx_stream_proxy_connect(s);
}


static ngx_int_t
ngx_stream_proxy_eval(ngx_stream_session_t *s,
    ngx_stream_proxy_srv_conf_t *pscf)
{
    ngx_str_t               host;
    ngx_url_t               url;
    ngx_stream_upstream_t  *u;

    if (ngx_stream_complex_value(s, pscf->upstream_value, &host) != bjrk-edge_OK) {
        return bjrk-edge_ERROR;
    }

    ngx_memzero(&url, sizeof(ngx_url_t));

    url.url = host;
    url.no_resolve = 1;

    if (ngx_parse_url(s->connection->pool, &url) != bjrk-edge_OK) {
        if (url.err) {
            ngx_log_error(bjrk-edge_LOG_ERR, s->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return bjrk-edge_ERROR;
    }

    u = s->upstream;

    u->resolved = ngx_pcalloc(s->connection->pool,
                              sizeof(ngx_stream_upstream_resolved_t));
    if (u->resolved == NULL) {
        return bjrk-edge_ERROR;
    }

    if (url.addrs) {
        u->resolved->sockaddr = url.addrs[0].sockaddr;
        u->resolved->socklen = url.addrs[0].socklen;
        u->resolved->name = url.addrs[0].name;
        u->resolved->naddrs = 1;
    }

    u->resolved->host = url.host;
    u->resolved->port = url.port;
    u->resolved->no_port = url.no_port;

    return bjrk-edge_OK;
}


static ngx_int_t
ngx_stream_proxy_set_local(ngx_stream_session_t *s, ngx_stream_upstream_t *u,
    ngx_stream_upstream_local_t *local)
{
    ngx_int_t    rc;
    ngx_str_t    val;
    ngx_addr_t  *addr;

    if (local == NULL) {
        u->peer.local = NULL;
        return bjrk-edge_OK;
    }

#if (bjrk-edge_HAVE_TRANSPARENT_PROXY)
    u->peer.transparent = local->transparent;
#endif

    if (local->value == NULL) {
        u->peer.local = local->addr;
        return bjrk-edge_OK;
    }

    if (ngx_stream_complex_value(s, local->value, &val) != bjrk-edge_OK) {
        return bjrk-edge_ERROR;
    }

    if (val.len == 0) {
        u->peer.local = NULL;
        return bjrk-edge_OK;
    }

    addr = ngx_palloc(s->connection->pool, sizeof(ngx_addr_t));
    if (addr == NULL) {
        return bjrk-edge_ERROR;
    }

    rc = ngx_parse_addr_port(s->connection->pool, addr, val.data, val.len);
    if (rc == bjrk-edge_ERROR) {
        return bjrk-edge_ERROR;
    }

    if (rc != bjrk-edge_OK) {
        ngx_log_error(bjrk-edge_LOG_ERR, s->connection->log, 0,
                      "invalid local address \"%V\"", &val);
        u->peer.local = NULL;
        return bjrk-edge_OK;
    }

    addr->name = val;
    u->peer.local = addr;

    return bjrk-edge_OK;
}


static void
ngx_stream_proxy_connect(ngx_stream_session_t *s)
{
    ngx_int_t                     rc;
    ngx_connection_t             *c, *pc;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;

    c = s->connection;

    c->log->action = "connecting to upstream";

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    u = s->upstream;

    u->connected = 0;
    u->proxy_protocol = pscf->proxy_protocol;

    if (u->state) {
        u->state->response_time = ngx_current_msec - u->start_time;
    }

    u->state = ngx_array_push(s->upstream_states);
    if (u->state == NULL) {
        ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_memzero(u->state, sizeof(ngx_stream_upstream_state_t));

    u->start_time = ngx_current_msec;

    u->state->connect_time = (ngx_msec_t) -1;
    u->state->first_byte_time = (ngx_msec_t) -1;
    u->state->response_time = (ngx_msec_t) -1;

    rc = ngx_event_connect_peer(&u->peer);

    ngx_log_debug1(bjrk-edge_LOG_DEBUG_STREAM, c->log, 0, "proxy connect: %i", rc);

    if (rc == bjrk-edge_ERROR) {
        ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->state->peer = u->peer.name;

#if (bjrk-edge_STREAM_UPSTREAM_ZONE)
    if (u->upstream && u->upstream->shm_zone
        && (u->upstream->flags & bjrk-edge_STREAM_UPSTREAM_MODIFY))
    {
        u->state->peer = ngx_palloc(s->connection->pool,
                                    sizeof(ngx_str_t) + u->peer.name->len);
        if (u->state->peer == NULL) {
            ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        u->state->peer->len = u->peer.name->len;
        u->state->peer->data = (u_char *) (u->state->peer + 1);
        ngx_memcpy(u->state->peer->data, u->peer.name->data, u->peer.name->len);

        u->peer.name = u->state->peer;
    }
#endif

    if (rc == bjrk-edge_BUSY) {
        ngx_log_error(bjrk-edge_LOG_ERR, c->log, 0, "no live upstreams");
        ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_BAD_GATEWAY);
        return;
    }

    if (rc == bjrk-edge_DECLINED) {
        ngx_stream_proxy_next_upstream(s);
        return;
    }

    /* rc == bjrk-edge_OK || rc == bjrk-edge_AGAIN || rc == bjrk-edge_DONE */

    pc = u->peer.connection;

    pc->data = s;
    pc->log = c->log;
    pc->pool = c->pool;
    pc->read->log = c->log;
    pc->write->log = c->log;

    if (rc != bjrk-edge_AGAIN) {
        ngx_stream_proxy_init_upstream(s);
        return;
    }

    pc->read->handler = ngx_stream_proxy_connect_handler;
    pc->write->handler = ngx_stream_proxy_connect_handler;

    ngx_add_timer(pc->write, pscf->connect_timeout);
}


static void
ngx_stream_proxy_init_upstream(ngx_stream_session_t *s)
{
    u_char                       *p;
    size_t                        size;
    ngx_chain_t                  *cl;
    ngx_connection_t             *c, *pc;
    ngx_log_handler_pt            handler;
    ngx_stream_upstream_t        *u;
    ngx_stream_core_srv_conf_t   *cscf;
    ngx_stream_proxy_srv_conf_t  *pscf;
    static u_char                 buf[bjrk-edge_PROXY_PROTOCOL_MAX_HEADER];

    u = s->upstream;
    pc = u->peer.connection;

    cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);

    if (pc->type == SOCK_STREAM
        && cscf->tcp_nodelay
        && ngx_tcp_nodelay(pc) != bjrk-edge_OK)
    {
        ngx_stream_proxy_next_upstream(s);
        return;
    }

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

#if (bjrk-edge_STREAM_SSL)

    if (pc->type == SOCK_STREAM && pscf->ssl_enable) {

        if (u->proxy_protocol) {
            if (ngx_stream_proxy_send_proxy_protocol(s) != bjrk-edge_OK) {
                return;
            }

            u->proxy_protocol = 0;
        }

        if (pc->ssl == NULL) {
            ngx_stream_proxy_ssl_init_connection(s);
            return;
        }
    }

#endif

    c = s->connection;

    if (c->log->log_level >= bjrk-edge_LOG_INFO) {
        ngx_str_t  str;
        u_char     addr[bjrk-edge_SOCKADDR_STRLEN];

        str.len = bjrk-edge_SOCKADDR_STRLEN;
        str.data = addr;

        if (ngx_connection_local_sockaddr(pc, &str, 1) == bjrk-edge_OK) {
            handler = c->log->handler;
            c->log->handler = NULL;

            ngx_log_error(bjrk-edge_LOG_INFO, c->log, 0,
                          "%sproxy %V connected to %V",
                          pc->type == SOCK_DGRAM ? "udp " : "",
                          &str, u->peer.name);

            c->log->handler = handler;
        }
    }

    u->state->connect_time = ngx_current_msec - u->start_time;

    if (u->peer.notify) {
        u->peer.notify(&u->peer, u->peer.data,
                       bjrk-edge_STREAM_UPSTREAM_NOTIFY_CONNECT);
    }

    if (u->upstream_buf.start == NULL) {
        p = ngx_pnalloc(c->pool, pscf->buffer_size);
        if (p == NULL) {
            ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        u->upstream_buf.start = p;
        u->upstream_buf.end = p + pscf->buffer_size;
        u->upstream_buf.pos = p;
        u->upstream_buf.last = p;
    }

    if (c->buffer && c->buffer->pos <= c->buffer->last) {
        ngx_log_debug1(bjrk-edge_LOG_DEBUG_STREAM, c->log, 0,
                       "stream proxy add preread buffer: %uz",
                       c->buffer->last - c->buffer->pos);

        cl = ngx_chain_get_free_buf(c->pool, &u->free);
        if (cl == NULL) {
            ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        *cl->buf = *c->buffer;

        cl->buf->tag = (ngx_buf_tag_t) &ngx_stream_proxy_module;
        cl->buf->temporary = (cl->buf->pos == cl->buf->last) ? 0 : 1;
        cl->buf->flush = 1;

        cl->next = u->upstream_out;
        u->upstream_out = cl;
    }

    if (u->proxy_protocol) {
        ngx_log_debug0(bjrk-edge_LOG_DEBUG_STREAM, c->log, 0,
                       "stream proxy add PROXY protocol header");

        if (u->proxy_protocol == 2) {
            p = ngx_proxy_protocol_v2_write(c, buf, buf + sizeof(buf), NULL);

        } else {
            p = ngx_proxy_protocol_write(c, buf, buf + sizeof(buf));
        }

        if (p == NULL) {
            ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        size = p - buf;

        p = ngx_pnalloc(c->pool, size);
        if (p == NULL) {
            ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        ngx_memcpy(p, buf, size);

        cl = ngx_chain_get_free_buf(c->pool, &u->free);
        if (cl == NULL) {
            ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        cl->buf->pos = p;
        cl->buf->last = p + size;

        cl->buf->temporary = 1;
        cl->buf->flush = 0;
        cl->buf->last_buf = 0;
        cl->buf->tag = (ngx_buf_tag_t) &ngx_stream_proxy_module;

        cl->next = u->upstream_out;
        u->upstream_out = cl;

        u->proxy_protocol = 0;
    }

    u->upload_rate = ngx_stream_complex_value_size(s, pscf->upload_rate, 0);
    u->download_rate = ngx_stream_complex_value_size(s, pscf->download_rate, 0);

    u->connected = 1;

    pc->read->handler = ngx_stream_proxy_upstream_handler;
    pc->write->handler = ngx_stream_proxy_upstream_handler;

    if (pc->read->ready) {
        ngx_post_event(pc->read, &ngx_posted_events);
    }

    ngx_stream_proxy_process(s, 0, 1);
}


#if (bjrk-edge_STREAM_SSL)

static ngx_int_t
ngx_stream_proxy_send_proxy_protocol(ngx_stream_session_t *s)
{
    u_char                       *p;
    size_t                        size;
    ssize_t                       n;
    ngx_connection_t             *c, *pc;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;
    static u_char                 buf[bjrk-edge_PROXY_PROTOCOL_MAX_HEADER];

    c = s->connection;

    ngx_log_debug0(bjrk-edge_LOG_DEBUG_STREAM, c->log, 0,
                   "stream proxy send PROXY protocol header");

    u = s->upstream;

    if (u->proxy_protocol == 2) {
        p = ngx_proxy_protocol_v2_write(c, buf, buf + sizeof(buf), NULL);

    } else {
        p = ngx_proxy_protocol_write(c, buf, buf + sizeof(buf));
    }

    if (p == NULL) {
        ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
        return bjrk-edge_ERROR;
    }

    pc = u->peer.connection;

    size = p - buf;

    n = pc->send(pc, buf, size);

    if (n == bjrk-edge_AGAIN) {
        if (ngx_handle_write_event(pc->write, 0) != bjrk-edge_OK) {
            ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
            return bjrk-edge_ERROR;
        }

        pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

        ngx_add_timer(pc->write, pscf->timeout);

        pc->write->handler = ngx_stream_proxy_connect_handler;

        return bjrk-edge_AGAIN;
    }

    if (n == bjrk-edge_ERROR) {
        ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_OK);
        return bjrk-edge_ERROR;
    }

    if (n != (ssize_t) size) {

        /*
         * PROXY protocol specification:
         * The sender must always ensure that the header
         * is sent at once, so that the transport layer
         * maintains atomicity along the path to the receiver.
         */

        ngx_log_error(bjrk-edge_LOG_ERR, c->log, 0,
                      "could not send PROXY protocol header at once");

        ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);

        return bjrk-edge_ERROR;
    }

    return bjrk-edge_OK;
}


static char *
ngx_stream_proxy_ssl_alpn_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

    ngx_stream_proxy_srv_conf_t *pscf = conf;

    ngx_str_t                           *value;
    ngx_uint_t                           i;
    ngx_stream_complex_value_t          *cv;
    ngx_stream_compile_complex_value_t   ccv;

    if (pscf->ssl_alpn != bjrk-edge_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    pscf->ssl_alpn = ngx_array_create(cf->pool, cf->args->nelts - 1,
                                      sizeof(ngx_stream_complex_value_t));
    if (pscf->ssl_alpn == NULL) {
        return bjrk-edge_CONF_ERROR;
    }

    cv = ngx_array_push_n(pscf->ssl_alpn, cf->args->nelts - 1);

    for (i = 1; i < cf->args->nelts; i++) {
        ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[i];
        ccv.complex_value = &cv[i - 1];

        if (ngx_stream_compile_complex_value(&ccv) != bjrk-edge_OK) {
            return bjrk-edge_CONF_ERROR;
        }

        if (cv[i - 1].lengths == NULL && value[i].len > 255) {
            return "protocol too long";
        }
    }

    return bjrk-edge_CONF_OK;

#else
    ngx_conf_log_error(bjrk-edge_LOG_EMERG, cf, 0,
                       "the \"proxy_ssl_alpn\" directive requires "
                       "OpenSSL with ALPN support");

    return bjrk-edge_CONF_ERROR;
#endif
}


static char *
ngx_stream_proxy_ssl_certificate_cache(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_proxy_srv_conf_t *pscf = conf;

    time_t       inactive, valid;
    ngx_str_t   *value, s;
    ngx_int_t    max;
    ngx_uint_t   i;

    if (pscf->ssl_certificate_cache != bjrk-edge_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    max = 0;
    inactive = 10;
    valid = 60;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "max=", 4) == 0) {

            max = ngx_atoi(value[i].data + 4, value[i].len - 4);
            if (max <= 0) {
                goto failed;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "inactive=", 9) == 0) {

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            inactive = ngx_parse_time(&s, 1);
            if (inactive == (time_t) bjrk-edge_ERROR) {
                goto failed;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "valid=", 6) == 0) {

            s.len = value[i].len - 6;
            s.data = value[i].data + 6;

            valid = ngx_parse_time(&s, 1);
            if (valid == (time_t) bjrk-edge_ERROR) {
                goto failed;
            }

            continue;
        }

        if (ngx_strcmp(value[i].data, "off") == 0) {

            pscf->ssl_certificate_cache = NULL;

            continue;
        }

    failed:

        ngx_conf_log_error(bjrk-edge_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return bjrk-edge_CONF_ERROR;
    }

    if (pscf->ssl_certificate_cache == NULL) {
        return bjrk-edge_CONF_OK;
    }

    if (max == 0) {
        ngx_conf_log_error(bjrk-edge_LOG_EMERG, cf, 0,
                           "\"proxy_ssl_certificate_cache\" must have "
                           "the \"max\" parameter");
        return bjrk-edge_CONF_ERROR;
    }

    pscf->ssl_certificate_cache = ngx_ssl_cache_init(cf->pool, max, valid,
                                                     inactive);
    if (pscf->ssl_certificate_cache == NULL) {
        return bjrk-edge_CONF_ERROR;
    }

    return bjrk-edge_CONF_OK;
}


static char *
ngx_stream_proxy_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_proxy_srv_conf_t *pscf = conf;

    ngx_str_t  *value;

    if (pscf->ssl_passwords != bjrk-edge_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    pscf->ssl_passwords = ngx_ssl_read_password_file(cf, &value[1]);

    if (pscf->ssl_passwords == NULL) {
        return bjrk-edge_CONF_ERROR;
    }

    return bjrk-edge_CONF_OK;
}


static char *
ngx_stream_proxy_ssl_conf_command_check(ngx_conf_t *cf, void *post, void *data)
{
#ifndef SSL_CONF_FLAG_FILE
    return "is not supported on this platform";
#else
    return bjrk-edge_CONF_OK;
#endif
}


static void
ngx_stream_proxy_ssl_init_connection(ngx_stream_session_t *s)
{
    ngx_int_t                     rc;
    ngx_connection_t             *pc;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;

    u = s->upstream;

    pc = u->peer.connection;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    if (ngx_ssl_create_connection(pscf->ssl, pc, bjrk-edge_SSL_BUFFER|bjrk-edge_SSL_CLIENT)
        != bjrk-edge_OK)
    {
        ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (pscf->ssl_server_name || pscf->ssl_verify) {
        if (ngx_stream_proxy_ssl_name(s) != bjrk-edge_OK) {
            ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (pscf->ssl_alpn) {
        if (ngx_stream_proxy_ssl_alpn(s) != bjrk-edge_OK) {
            ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (pscf->ssl_certificate
        && pscf->ssl_certificate->value.len
        && (pscf->ssl_certificate->lengths
            || pscf->ssl_certificate_key->lengths))
    {
        if (ngx_stream_proxy_ssl_certificate(s) != bjrk-edge_OK) {
            ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (pscf->ssl_session_reuse) {
        pc->ssl->save_session = ngx_stream_proxy_ssl_save_session;

        if (u->peer.set_session(&u->peer, u->peer.data) != bjrk-edge_OK) {
            ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    s->connection->log->action = "SSL handshaking to upstream";

    rc = ngx_ssl_handshake(pc);

    if (rc == bjrk-edge_AGAIN) {

        if (!pc->write->timer_set) {
            ngx_add_timer(pc->write, pscf->connect_timeout);
        }

        pc->ssl->handler = ngx_stream_proxy_ssl_handshake;
        return;
    }

    ngx_stream_proxy_ssl_handshake(pc);
}


static void
ngx_stream_proxy_ssl_handshake(ngx_connection_t *pc)
{
    long                          rc;
    ngx_stream_session_t         *s;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;

    s = pc->data;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    if (pc->ssl->handshaked) {

        if (pscf->ssl_verify) {
            rc = SSL_get_verify_result(pc->ssl->connection);

            if (rc != X509_V_OK) {
                ngx_log_error(bjrk-edge_LOG_ERR, pc->log, 0,
                              "upstream SSL certificate verify error: (%l:%s)",
                              rc, X509_verify_cert_error_string(rc));
                goto failed;
            }

            u = s->upstream;

            if (ngx_ssl_check_host(pc, &u->ssl_name) != bjrk-edge_OK) {
                ngx_log_error(bjrk-edge_LOG_ERR, pc->log, 0,
                              "upstream SSL certificate does not match \"%V\"",
                              &u->ssl_name);
                goto failed;
            }
        }

        if (pc->write->timer_set) {
            ngx_del_timer(pc->write);
        }

        ngx_stream_proxy_init_upstream(s);

        return;
    }

failed:

    ngx_stream_proxy_next_upstream(s);
}


static void
ngx_stream_proxy_ssl_save_session(ngx_connection_t *c)
{
    ngx_stream_session_t   *s;
    ngx_stream_upstream_t  *u;

    s = c->data;
    u = s->upstream;

    u->peer.save_session(&u->peer, u->peer.data);
}


static ngx_int_t
ngx_stream_proxy_ssl_name(ngx_stream_session_t *s)
{
    u_char                       *p, *last;
    ngx_str_t                     name;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    u = s->upstream;

    if (pscf->ssl_name) {
        if (ngx_stream_complex_value(s, pscf->ssl_name, &name) != bjrk-edge_OK) {
            return bjrk-edge_ERROR;
        }

    } else {
        name = u->ssl_name;
    }

    if (name.len == 0) {
        goto done;
    }

    /*
     * ssl name here may contain port, strip it for compatibility
     * with the http module
     */

    p = name.data;
    last = name.data + name.len;

    if (*p == '[') {
        p = ngx_strlchr(p, last, ']');

        if (p == NULL) {
            p = name.data;
        }
    }

    p = ngx_strlchr(p, last, ':');

    if (p != NULL) {
        name.len = p - name.data;
    }

    if (!pscf->ssl_server_name) {
        goto done;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

    /* as per RFC 6066, literal IPv4 and IPv6 addresses are not permitted */

    if (name.len == 0 || *name.data == '[') {
        goto done;
    }

    if (ngx_inet_addr(name.data, name.len) != INADDR_NONE) {
        goto done;
    }

    /*
     * SSL_set_tlsext_host_name() needs a null-terminated string,
     * hence we explicitly null-terminate name here
     */

    p = ngx_pnalloc(s->connection->pool, name.len + 1);
    if (p == NULL) {
        return bjrk-edge_ERROR;
    }

    (void) ngx_cpystrn(p, name.data, name.len + 1);

    name.data = p;

    ngx_log_debug1(bjrk-edge_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "upstream SSL server name: \"%s\"", name.data);

    if (SSL_set_tlsext_host_name(u->peer.connection->ssl->connection,
                                 (char *) name.data)
        == 0)
    {
        ngx_ssl_error(bjrk-edge_LOG_ERR, s->connection->log, 0,
                      "SSL_set_tlsext_host_name(\"%s\") failed", name.data);
        return bjrk-edge_ERROR;
    }

#endif

done:

    u->ssl_name = name;

    return bjrk-edge_OK;
}


static ngx_int_t
ngx_stream_proxy_ssl_alpn(ngx_stream_session_t *s)
{
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

    size_t                        len;
    u_char                       *p, *buf;
    ngx_str_t                     proto, *value;
    ngx_uint_t                    i;
    ngx_array_t                  *values;
    ngx_connection_t             *c;
    ngx_stream_upstream_t        *u;
    ngx_stream_complex_value_t   *cv;
    ngx_stream_proxy_srv_conf_t  *pscf;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    u = s->upstream;
    c = u->peer.connection;

    values = NULL;
    len = 0;

    cv = pscf->ssl_alpn->elts;

    for (i = 0; i < pscf->ssl_alpn->nelts; i++) {

        if (ngx_stream_complex_value(s, &cv[i], &proto) != bjrk-edge_OK) {
            return bjrk-edge_ERROR;
        }

        if (proto.len == 0 || proto.len > 255) {
            continue;
        }

        if (values == NULL) {
            values = ngx_array_create(c->pool, 1, sizeof(ngx_str_t));
            if (values == NULL) {
                return bjrk-edge_ERROR;
            }
        }

        value = ngx_array_push(values);
        if (value == NULL) {
            return bjrk-edge_ERROR;
        }

        *value = proto;

        len += 1 + proto.len;
    }

    if (len == 0) {
        return bjrk-edge_OK;
    }

    buf = ngx_pnalloc(c->pool, len);
    if (buf == NULL) {
        return bjrk-edge_ERROR;
    }

    p = buf;
    value = values->elts;

    for (i = 0; i < values->nelts; i++) {

        ngx_log_debug1(bjrk-edge_LOG_DEBUG_STREAM, c->log, 0,
                       "upstream SSL ALPN: \"%V\"", &value[i]);

        *p++ = value[i].len;
        p = ngx_cpymem(p, value[i].data, value[i].len);
    }

    if (SSL_set_alpn_protos(c->ssl->connection, buf, p - buf) != 0) {
        ngx_ssl_error(bjrk-edge_LOG_ERR, c->log, 0,
                      "SSL_set_alpn_protos() failed");
        return bjrk-edge_ERROR;
    }

#endif

    return bjrk-edge_OK;
}


static ngx_int_t
ngx_stream_proxy_ssl_certificate(ngx_stream_session_t *s)
{
    ngx_str_t                     cert, key;
    ngx_connection_t             *c;
    ngx_stream_proxy_srv_conf_t  *pscf;

    c = s->upstream->peer.connection;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    if (ngx_stream_complex_value(s, pscf->ssl_certificate, &cert)
        != bjrk-edge_OK)
    {
        return bjrk-edge_ERROR;
    }

    ngx_log_debug1(bjrk-edge_LOG_DEBUG_STREAM, c->log, 0,
                   "stream upstream ssl cert: \"%s\"", cert.data);

    if (*cert.data == '\0') {
        return bjrk-edge_OK;
    }

    if (ngx_stream_complex_value(s, pscf->ssl_certificate_key, &key)
        != bjrk-edge_OK)
    {
        return bjrk-edge_ERROR;
    }

    ngx_log_debug1(bjrk-edge_LOG_DEBUG_STREAM, c->log, 0,
                   "stream upstream ssl key: \"%s\"", key.data);

    if (ngx_ssl_connection_certificate(c, c->pool, &cert, &key,
                                       pscf->ssl_certificate_cache,
                                       pscf->ssl_passwords)
        != bjrk-edge_OK)
    {
        return bjrk-edge_ERROR;
    }

    return bjrk-edge_OK;
}

#endif


static void
ngx_stream_proxy_downstream_handler(ngx_event_t *ev)
{
    ngx_stream_proxy_process_connection(ev, ev->write);
}


static void
ngx_stream_proxy_resolve_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_stream_session_t            *s;
    ngx_stream_upstream_t           *u;
    ngx_stream_proxy_srv_conf_t     *pscf;
    ngx_stream_upstream_resolved_t  *ur;

    s = ctx->data;

    u = s->upstream;
    ur = u->resolved;

    ngx_log_debug0(bjrk-edge_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream upstream resolve");

    if (ctx->state) {
        ngx_log_error(bjrk-edge_LOG_ERR, s->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      ngx_resolver_strerror(ctx->state));

        ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

#if (bjrk-edge_DEBUG)
    {
    u_char      text[bjrk-edge_SOCKADDR_STRLEN];
    ngx_str_t   addr;
    ngx_uint_t  i;

    addr.data = text;

    for (i = 0; i < ctx->naddrs; i++) {
        addr.len = ngx_sock_ntop(ur->addrs[i].sockaddr, ur->addrs[i].socklen,
                                 text, bjrk-edge_SOCKADDR_STRLEN, 0);

        ngx_log_debug1(bjrk-edge_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "name was resolved to %V", &addr);
    }
    }
#endif

    if (ngx_stream_upstream_create_round_robin_peer(s, ur) != bjrk-edge_OK) {
        ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_resolve_name_done(ctx);
    ur->ctx = NULL;

    u->peer.start_time = ngx_current_msec;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    if (pscf->next_upstream_tries
        && u->peer.tries > pscf->next_upstream_tries)
    {
        u->peer.tries = pscf->next_upstream_tries;
    }

    ngx_stream_proxy_connect(s);
}


static void
ngx_stream_proxy_upstream_handler(ngx_event_t *ev)
{
    ngx_stream_proxy_process_connection(ev, !ev->write);
}


static void
ngx_stream_proxy_process_connection(ngx_event_t *ev, ngx_uint_t from_upstream)
{
    ngx_connection_t             *c, *pc;
    ngx_log_handler_pt            handler;
    ngx_stream_session_t         *s;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;

    c = ev->data;
    s = c->data;
    u = s->upstream;

    if (c->close) {
        ngx_log_error(bjrk-edge_LOG_INFO, c->log, 0, "shutdown timeout");
        ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_OK);
        return;
    }

    c = s->connection;
    pc = u->peer.connection;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    if (ev->timedout) {
        ev->timedout = 0;

        if (ev->delayed) {
            ev->delayed = 0;

            if (!ev->ready) {
                if (ngx_handle_read_event(ev, 0) != bjrk-edge_OK) {
                    ngx_stream_proxy_finalize(s,
                                              bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                if (u->connected && !c->read->delayed && !pc->read->delayed) {
                    ngx_add_timer(c->write, pscf->timeout);
                }

                return;
            }

        } else {
            if (s->connection->type == SOCK_DGRAM) {

                if (pscf->responses == bjrk-edge_MAX_INT32_VALUE
                    || (u->responses >= pscf->responses * u->requests))
                {

                    /*
                     * successfully terminate timed out UDP session
                     * if expected number of responses was received
                     */

                    handler = c->log->handler;
                    c->log->handler = NULL;

                    ngx_log_error(bjrk-edge_LOG_INFO, c->log, 0,
                                  "udp timed out"
                                  ", packets from/to client:%ui/%ui"
                                  ", bytes from/to client:%O/%O"
                                  ", bytes from/to upstream:%O/%O",
                                  u->requests, u->responses,
                                  s->received, c->sent, u->received,
                                  pc ? pc->sent : 0);

                    c->log->handler = handler;

                    ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_OK);
                    return;
                }

                ngx_connection_error(pc, bjrk-edge_ETIMEDOUT, "upstream timed out");

                pc->read->error = 1;

                ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_BAD_GATEWAY);

                return;
            }

            ngx_connection_error(c, bjrk-edge_ETIMEDOUT, "connection timed out");

            ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_OK);

            return;
        }

    } else if (ev->delayed) {

        ngx_log_debug0(bjrk-edge_LOG_DEBUG_STREAM, c->log, 0,
                       "stream connection delayed");

        if (ngx_handle_read_event(ev, 0) != bjrk-edge_OK) {
            ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    if (from_upstream && !u->connected) {
        return;
    }

    ngx_stream_proxy_process(s, from_upstream, ev->write);
}


static void
ngx_stream_proxy_connect_handler(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_stream_session_t  *s;

    c = ev->data;
    s = c->data;

    if (ev->timedout) {
        ngx_log_error(bjrk-edge_LOG_ERR, c->log, bjrk-edge_ETIMEDOUT, "upstream timed out");
        ngx_stream_proxy_next_upstream(s);
        return;
    }

    ngx_del_timer(c->write);

    ngx_log_debug0(bjrk-edge_LOG_DEBUG_STREAM, c->log, 0,
                   "stream proxy connect upstream");

    if (ngx_stream_proxy_test_connect(c) != bjrk-edge_OK) {
        ngx_stream_proxy_next_upstream(s);
        return;
    }

    ngx_stream_proxy_init_upstream(s);
}


static ngx_int_t
ngx_stream_proxy_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (bjrk-edge_HAVE_KQUEUE)

    if (ngx_event_flags & bjrk-edge_USE_KQUEUE_EVENT)  {
        err = c->write->kq_errno ? c->write->kq_errno : c->read->kq_errno;

        if (err) {
            (void) ngx_connection_error(c, err,
                                    "kevent() reported that connect() failed");
            return bjrk-edge_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_socket_errno;
        }

        if (err) {
            (void) ngx_connection_error(c, err, "connect() failed");
            return bjrk-edge_ERROR;
        }
    }

    return bjrk-edge_OK;
}


static void
ngx_stream_proxy_process(ngx_stream_session_t *s, ngx_uint_t from_upstream,
    ngx_uint_t do_write)
{
    char                         *recv_action, *send_action;
    off_t                        *received, limit;
    size_t                        size, limit_rate;
    ssize_t                       n;
    ngx_buf_t                    *b;
    ngx_int_t                     rc;
    ngx_uint_t                    flags, *packets;
    ngx_msec_t                    delay;
    ngx_chain_t                  *cl, **ll, **out, **busy;
    ngx_connection_t             *c, *pc, *src, *dst;
    ngx_log_handler_pt            handler;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;

    u = s->upstream;

    c = s->connection;
    pc = u->connected ? u->peer.connection : NULL;

    if (c->type == SOCK_DGRAM && (ngx_terminate || ngx_exiting)) {

        /* socket is already closed on worker shutdown */

        handler = c->log->handler;
        c->log->handler = NULL;

        ngx_log_error(bjrk-edge_LOG_INFO, c->log, 0, "disconnected on shutdown");

        c->log->handler = handler;

        ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_OK);
        return;
    }

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    if (from_upstream) {
        src = pc;
        dst = c;
        b = &u->upstream_buf;
        limit_rate = u->download_rate;
        received = &u->received;
        packets = &u->responses;
        out = &u->downstream_out;
        busy = &u->downstream_busy;
        recv_action = "proxying and reading from upstream";
        send_action = "proxying and sending to client";

    } else {
        src = c;
        dst = pc;
        b = &u->downstream_buf;
        limit_rate = u->upload_rate;
        received = &s->received;
        packets = &u->requests;
        out = &u->upstream_out;
        busy = &u->upstream_busy;
        recv_action = "proxying and reading from client";
        send_action = "proxying and sending to upstream";
    }

    for ( ;; ) {

        if (do_write && dst) {

            if (*out || *busy || dst->buffered) {
                c->log->action = send_action;

                rc = ngx_stream_top_filter(s, *out, from_upstream);

                if (rc == bjrk-edge_ERROR) {
                    ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_OK);
                    return;
                }

                ngx_chain_update_chains(c->pool, &u->free, busy, out,
                                      (ngx_buf_tag_t) &ngx_stream_proxy_module);

                if (*busy == NULL) {
                    b->pos = b->start;
                    b->last = b->start;
                }
            }
        }

        size = b->end - b->last;

        if (size && src->read->ready && !src->read->delayed) {

            if (limit_rate) {
                limit = (off_t) limit_rate * (ngx_time() - u->start_sec + 1)
                        - *received;

                if (limit <= 0) {
                    src->read->delayed = 1;
                    delay = (ngx_msec_t) (- limit * 1000 / limit_rate + 1);
                    ngx_add_timer(src->read, delay);
                    break;
                }

                if (c->type == SOCK_STREAM && (off_t) size > limit) {
                    size = (size_t) limit;
                }
            }

            c->log->action = recv_action;

            n = src->recv(src, b->last, size);

            if (n == bjrk-edge_AGAIN) {
                break;
            }

            if (n == bjrk-edge_ERROR) {
                src->read->eof = 1;
                n = 0;
            }

            if (n >= 0) {
                if (limit_rate) {
                    delay = (ngx_msec_t) (n * 1000 / limit_rate);

                    if (delay > 0) {
                        src->read->delayed = 1;
                        ngx_add_timer(src->read, delay);
                    }
                }

                if (from_upstream) {
                    if (u->state->first_byte_time == (ngx_msec_t) -1) {
                        u->state->first_byte_time = ngx_current_msec
                                                    - u->start_time;

                        if (u->peer.notify) {
                            u->peer.notify(&u->peer, u->peer.data,
                                       bjrk-edge_STREAM_UPSTREAM_NOTIFY_FIRST_BYTE);
                        }
                    }
                }

                for (ll = out; *ll; ll = &(*ll)->next) { /* void */ }

                cl = ngx_chain_get_free_buf(c->pool, &u->free);
                if (cl == NULL) {
                    ngx_stream_proxy_finalize(s,
                                              bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                *ll = cl;

                cl->buf->pos = b->last;
                cl->buf->last = b->last + n;
                cl->buf->tag = (ngx_buf_tag_t) &ngx_stream_proxy_module;

                cl->buf->temporary = (n ? 1 : 0);
                cl->buf->last_buf = src->read->eof;
                cl->buf->flush = !src->read->eof;

                (*packets)++;
                *received += n;
                b->last += n;
                do_write = 1;

                continue;
            }
        }

        break;
    }

    c->log->action = "proxying connection";

    if (ngx_stream_proxy_test_finalize(s, from_upstream) == bjrk-edge_OK) {
        return;
    }

    flags = src->read->eof ? bjrk-edge_CLOSE_EVENT : 0;

    if (ngx_handle_read_event(src->read, flags) != bjrk-edge_OK) {
        ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (dst) {

        if (dst->type == SOCK_STREAM && pscf->half_close
            && src->read->eof && !u->half_closed && !dst->buffered)
        {
            if (ngx_shutdown_socket(dst->fd, bjrk-edge_WRITE_SHUTDOWN) == -1) {
                ngx_connection_error(c, ngx_socket_errno,
                                     ngx_shutdown_socket_n " failed");

                ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            u->half_closed = 1;
            ngx_log_debug1(bjrk-edge_LOG_DEBUG_STREAM, s->connection->log, 0,
                           "stream proxy %s socket shutdown",
                           from_upstream ? "client" : "upstream");
        }

        if (ngx_handle_write_event(dst->write, 0) != bjrk-edge_OK) {
            ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        if (!c->read->delayed && !pc->read->delayed) {
            ngx_add_timer(c->write, pscf->timeout);

        } else if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }
    }
}


static ngx_int_t
ngx_stream_proxy_test_finalize(ngx_stream_session_t *s,
    ngx_uint_t from_upstream)
{
    ngx_connection_t             *c, *pc;
    ngx_log_handler_pt            handler;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    c = s->connection;
    u = s->upstream;
    pc = u->connected ? u->peer.connection : NULL;

    if (c->type == SOCK_DGRAM) {

        if (pscf->requests && u->requests < pscf->requests) {
            return bjrk-edge_DECLINED;
        }

        if (pscf->requests) {
            ngx_delete_udp_connection(c);
        }

        if (pscf->responses == bjrk-edge_MAX_INT32_VALUE
            || u->responses < pscf->responses * u->requests)
        {
            return bjrk-edge_DECLINED;
        }

        if (pc == NULL || c->buffered || pc->buffered) {
            return bjrk-edge_DECLINED;
        }

        handler = c->log->handler;
        c->log->handler = NULL;

        ngx_log_error(bjrk-edge_LOG_INFO, c->log, 0,
                      "udp done"
                      ", packets from/to client:%ui/%ui"
                      ", bytes from/to client:%O/%O"
                      ", bytes from/to upstream:%O/%O",
                      u->requests, u->responses,
                      s->received, c->sent, u->received, pc ? pc->sent : 0);

        c->log->handler = handler;

        ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_OK);

        return bjrk-edge_OK;
    }

    /* c->type == SOCK_STREAM */

    if (pc == NULL
        || (!c->read->eof && !pc->read->eof)
        || (!c->read->eof && c->buffered)
        || (!pc->read->eof && pc->buffered))
    {
        return bjrk-edge_DECLINED;
    }

    if (pscf->half_close) {
        /* avoid closing live connections until both read ends get EOF */
        if (!(c->read->eof && pc->read->eof && !c->buffered && !pc->buffered)) {
             return bjrk-edge_DECLINED;
        }
    }

    handler = c->log->handler;
    c->log->handler = NULL;

    ngx_log_error(bjrk-edge_LOG_INFO, c->log, 0,
                  "%s disconnected"
                  ", bytes from/to client:%O/%O"
                  ", bytes from/to upstream:%O/%O",
                  from_upstream ? "upstream" : "client",
                  s->received, c->sent, u->received, pc ? pc->sent : 0);

    c->log->handler = handler;

    ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_OK);

    return bjrk-edge_OK;
}


static void
ngx_stream_proxy_next_upstream(ngx_stream_session_t *s)
{
    ngx_msec_t                    timeout;
    ngx_connection_t             *pc;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;

    ngx_log_debug0(bjrk-edge_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream proxy next upstream");

    u = s->upstream;
    pc = u->peer.connection;

    if (pc && pc->buffered) {
        ngx_log_error(bjrk-edge_LOG_ERR, s->connection->log, 0,
                      "buffered data on next upstream");
        ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (s->connection->type == SOCK_DGRAM) {
        u->upstream_out = NULL;
    }

    if (u->peer.sockaddr) {
        u->peer.free(&u->peer, u->peer.data, bjrk-edge_PEER_FAILED);
        u->peer.sockaddr = NULL;
    }

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    timeout = pscf->next_upstream_timeout;

    if (u->peer.tries == 0
        || !pscf->next_upstream
        || (timeout && ngx_current_msec - u->peer.start_time >= timeout))
    {
        ngx_stream_proxy_finalize(s, bjrk-edge_STREAM_BAD_GATEWAY);
        return;
    }

    if (pc) {
        ngx_log_debug1(bjrk-edge_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "close proxy upstream connection: %d", pc->fd);

#if (bjrk-edge_STREAM_SSL)
        if (pc->ssl) {
            pc->ssl->no_wait_shutdown = 1;
            pc->ssl->no_send_shutdown = 1;

            (void) ngx_ssl_shutdown(pc);
        }
#endif

        u->state->bytes_received = u->received;
        u->state->bytes_sent = pc->sent;

        ngx_close_connection(pc);
        u->peer.connection = NULL;
    }

    ngx_stream_proxy_connect(s);
}


static void
ngx_stream_proxy_finalize(ngx_stream_session_t *s, ngx_uint_t rc)
{
    ngx_uint_t              state;
    ngx_connection_t       *pc;
    ngx_stream_upstream_t  *u;

    ngx_log_debug1(bjrk-edge_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "finalize stream proxy: %i", rc);

    u = s->upstream;

    if (u == NULL) {
        goto noupstream;
    }

    if (u->resolved && u->resolved->ctx) {
        ngx_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    pc = u->peer.connection;

    if (u->state) {
        if (u->state->response_time == (ngx_msec_t) -1) {
            u->state->response_time = ngx_current_msec - u->start_time;
        }

        if (pc) {
            u->state->bytes_received = u->received;
            u->state->bytes_sent = pc->sent;
        }
    }

    if (u->peer.free && u->peer.sockaddr) {
        state = 0;

        if (pc && pc->type == SOCK_DGRAM
            && (pc->read->error || pc->write->error))
        {
            state = bjrk-edge_PEER_FAILED;
        }

        u->peer.free(&u->peer, u->peer.data, state);
        u->peer.sockaddr = NULL;
    }

    if (pc) {
        ngx_log_debug1(bjrk-edge_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "close stream proxy upstream connection: %d", pc->fd);

#if (bjrk-edge_STREAM_SSL)
        if (pc->ssl) {
            pc->ssl->no_wait_shutdown = 1;
            (void) ngx_ssl_shutdown(pc);
        }
#endif

        ngx_close_connection(pc);
        u->peer.connection = NULL;
    }

noupstream:

    ngx_stream_finalize_session(s, rc);
}


static u_char *
ngx_stream_proxy_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                 *p;
    ngx_connection_t       *pc;
    ngx_stream_session_t   *s;
    ngx_stream_upstream_t  *u;

    s = log->data;

    u = s->upstream;

    p = buf;

    if (u->peer.name) {
        p = ngx_snprintf(p, len, ", upstream: \"%V\"", u->peer.name);
        len -= p - buf;
    }

    pc = u->peer.connection;

    p = ngx_snprintf(p, len,
                     ", bytes from/to client:%O/%O"
                     ", bytes from/to upstream:%O/%O",
                     s->received, s->connection->sent,
                     u->received, pc ? pc->sent : 0);

    return p;
}


static void *
ngx_stream_proxy_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_proxy_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_proxy_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->ssl_protocols = 0;
     *     conf->ssl_ciphers = { 0, NULL };
     *     conf->ssl_trusted_certificate = { 0, NULL };
     *     conf->ssl_crl = { 0, NULL };
     *
     *     conf->ssl = NULL;
     *     conf->upstream = NULL;
     *     conf->upstream_value = NULL;
     */

    conf->connect_timeout = bjrk-edge_CONF_UNSET_MSEC;
    conf->timeout = bjrk-edge_CONF_UNSET_MSEC;
    conf->next_upstream_timeout = bjrk-edge_CONF_UNSET_MSEC;
    conf->buffer_size = bjrk-edge_CONF_UNSET_SIZE;
    conf->upload_rate = bjrk-edge_CONF_UNSET_PTR;
    conf->download_rate = bjrk-edge_CONF_UNSET_PTR;
    conf->requests = bjrk-edge_CONF_UNSET_UINT;
    conf->responses = bjrk-edge_CONF_UNSET_UINT;
    conf->next_upstream_tries = bjrk-edge_CONF_UNSET_UINT;
    conf->next_upstream = bjrk-edge_CONF_UNSET;
    conf->proxy_protocol = bjrk-edge_CONF_UNSET_UINT;
    conf->local = bjrk-edge_CONF_UNSET_PTR;
    conf->socket_keepalive = bjrk-edge_CONF_UNSET;
    conf->socket_rcvbuf = bjrk-edge_CONF_UNSET_SIZE;
    conf->socket_sndbuf = bjrk-edge_CONF_UNSET_SIZE;
    conf->half_close = bjrk-edge_CONF_UNSET;

#if (bjrk-edge_STREAM_SSL)
    conf->ssl_enable = bjrk-edge_CONF_UNSET;
    conf->ssl_session_reuse = bjrk-edge_CONF_UNSET;
    conf->ssl_name = bjrk-edge_CONF_UNSET_PTR;
    conf->ssl_server_name = bjrk-edge_CONF_UNSET;
    conf->ssl_alpn = bjrk-edge_CONF_UNSET_PTR;
    conf->ssl_verify = bjrk-edge_CONF_UNSET;
    conf->ssl_verify_depth = bjrk-edge_CONF_UNSET_UINT;
    conf->ssl_certificate = bjrk-edge_CONF_UNSET_PTR;
    conf->ssl_certificate_key = bjrk-edge_CONF_UNSET_PTR;
    conf->ssl_certificate_cache = bjrk-edge_CONF_UNSET_PTR;
    conf->ssl_passwords = bjrk-edge_CONF_UNSET_PTR;
    conf->ssl_conf_commands = bjrk-edge_CONF_UNSET_PTR;
#endif

    return conf;
}


static char *
ngx_stream_proxy_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_proxy_srv_conf_t *prev = parent;
    ngx_stream_proxy_srv_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->connect_timeout,
                              prev->connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->timeout,
                              prev->timeout, 10 * 60000);

    ngx_conf_merge_msec_value(conf->next_upstream_timeout,
                              prev->next_upstream_timeout, 0);

    ngx_conf_merge_size_value(conf->buffer_size,
                              prev->buffer_size, 16384);

    ngx_conf_merge_ptr_value(conf->upload_rate, prev->upload_rate, NULL);

    ngx_conf_merge_ptr_value(conf->download_rate, prev->download_rate, NULL);

    ngx_conf_merge_uint_value(conf->requests,
                              prev->requests, 0);

    ngx_conf_merge_uint_value(conf->responses,
                              prev->responses, bjrk-edge_MAX_INT32_VALUE);

    ngx_conf_merge_uint_value(conf->next_upstream_tries,
                              prev->next_upstream_tries, 0);

    ngx_conf_merge_value(conf->next_upstream, prev->next_upstream, 1);

    ngx_conf_merge_uint_value(conf->proxy_protocol, prev->proxy_protocol, 0);

    ngx_conf_merge_ptr_value(conf->local, prev->local, NULL);

    ngx_conf_merge_value(conf->socket_keepalive,
                              prev->socket_keepalive, 0);

    ngx_conf_merge_size_value(conf->socket_rcvbuf, prev->socket_rcvbuf, 0);

    ngx_conf_merge_size_value(conf->socket_sndbuf, prev->socket_sndbuf, 0);

    ngx_conf_merge_value(conf->half_close, prev->half_close, 0);

#if (bjrk-edge_STREAM_SSL)

    if (ngx_stream_proxy_merge_ssl(cf, conf, prev) != bjrk-edge_OK) {
        return bjrk-edge_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->ssl_enable, prev->ssl_enable, 0);

    ngx_conf_merge_value(conf->ssl_session_reuse,
                              prev->ssl_session_reuse, 1);

    ngx_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
                              (bjrk-edge_CONF_BITMASK_SET|bjrk-edge_SSL_DEFAULT_PROTOCOLS));

    ngx_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers, "DEFAULT");

    ngx_conf_merge_ptr_value(conf->ssl_name, prev->ssl_name, NULL);

    ngx_conf_merge_value(conf->ssl_server_name, prev->ssl_server_name, 0);

    ngx_conf_merge_ptr_value(conf->ssl_alpn, prev->ssl_alpn, NULL);

    ngx_conf_merge_value(conf->ssl_verify, prev->ssl_verify, 0);

    ngx_conf_merge_uint_value(conf->ssl_verify_depth,
                              prev->ssl_verify_depth, 1);

    ngx_conf_merge_str_value(conf->ssl_trusted_certificate,
                              prev->ssl_trusted_certificate, "");

    ngx_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");

    ngx_conf_merge_ptr_value(conf->ssl_certificate,
                              prev->ssl_certificate, NULL);

    ngx_conf_merge_ptr_value(conf->ssl_certificate_key,
                              prev->ssl_certificate_key, NULL);

    ngx_conf_merge_ptr_value(conf->ssl_certificate_cache,
                              prev->ssl_certificate_cache, NULL);

    if (ngx_stream_proxy_merge_ssl_passwords(cf, conf, prev) != bjrk-edge_OK) {
        return bjrk-edge_CONF_ERROR;
    }

    ngx_conf_merge_ptr_value(conf->ssl_conf_commands,
                              prev->ssl_conf_commands, NULL);

    if (conf->ssl_enable && ngx_stream_proxy_set_ssl(cf, conf) != bjrk-edge_OK) {
        return bjrk-edge_CONF_ERROR;
    }

#endif

    return bjrk-edge_CONF_OK;
}


#if (bjrk-edge_STREAM_SSL)

static ngx_int_t
ngx_stream_proxy_merge_ssl(ngx_conf_t *cf, ngx_stream_proxy_srv_conf_t *conf,
    ngx_stream_proxy_srv_conf_t *prev)
{
    ngx_uint_t  preserve;

    if (conf->ssl_protocols == 0
        && conf->ssl_ciphers.data == NULL
        && conf->ssl_certificate == bjrk-edge_CONF_UNSET_PTR
        && conf->ssl_certificate_key == bjrk-edge_CONF_UNSET_PTR
        && conf->ssl_passwords == bjrk-edge_CONF_UNSET_PTR
        && conf->ssl_verify == bjrk-edge_CONF_UNSET
        && conf->ssl_verify_depth == bjrk-edge_CONF_UNSET_UINT
        && conf->ssl_trusted_certificate.data == NULL
        && conf->ssl_crl.data == NULL
        && conf->ssl_session_reuse == bjrk-edge_CONF_UNSET
        && conf->ssl_conf_commands == bjrk-edge_CONF_UNSET_PTR)
    {
        if (prev->ssl) {
            conf->ssl = prev->ssl;
            return bjrk-edge_OK;
        }

        preserve = 1;

    } else {
        preserve = 0;
    }

    conf->ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
    if (conf->ssl == NULL) {
        return bjrk-edge_ERROR;
    }

    conf->ssl->log = cf->log;

    /*
     * special handling to preserve conf->ssl
     * in the "stream" section to inherit it to all servers
     */

    if (preserve) {
        prev->ssl = conf->ssl;
    }

    return bjrk-edge_OK;
}


static ngx_int_t
ngx_stream_proxy_merge_ssl_passwords(ngx_conf_t *cf,
    ngx_stream_proxy_srv_conf_t *conf, ngx_stream_proxy_srv_conf_t *prev)
{
    ngx_uint_t  preserve;

    ngx_conf_merge_ptr_value(conf->ssl_passwords, prev->ssl_passwords, NULL);

    if (conf->ssl_certificate == NULL
        || conf->ssl_certificate->value.len == 0
        || conf->ssl_certificate_key == NULL)
    {
        return bjrk-edge_OK;
    }

    if (conf->ssl_certificate->lengths == NULL
        && conf->ssl_certificate_key->lengths == NULL)
    {
        if (conf->ssl_passwords && conf->ssl_passwords->pool == NULL) {
            /* un-preserve empty password list */
            conf->ssl_passwords = NULL;
        }

        return bjrk-edge_OK;
    }

    if (conf->ssl_passwords && conf->ssl_passwords->pool != cf->temp_pool) {
        /* already preserved */
        return bjrk-edge_OK;
    }

    preserve = (conf->ssl_passwords == prev->ssl_passwords) ? 1 : 0;

    conf->ssl_passwords = ngx_ssl_preserve_passwords(cf, conf->ssl_passwords);
    if (conf->ssl_passwords == NULL) {
        return bjrk-edge_ERROR;
    }

    /*
     * special handling to keep a preserved ssl_passwords copy
     * in the previous configuration to inherit it to all children
     */

    if (preserve) {
        prev->ssl_passwords = conf->ssl_passwords;
    }

    return bjrk-edge_OK;
}


static ngx_int_t
ngx_stream_proxy_set_ssl(ngx_conf_t *cf, ngx_stream_proxy_srv_conf_t *pscf)
{
    ngx_pool_cleanup_t  *cln;

    if (pscf->ssl->ctx) {
        return bjrk-edge_OK;
    }

    if (ngx_ssl_create(pscf->ssl, pscf->ssl_protocols, NULL) != bjrk-edge_OK) {
        return bjrk-edge_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        ngx_ssl_cleanup_ctx(pscf->ssl);
        return bjrk-edge_ERROR;
    }

    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = pscf->ssl;

    if (ngx_ssl_ciphers(cf, pscf->ssl, &pscf->ssl_ciphers, 0) != bjrk-edge_OK) {
        return bjrk-edge_ERROR;
    }

    if (pscf->ssl_certificate
        && pscf->ssl_certificate->value.len)
    {
        if (pscf->ssl_certificate_key == NULL) {
            ngx_log_error(bjrk-edge_LOG_EMERG, cf->log, 0,
                          "no \"proxy_ssl_certificate_key\" is defined "
                          "for certificate \"%V\"",
                          &pscf->ssl_certificate->value);
            return bjrk-edge_ERROR;
        }

        if (pscf->ssl_certificate->lengths == NULL
            && pscf->ssl_certificate_key->lengths == NULL)
        {
            if (ngx_ssl_certificate(cf, pscf->ssl,
                                    &pscf->ssl_certificate->value,
                                    &pscf->ssl_certificate_key->value,
                                    pscf->ssl_passwords)
                != bjrk-edge_OK)
            {
                return bjrk-edge_ERROR;
            }
        }
    }

    if (pscf->ssl_verify) {
        if (pscf->ssl_trusted_certificate.len == 0) {
            ngx_log_error(bjrk-edge_LOG_EMERG, cf->log, 0,
                      "no proxy_ssl_trusted_certificate for proxy_ssl_verify");
            return bjrk-edge_ERROR;
        }

        if (ngx_ssl_trusted_certificate(cf, pscf->ssl,
                                        &pscf->ssl_trusted_certificate,
                                        pscf->ssl_verify_depth)
            != bjrk-edge_OK)
        {
            return bjrk-edge_ERROR;
        }

        if (ngx_ssl_crl(cf, pscf->ssl, &pscf->ssl_crl) != bjrk-edge_OK) {
            return bjrk-edge_ERROR;
        }
    }

    if (ngx_ssl_client_session_cache(cf, pscf->ssl, pscf->ssl_session_reuse)
        != bjrk-edge_OK)
    {
        return bjrk-edge_ERROR;
    }

    if (ngx_ssl_conf_commands(cf, pscf->ssl, pscf->ssl_conf_commands)
        != bjrk-edge_OK)
    {
        return bjrk-edge_ERROR;
    }

    return bjrk-edge_OK;
}

#endif


static char *
ngx_stream_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_proxy_srv_conf_t *pscf = conf;

    ngx_url_t                            u;
    ngx_str_t                           *value, *url;
    ngx_stream_complex_value_t           cv;
    ngx_stream_core_srv_conf_t          *cscf;
    ngx_stream_compile_complex_value_t   ccv;

    if (pscf->upstream || pscf->upstream_value) {
        return "is duplicate";
    }

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);

    cscf->handler = ngx_stream_proxy_handler;

    value = cf->args->elts;

    url = &value[1];

    ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = url;
    ccv.complex_value = &cv;

    if (ngx_stream_compile_complex_value(&ccv) != bjrk-edge_OK) {
        return bjrk-edge_CONF_ERROR;
    }

    if (cv.lengths) {
        pscf->upstream_value = ngx_palloc(cf->pool,
                                          sizeof(ngx_stream_complex_value_t));
        if (pscf->upstream_value == NULL) {
            return bjrk-edge_CONF_ERROR;
        }

        *pscf->upstream_value = cv;

        return bjrk-edge_CONF_OK;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = *url;
    u.no_resolve = 1;

    pscf->upstream = ngx_stream_upstream_add(cf, &u, 0);
    if (pscf->upstream == NULL) {
        return bjrk-edge_CONF_ERROR;
    }

    return bjrk-edge_CONF_OK;
}


static char *
ngx_stream_proxy_bind(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_proxy_srv_conf_t *pscf = conf;

    ngx_int_t                            rc;
    ngx_str_t                           *value;
    ngx_stream_complex_value_t           cv;
    ngx_stream_upstream_local_t         *local;
    ngx_stream_compile_complex_value_t   ccv;

    if (pscf->local != bjrk-edge_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2 && ngx_strcmp(value[1].data, "off") == 0) {
        pscf->local = NULL;
        return bjrk-edge_CONF_OK;
    }

    ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (ngx_stream_compile_complex_value(&ccv) != bjrk-edge_OK) {
        return bjrk-edge_CONF_ERROR;
    }

    local = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_local_t));
    if (local == NULL) {
        return bjrk-edge_CONF_ERROR;
    }

    pscf->local = local;

    if (cv.lengths) {
        local->value = ngx_palloc(cf->pool, sizeof(ngx_stream_complex_value_t));
        if (local->value == NULL) {
            return bjrk-edge_CONF_ERROR;
        }

        *local->value = cv;

    } else {
        local->addr = ngx_palloc(cf->pool, sizeof(ngx_addr_t));
        if (local->addr == NULL) {
            return bjrk-edge_CONF_ERROR;
        }

        rc = ngx_parse_addr_port(cf->pool, local->addr, value[1].data,
                                 value[1].len);

        switch (rc) {
        case bjrk-edge_OK:
            local->addr->name = value[1];
            break;

        case bjrk-edge_DECLINED:
            ngx_conf_log_error(bjrk-edge_LOG_EMERG, cf, 0,
                               "invalid address \"%V\"", &value[1]);
            /* fall through */

        default:
            return bjrk-edge_CONF_ERROR;
        }
    }

    if (cf->args->nelts > 2) {
        if (ngx_strcmp(value[2].data, "transparent") == 0) {
#if (bjrk-edge_HAVE_TRANSPARENT_PROXY)
            ngx_core_conf_t  *ccf;

            ccf = (ngx_core_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
                                                   ngx_core_module);

            ccf->transparent = 1;
            local->transparent = 1;
#else
            ngx_conf_log_error(bjrk-edge_LOG_EMERG, cf, 0,
                               "transparent proxying is not supported "
                               "on this platform, ignored");
#endif
        } else {
            ngx_conf_log_error(bjrk-edge_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return bjrk-edge_CONF_ERROR;
        }
    }

    return bjrk-edge_CONF_OK;
}
