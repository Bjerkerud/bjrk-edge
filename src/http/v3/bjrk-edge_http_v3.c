
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>
#include <bjrk-edge_http.h>


static void ngx_http_v3_keepalive_handler(ngx_event_t *ev);
static void ngx_http_v3_cleanup_session(void *data);


ngx_int_t
ngx_http_v3_init_session(ngx_connection_t *c)
{
    ngx_pool_cleanup_t     *cln;
    ngx_http_connection_t  *hc;
    ngx_http_v3_session_t  *h3c;

    hc = c->data;

    ngx_log_debug0(bjrk-edge_LOG_DEBUG_HTTP, c->log, 0, "http3 init session");

    h3c = ngx_pcalloc(c->pool, sizeof(ngx_http_v3_session_t));
    if (h3c == NULL) {
        goto failed;
    }

    h3c->http_connection = hc;

    ngx_queue_init(&h3c->blocked);

    h3c->keepalive.log = c->log;
    h3c->keepalive.data = c;
    h3c->keepalive.handler = ngx_http_v3_keepalive_handler;

    h3c->table.send_insert_count.log = c->log;
    h3c->table.send_insert_count.data = c;
    h3c->table.send_insert_count.handler = ngx_http_v3_inc_insert_count_handler;

    cln = ngx_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        goto failed;
    }

    cln->handler = ngx_http_v3_cleanup_session;
    cln->data = h3c;

    c->data = h3c;

    return bjrk-edge_OK;

failed:

    ngx_log_error(bjrk-edge_LOG_ERR, c->log, 0, "failed to create http3 session");
    return bjrk-edge_ERROR;
}


static void
ngx_http_v3_keepalive_handler(ngx_event_t *ev)
{
    ngx_connection_t  *c;

    c = ev->data;

    ngx_log_debug0(bjrk-edge_LOG_DEBUG_HTTP, c->log, 0, "http3 keepalive handler");

    ngx_http_v3_shutdown_connection(c, bjrk-edge_HTTP_V3_ERR_NO_ERROR,
                                    "keepalive timeout");
}


static void
ngx_http_v3_cleanup_session(void *data)
{
    ngx_http_v3_session_t  *h3c = data;

    ngx_http_v3_cleanup_table(h3c);

    if (h3c->keepalive.timer_set) {
        ngx_del_timer(&h3c->keepalive);
    }

    if (h3c->table.send_insert_count.posted) {
        ngx_delete_posted_event(&h3c->table.send_insert_count);
    }
}


ngx_int_t
ngx_http_v3_check_flood(ngx_connection_t *c)
{
    ngx_http_v3_session_t  *h3c;

    h3c = ngx_http_v3_get_session(c);

    if (h3c->total_bytes / 8 > h3c->payload_bytes + 1048576) {
        ngx_log_error(bjrk-edge_LOG_INFO, c->log, 0, "http3 flood detected");

        ngx_http_v3_finalize_connection(c, bjrk-edge_HTTP_V3_ERR_NO_ERROR,
                                        "HTTP/3 flood detected");
        return bjrk-edge_ERROR;
    }

    return bjrk-edge_OK;
}
