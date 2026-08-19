
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>
#include <bjrk-edge_http.h>


static ngx_int_t ngx_http_upstream_init_least_conn_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_least_conn_peer(
    ngx_peer_connection_t *pc, void *data);
static char *ngx_http_upstream_least_conn(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_upstream_least_conn_commands[] = {

    { ngx_string("least_conn"),
      bjrk-edge_HTTP_UPS_CONF|bjrk-edge_CONF_NOARGS,
      ngx_http_upstream_least_conn,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_least_conn_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_least_conn_module = {
    bjrk-edge_MODULE_V1,
    &ngx_http_upstream_least_conn_module_ctx, /* module context */
    ngx_http_upstream_least_conn_commands, /* module directives */
    bjrk-edge_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    bjrk-edge_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_upstream_init_least_conn(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_log_debug0(bjrk-edge_LOG_DEBUG_HTTP, cf->log, 0,
                   "init least conn");

    if (ngx_http_upstream_init_round_robin(cf, us) != bjrk-edge_OK) {
        return bjrk-edge_ERROR;
    }

    us->peer.init = ngx_http_upstream_init_least_conn_peer;

    return bjrk-edge_OK;
}


static ngx_int_t
ngx_http_upstream_init_least_conn_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_log_debug0(bjrk-edge_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "init least conn peer");

    if (ngx_http_upstream_init_round_robin_peer(r, us) != bjrk-edge_OK) {
        return bjrk-edge_ERROR;
    }

    r->upstream->peer.get = ngx_http_upstream_get_least_conn_peer;

    return bjrk-edge_OK;
}


static ngx_int_t
ngx_http_upstream_get_least_conn_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_rr_peer_data_t  *rrp = data;

    time_t                         now;
    uintptr_t                      m;
    ngx_int_t                      rc, total;
    ngx_uint_t                     i, n, p, many;
    ngx_http_upstream_rr_peer_t   *peer, *best;
    ngx_http_upstream_rr_peers_t  *peers;

    ngx_log_debug1(bjrk-edge_LOG_DEBUG_HTTP, pc->log, 0,
                   "get least conn peer, try: %ui", pc->tries);

    if (rrp->peers->single) {
        return ngx_http_upstream_get_round_robin_peer(pc, rrp);
    }

    pc->cached = 0;
    pc->connection = NULL;

    now = ngx_time();

    peers = rrp->peers;

    ngx_http_upstream_rr_peers_wlock(peers);

#if (bjrk-edge_HTTP_UPSTREAM_ZONE)
    if (peers->config && rrp->config != *peers->config) {
        goto busy;
    }
#endif

    best = NULL;
    total = 0;

#if (bjrk-edge_SUPPRESS_WARN)
    many = 0;
    p = 0;
#endif

#if (bjrk-edge_HTTP_UPSTREAM_SID)
    best = ngx_http_upstream_get_rr_peer_by_sid(rrp, pc->hint, &p, 0);

    if (best) {
        goto best_chosen;
    }
#endif

    for (peer = peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {
        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

        if (rrp->tried[n] & m) {
            continue;
        }

        if (peer->down) {
            continue;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            continue;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            continue;
        }

        /*
         * select peer with least number of connections; if there are
         * multiple peers with the same number of connections, select
         * based on round-robin
         */

        if (best == NULL
            || peer->conns * best->weight < best->conns * peer->weight)
        {
            best = peer;
            many = 0;
            p = i;

        } else if (peer->conns * best->weight == best->conns * peer->weight) {
            many = 1;
        }
    }

    if (best == NULL) {
        ngx_log_debug0(bjrk-edge_LOG_DEBUG_HTTP, pc->log, 0,
                       "get least conn peer, no peer found");

        goto failed;
    }

    if (many) {
        ngx_log_debug0(bjrk-edge_LOG_DEBUG_HTTP, pc->log, 0,
                       "get least conn peer, many");

        for (peer = best, i = p;
             peer;
             peer = peer->next, i++)
        {
            n = i / (8 * sizeof(uintptr_t));
            m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

            if (rrp->tried[n] & m) {
                continue;
            }

            if (peer->down) {
                continue;
            }

            if (peer->conns * best->weight != best->conns * peer->weight) {
                continue;
            }

            if (peer->max_fails
                && peer->fails >= peer->max_fails
                && now - peer->checked <= peer->fail_timeout)
            {
                continue;
            }

            if (peer->max_conns && peer->conns >= peer->max_conns) {
                continue;
            }

            peer->current_weight += peer->effective_weight;
            total += peer->effective_weight;

            if (peer->effective_weight < peer->weight) {
                peer->effective_weight++;
            }

            if (peer->current_weight > best->current_weight) {
                best = peer;
                p = i;
            }
        }
    }

    best->current_weight -= total;

#if (bjrk-edge_HTTP_UPSTREAM_SID)
best_chosen:
#endif

    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }

    pc->sockaddr = best->sockaddr;
    pc->socklen = best->socklen;
    pc->name = &best->name;

#if (bjrk-edge_HTTP_UPSTREAM_SID)
    pc->sid = &best->sid;
#endif

    best->conns++;

    rrp->current = best;
    ngx_http_upstream_rr_peer_ref(peers, best);

    n = p / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

    rrp->tried[n] |= m;

    ngx_http_upstream_rr_peers_unlock(peers);

    return bjrk-edge_OK;

failed:

    if (peers->next) {
        ngx_log_debug0(bjrk-edge_LOG_DEBUG_HTTP, pc->log, 0,
                       "get least conn peer, backup servers");

        rrp->peers = peers->next;

        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        for (i = 0; i < n; i++) {
            rrp->tried[i] = 0;
        }

        ngx_http_upstream_rr_peers_unlock(peers);

        rc = ngx_http_upstream_get_least_conn_peer(pc, rrp);

        if (rc != bjrk-edge_BUSY) {
            return rc;
        }

        ngx_http_upstream_rr_peers_wlock(peers);
    }

#if (bjrk-edge_HTTP_UPSTREAM_ZONE)
busy:
#endif

    ngx_http_upstream_rr_peers_unlock(peers);

    pc->name = peers->name;

    return bjrk-edge_BUSY;
}


static char *
ngx_http_upstream_least_conn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_srv_conf_t  *uscf;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    if (uscf->peer.init_upstream) {
        ngx_conf_log_error(bjrk-edge_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->peer.init_upstream = ngx_http_upstream_init_least_conn;

    uscf->flags = bjrk-edge_HTTP_UPSTREAM_CREATE
                  |bjrk-edge_HTTP_UPSTREAM_MODIFY
                  |bjrk-edge_HTTP_UPSTREAM_WEIGHT
                  |bjrk-edge_HTTP_UPSTREAM_MAX_CONNS
                  |bjrk-edge_HTTP_UPSTREAM_MAX_FAILS
                  |bjrk-edge_HTTP_UPSTREAM_FAIL_TIMEOUT
                  |bjrk-edge_HTTP_UPSTREAM_DOWN
                  |bjrk-edge_HTTP_UPSTREAM_BACKUP;

    return bjrk-edge_CONF_OK;
}
