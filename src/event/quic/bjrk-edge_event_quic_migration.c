
/*
 * Copyright (C) Nginx, Inc.
 */


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>
#include <bjrk-edge_event.h>
#include <bjrk-edge_event_quic_connection.h>


#define bjrk-edge_QUIC_PATH_MTU_DELAY       100
#define bjrk-edge_QUIC_PATH_MTU_PRECISION   16


static void ngx_quic_set_connection_path(ngx_connection_t *c,
    ngx_quic_path_t *path);
static ngx_int_t ngx_quic_validate_path(ngx_connection_t *c,
    ngx_quic_path_t *path);
static ngx_int_t ngx_quic_send_path_challenge(ngx_connection_t *c,
    ngx_quic_path_t *path);
static void ngx_quic_set_path_timer(ngx_connection_t *c);
static ngx_int_t ngx_quic_expire_path_validation(ngx_connection_t *c,
    ngx_quic_path_t *path);
static ngx_int_t ngx_quic_expire_path_mtu_delay(ngx_connection_t *c,
    ngx_quic_path_t *path);
static ngx_int_t ngx_quic_expire_path_mtu_discovery(ngx_connection_t *c,
    ngx_quic_path_t *path);
static ngx_quic_path_t *ngx_quic_get_path(ngx_connection_t *c, ngx_uint_t tag);
static ngx_int_t ngx_quic_send_path_mtu_probe(ngx_connection_t *c,
    ngx_quic_path_t *path);


ngx_int_t
ngx_quic_handle_path_challenge_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_path_challenge_frame_t *f)
{
    size_t                  min;
    ngx_quic_frame_t       *fp;
    ngx_quic_connection_t  *qc;

    if (pkt->level != bjrk-edge_QUIC_ENCRYPTION_APPLICATION || pkt->path_challenged) {
        ngx_log_debug0(bjrk-edge_LOG_DEBUG_EVENT, c->log, 0,
                       "quic ignoring PATH_CHALLENGE");
        return bjrk-edge_OK;
    }

    pkt->path_challenged = 1;

    qc = ngx_quic_get_connection(c);

    fp = ngx_quic_alloc_frame(c);
    if (fp == NULL) {
        return bjrk-edge_ERROR;
    }

    fp->level = bjrk-edge_QUIC_ENCRYPTION_APPLICATION;
    fp->type = bjrk-edge_QUIC_FT_PATH_RESPONSE;
    fp->u.path_response = *f;

    /*
     * RFC 9000, 8.2.2.  Path Validation Responses
     *
     * A PATH_RESPONSE frame MUST be sent on the network path where the
     * PATH_CHALLENGE frame was received.
     */

    /*
     * An endpoint MUST expand datagrams that contain a PATH_RESPONSE frame
     * to at least the smallest allowed maximum datagram size of 1200 bytes.
     * ...
     * However, an endpoint MUST NOT expand the datagram containing the
     * PATH_RESPONSE if the resulting data exceeds the anti-amplification limit.
     */

    min = (ngx_quic_path_limit(c, pkt->path, 1200) < 1200) ? 0 : 1200;

    if (ngx_quic_frame_sendto(c, fp, min, pkt->path) == bjrk-edge_ERROR) {
        return bjrk-edge_ERROR;
    }

    if (pkt->path == qc->path) {
        /*
         * RFC 9000, 9.3.3.  Off-Path Packet Forwarding
         *
         * An endpoint that receives a PATH_CHALLENGE on an active path SHOULD
         * send a non-probing packet in response.
         */

        fp = ngx_quic_alloc_frame(c);
        if (fp == NULL) {
            return bjrk-edge_ERROR;
        }

        fp->level = bjrk-edge_QUIC_ENCRYPTION_APPLICATION;
        fp->type = bjrk-edge_QUIC_FT_PING;

        ngx_quic_queue_frame(qc, fp);
    }

    return bjrk-edge_OK;
}


ngx_int_t
ngx_quic_handle_path_response_frame(ngx_connection_t *c,
    ngx_quic_path_challenge_frame_t *f)
{
    ngx_uint_t              rst;
    ngx_queue_t            *q;
    ngx_quic_path_t        *path, *prev;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    /*
     * RFC 9000, 8.2.3.  Successful Path Validation
     *
     * A PATH_RESPONSE frame received on any network path validates the path
     * on which the PATH_CHALLENGE was sent.
     */

    for (q = ngx_queue_head(&qc->paths);
         q != ngx_queue_sentinel(&qc->paths);
         q = ngx_queue_next(q))
    {
        path = ngx_queue_data(q, ngx_quic_path_t, queue);

        if (path->state != bjrk-edge_QUIC_PATH_VALIDATING) {
            continue;
        }

        if (ngx_memcmp(path->challenge[0], f->data, sizeof(f->data)) == 0
            || ngx_memcmp(path->challenge[1], f->data, sizeof(f->data)) == 0)
        {
            goto valid;
        }
    }

    ngx_log_debug0(bjrk-edge_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stale PATH_RESPONSE ignored");

    return bjrk-edge_OK;

valid:

    /*
     * RFC 9000, 9.4.  Loss Detection and Congestion Control
     *
     * On confirming a peer's ownership of its new address,
     * an endpoint MUST immediately reset the congestion controller
     * and round-trip time estimator for the new path to initial values
     * unless the only change in the peer's address is its port number.
     */

    rst = 1;

    prev = ngx_quic_get_path(c, bjrk-edge_QUIC_PATH_BACKUP);

    if (prev != NULL) {

        if (ngx_cmp_sockaddr(prev->sockaddr, prev->socklen,
                             path->sockaddr, path->socklen, 0)
            == bjrk-edge_OK)
        {
            /* address did not change */
            rst = 0;

            path->mtu = prev->mtu;
            path->max_mtu = prev->max_mtu;
            path->mtu_unvalidated = 0;
        }
    }

    if (rst) {
        /* prevent old path packets contribution to congestion control */

        ctx = ngx_quic_get_send_ctx(qc, bjrk-edge_QUIC_ENCRYPTION_APPLICATION);
        qc->rst_pnum = ctx->pnum;

        ngx_memzero(&qc->congestion, sizeof(ngx_quic_congestion_t));

        qc->congestion.window = ngx_min(10 * bjrk-edge_QUIC_MIN_INITIAL_SIZE,
                                   ngx_max(2 * bjrk-edge_QUIC_MIN_INITIAL_SIZE,
                                           14720));
        qc->congestion.ssthresh = (size_t) -1;
        qc->congestion.mtu = bjrk-edge_QUIC_MIN_INITIAL_SIZE;
        qc->congestion.recovery_start = ngx_current_msec - 1;

        ngx_quic_init_rtt(qc);
    }

    path->validated = 1;

    ngx_quic_set_connection_path(c, path);

    if (path->mtu_unvalidated) {
        path->mtu_unvalidated = 0;
        return ngx_quic_validate_path(c, path);
    }

    /*
     * RFC 9000, 9.3.  Responding to Connection Migration
     *
     *  After verifying a new client address, the server SHOULD
     *  send new address validation tokens (Section 8) to the client.
     */

    if (ngx_quic_send_new_token(c, path) != bjrk-edge_OK) {
        return bjrk-edge_ERROR;
    }

    ngx_log_error(bjrk-edge_LOG_INFO, c->log, 0,
                  "quic path seq:%uL addr:%V successfully validated",
                  path->seqnum, &path->addr_text);

    ngx_quic_path_dbg(c, "is validated", path);

    ngx_quic_discover_path_mtu(c, path);

    return bjrk-edge_OK;
}


ngx_quic_path_t *
ngx_quic_new_path(ngx_connection_t *c,
    struct sockaddr *sockaddr, socklen_t socklen, ngx_quic_client_id_t *cid)
{
    ngx_queue_t            *q;
    ngx_quic_path_t        *path;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (!ngx_queue_empty(&qc->free_paths)) {

        q = ngx_queue_head(&qc->free_paths);
        path = ngx_queue_data(q, ngx_quic_path_t, queue);

        ngx_queue_remove(&path->queue);

        ngx_memzero(path, sizeof(ngx_quic_path_t));

    } else {

        path = ngx_pcalloc(c->pool, sizeof(ngx_quic_path_t));
        if (path == NULL) {
            return NULL;
        }
    }

    ngx_queue_insert_tail(&qc->paths, &path->queue);

    path->cid = cid;
    cid->used = 1;

    path->seqnum = qc->path_seqnum++;

    path->sockaddr = &path->sa.sockaddr;
    path->socklen = socklen;
    ngx_memcpy(path->sockaddr, sockaddr, socklen);

    path->addr_text.data = path->text;
    path->addr_text.len = ngx_sock_ntop(sockaddr, socklen, path->text,
                                        bjrk-edge_SOCKADDR_STRLEN, 1);

    path->mtu = bjrk-edge_QUIC_MIN_INITIAL_SIZE;

    ngx_log_debug2(bjrk-edge_LOG_DEBUG_EVENT, c->log, 0,
                   "quic path seq:%uL created addr:%V",
                   path->seqnum, &path->addr_text);
    return path;
}


static ngx_quic_path_t *
ngx_quic_get_path(ngx_connection_t *c, ngx_uint_t tag)
{
    ngx_queue_t            *q;
    ngx_quic_path_t        *path;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    for (q = ngx_queue_head(&qc->paths);
         q != ngx_queue_sentinel(&qc->paths);
         q = ngx_queue_next(q))
    {
        path = ngx_queue_data(q, ngx_quic_path_t, queue);

        if (path->tag == tag) {
            return path;
        }
    }

    return NULL;
}


ngx_int_t
ngx_quic_set_path(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    off_t                   len;
    ngx_queue_t            *q;
    ngx_quic_path_t        *path, *probe;
    ngx_quic_socket_t      *qsock;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_client_id_t   *cid;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    qsock = ngx_quic_get_socket(c);

    len = pkt->raw->last - pkt->raw->start;

    if (c->udp->buffer == NULL) {
        /* first ever packet in connection, path already exists  */
        path = qc->path;
        goto update;
    }

    probe = NULL;

    for (q = ngx_queue_head(&qc->paths);
         q != ngx_queue_sentinel(&qc->paths);
         q = ngx_queue_next(q))
    {
        path = ngx_queue_data(q, ngx_quic_path_t, queue);

        if (ngx_cmp_sockaddr(&qsock->sockaddr.sockaddr, qsock->socklen,
                             path->sockaddr, path->socklen, 1)
            == bjrk-edge_OK)
        {
            goto update;
        }

        if (path->tag == bjrk-edge_QUIC_PATH_PROBE) {
            probe = path;
        }
    }

    /* packet from new path, drop current probe, if any */

    ctx = ngx_quic_get_send_ctx(qc, pkt->level);

    /*
     * only accept highest-numbered packets to prevent connection id
     * exhaustion by excessive probing packets from unknown paths
     */
    if (pkt->pn != ctx->largest_pn) {
        return bjrk-edge_DONE;
    }

    if (probe && ngx_quic_free_path(c, probe) != bjrk-edge_OK) {
        return bjrk-edge_ERROR;
    }

    /* new path requires new client id */
    cid = ngx_quic_next_client_id(c);
    if (cid == NULL) {
        ngx_log_error(bjrk-edge_LOG_INFO, c->log, 0,
                      "quic no available client ids for new path");
        /* stop processing of this datagram */
        return bjrk-edge_DONE;
    }

    path = ngx_quic_new_path(c, &qsock->sockaddr.sockaddr, qsock->socklen, cid);
    if (path == NULL) {
        return bjrk-edge_ERROR;
    }

    path->tag = bjrk-edge_QUIC_PATH_PROBE;

    /*
     * client arrived using new path and previously seen DCID,
     * this indicates NAT rebinding (or bad client)
     */
    if (qsock->used) {
        pkt->rebound = 1;
    }

update:

    qsock->used = 1;
    pkt->path = path;

    /* TODO: this may be too late in some cases;
     *       for example, if error happens during decrypt(), we cannot
     *       send CC, if error happens in 1st packet, due to amplification
     *       limit, because path->received = 0
     *
     *       should we account garbage as received or only decrypting packets?
     */
    path->received += len;

    ngx_log_debug3(bjrk-edge_LOG_DEBUG_EVENT, c->log, 0,
                   "quic packet len:%O via sock seq:%L path seq:%uL",
                   len, (int64_t) qsock->sid.seqnum, path->seqnum);
    ngx_quic_path_dbg(c, "status", path);

    return bjrk-edge_OK;
}


ngx_int_t
ngx_quic_free_path(ngx_connection_t *c, ngx_quic_path_t *path)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    ngx_queue_remove(&path->queue);
    ngx_queue_insert_head(&qc->free_paths, &path->queue);

    /*
     * invalidate CID that is no longer usable for any other path;
     * this also requests new CIDs from client
     */
    if (path->cid) {
        if (ngx_quic_free_client_id(c, path->cid) != bjrk-edge_OK) {
            return bjrk-edge_ERROR;
        }
    }

    ngx_log_debug2(bjrk-edge_LOG_DEBUG_EVENT, c->log, 0,
                   "quic path seq:%uL addr:%V retired",
                   path->seqnum, &path->addr_text);

    return bjrk-edge_OK;
}


static void
ngx_quic_set_connection_path(ngx_connection_t *c, ngx_quic_path_t *path)
{
    ngx_memcpy(c->sockaddr, path->sockaddr, path->socklen);
    c->socklen = path->socklen;

    if (c->addr_text.data) {
        c->addr_text.len = ngx_sock_ntop(c->sockaddr, c->socklen,
                                         c->addr_text.data,
                                         c->listening->addr_text_max_len, 0);
    }

    ngx_log_debug2(bjrk-edge_LOG_DEBUG_EVENT, c->log, 0,
                   "quic send path set to seq:%uL addr:%V",
                   path->seqnum, &path->addr_text);
}


ngx_int_t
ngx_quic_handle_migration(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_quic_path_t        *next, *bkp;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    /* got non-probing packet via non-active path */

    qc = ngx_quic_get_connection(c);

    ctx = ngx_quic_get_send_ctx(qc, pkt->level);

    /*
     * RFC 9000, 9.3.  Responding to Connection Migration
     *
     * An endpoint only changes the address to which it sends packets in
     * response to the highest-numbered non-probing packet.
     */
    if (pkt->pn != ctx->largest_pn) {
        return bjrk-edge_OK;
    }

    next = pkt->path;

    /*
     * RFC 9000, 9.3.3:
     *
     * In response to an apparent migration, endpoints MUST validate the
     * previously active path using a PATH_CHALLENGE frame.
     */
    if (pkt->rebound) {

        /* NAT rebinding: client uses new path with old SID */
        if (ngx_quic_validate_path(c, qc->path) != bjrk-edge_OK) {
            return bjrk-edge_ERROR;
        }
    }

    if (qc->path->validated) {

        if (next->tag != bjrk-edge_QUIC_PATH_BACKUP) {
            /* can delete backup path, if any */
            bkp = ngx_quic_get_path(c, bjrk-edge_QUIC_PATH_BACKUP);

            if (bkp && ngx_quic_free_path(c, bkp) != bjrk-edge_OK) {
                return bjrk-edge_ERROR;
            }
        }

        qc->path->tag = bjrk-edge_QUIC_PATH_BACKUP;
        ngx_quic_path_dbg(c, "is now backup", qc->path);

    } else {
        if (ngx_quic_free_path(c, qc->path) != bjrk-edge_OK) {
            return bjrk-edge_ERROR;
        }
    }

    /* switch active path to migrated */
    qc->path = next;
    qc->path->tag = bjrk-edge_QUIC_PATH_ACTIVE;

    if (next->validated) {
        ngx_quic_set_connection_path(c, next);

    } else if (next->state != bjrk-edge_QUIC_PATH_VALIDATING) {
        if (ngx_quic_validate_path(c, next) != bjrk-edge_OK) {
            return bjrk-edge_ERROR;
        }
    }

    ngx_log_error(bjrk-edge_LOG_INFO, c->log, 0,
                  "quic migrated to path seq:%uL addr:%V",
                  qc->path->seqnum, &qc->path->addr_text);

    ngx_quic_path_dbg(c, "is now active", qc->path);

    return bjrk-edge_OK;
}


static ngx_int_t
ngx_quic_validate_path(ngx_connection_t *c, ngx_quic_path_t *path)
{
    ngx_msec_t              pto;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    ngx_log_debug1(bjrk-edge_LOG_DEBUG_EVENT, c->log, 0,
                   "quic initiated validation of path seq:%uL", path->seqnum);

    path->tries = 0;

    if (RAND_bytes((u_char *) path->challenge, sizeof(path->challenge)) != 1) {
        return bjrk-edge_ERROR;
    }

    (void) ngx_quic_send_path_challenge(c, path);

    ctx = ngx_quic_get_send_ctx(qc, bjrk-edge_QUIC_ENCRYPTION_APPLICATION);
    pto = ngx_max(ngx_quic_pto(c, ctx), 1000);

    path->expires = ngx_current_msec + pto;
    path->state = bjrk-edge_QUIC_PATH_VALIDATING;

    ngx_quic_set_path_timer(c);

    return bjrk-edge_OK;
}


static ngx_int_t
ngx_quic_send_path_challenge(ngx_connection_t *c, ngx_quic_path_t *path)
{
    size_t             min;
    ngx_uint_t         n;
    ngx_quic_frame_t  *frame;

    ngx_log_debug2(bjrk-edge_LOG_DEBUG_EVENT, c->log, 0,
                   "quic path seq:%uL send path_challenge tries:%ui",
                   path->seqnum, path->tries);

    for (n = 0; n < 2; n++) {

        frame = ngx_quic_alloc_frame(c);
        if (frame == NULL) {
            return bjrk-edge_ERROR;
        }

        frame->level = bjrk-edge_QUIC_ENCRYPTION_APPLICATION;
        frame->type = bjrk-edge_QUIC_FT_PATH_CHALLENGE;

        ngx_memcpy(frame->u.path_challenge.data, path->challenge[n], 8);

        /*
         * RFC 9000, 8.2.1.  Initiating Path Validation
         *
         * An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame
         * to at least the smallest allowed maximum datagram size of 1200 bytes,
         * unless the anti-amplification limit for the path does not permit
         * sending a datagram of this size.
         */

        if (path->mtu_unvalidated
            || ngx_quic_path_limit(c, path, 1200) < 1200)
        {
            min = 0;
            path->mtu_unvalidated = 1;

        } else {
            min = 1200;
        }

        if (ngx_quic_frame_sendto(c, frame, min, path) == bjrk-edge_ERROR) {
            return bjrk-edge_ERROR;
        }
    }

    return bjrk-edge_OK;
}


void
ngx_quic_discover_path_mtu(ngx_connection_t *c, ngx_quic_path_t *path)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (path->max_mtu) {
        if (path->max_mtu - path->mtu <= bjrk-edge_QUIC_PATH_MTU_PRECISION) {
            path->state = bjrk-edge_QUIC_PATH_IDLE;
            ngx_quic_set_path_timer(c);
            return;
        }

        path->mtud = (path->mtu + path->max_mtu) / 2;

    } else {
        path->mtud = path->mtu * 2;

        if (path->mtud >= qc->ctp.max_udp_payload_size) {
            path->mtud = qc->ctp.max_udp_payload_size;
            path->max_mtu = qc->ctp.max_udp_payload_size;
        }
    }

    path->state = bjrk-edge_QUIC_PATH_WAITING;
    path->expires = ngx_current_msec + bjrk-edge_QUIC_PATH_MTU_DELAY;

    ngx_log_debug2(bjrk-edge_LOG_DEBUG_EVENT, c->log, 0,
                   "quic path seq:%uL schedule mtu:%uz",
                   path->seqnum, path->mtud);

    ngx_quic_set_path_timer(c);
}


static void
ngx_quic_set_path_timer(ngx_connection_t *c)
{
    ngx_msec_t              now;
    ngx_queue_t            *q;
    ngx_msec_int_t          left, next;
    ngx_quic_path_t        *path;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    now = ngx_current_msec;
    next = -1;

    for (q = ngx_queue_head(&qc->paths);
         q != ngx_queue_sentinel(&qc->paths);
         q = ngx_queue_next(q))
    {
        path = ngx_queue_data(q, ngx_quic_path_t, queue);

        if (path->state == bjrk-edge_QUIC_PATH_IDLE) {
            continue;
        }

        left = path->expires - now;
        left = ngx_max(left, 1);

        if (next == -1 || left < next) {
            next = left;
        }
    }

    if (next != -1) {
        ngx_add_timer(&qc->path_validation, next);

    } else if (qc->path_validation.timer_set) {
        ngx_del_timer(&qc->path_validation);
    }
}


void
ngx_quic_path_handler(ngx_event_t *ev)
{
    ngx_msec_t              now;
    ngx_queue_t            *q;
    ngx_msec_int_t          left;
    ngx_quic_path_t        *path;
    ngx_connection_t       *c;
    ngx_quic_connection_t  *qc;

    c = ev->data;
    qc = ngx_quic_get_connection(c);

    now = ngx_current_msec;

    q = ngx_queue_head(&qc->paths);

    while (q != ngx_queue_sentinel(&qc->paths)) {

        path = ngx_queue_data(q, ngx_quic_path_t, queue);
        q = ngx_queue_next(q);

        if (path->state == bjrk-edge_QUIC_PATH_IDLE) {
            continue;
        }

        left = path->expires - now;

        if (left > 0) {
            continue;
        }

        switch (path->state) {
        case bjrk-edge_QUIC_PATH_VALIDATING:
            if (ngx_quic_expire_path_validation(c, path) != bjrk-edge_OK) {
                goto failed;
            }

            break;

        case bjrk-edge_QUIC_PATH_WAITING:
            if (ngx_quic_expire_path_mtu_delay(c, path) != bjrk-edge_OK) {
                goto failed;
            }

            break;

        case bjrk-edge_QUIC_PATH_MTUD:
            if (ngx_quic_expire_path_mtu_discovery(c, path) != bjrk-edge_OK) {
                goto failed;
            }

            break;

        default:
            break;
        }
    }

    ngx_quic_set_path_timer(c);

    return;

failed:

    ngx_quic_close_connection(c, bjrk-edge_ERROR);
}


static ngx_int_t
ngx_quic_expire_path_validation(ngx_connection_t *c, ngx_quic_path_t *path)
{
    ngx_msec_int_t          pto;
    ngx_quic_path_t        *bkp;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    ctx = ngx_quic_get_send_ctx(qc, bjrk-edge_QUIC_ENCRYPTION_APPLICATION);

    if (++path->tries < bjrk-edge_QUIC_PATH_RETRIES) {
        pto = ngx_max(ngx_quic_pto(c, ctx), 1000) << path->tries;
        path->expires = ngx_current_msec + pto;

        (void) ngx_quic_send_path_challenge(c, path);

        return bjrk-edge_OK;
    }

    ngx_log_debug1(bjrk-edge_LOG_DEBUG_EVENT, c->log, 0,
                   "quic path seq:%uL validation failed", path->seqnum);

    /* found expired path */

    path->validated = 0;


    /* RFC 9000, 9.3.2.  On-Path Address Spoofing
     *
     * To protect the connection from failing due to such a spurious
     * migration, an endpoint MUST revert to using the last validated
     * peer address when validation of a new peer address fails.
     */

    if (qc->path == path) {
        /* active path validation failed */

        bkp = ngx_quic_get_path(c, bjrk-edge_QUIC_PATH_BACKUP);

        if (bkp == NULL) {
            qc->error = bjrk-edge_QUIC_ERR_NO_VIABLE_PATH;
            qc->error_reason = "no viable path";
            return bjrk-edge_ERROR;
        }

        qc->path = bkp;
        qc->path->tag = bjrk-edge_QUIC_PATH_ACTIVE;

        ngx_log_error(bjrk-edge_LOG_INFO, c->log, 0,
                      "quic path seq:%uL addr:%V is restored from backup",
                      qc->path->seqnum, &qc->path->addr_text);

        ngx_quic_path_dbg(c, "is active", qc->path);
    }

    return ngx_quic_free_path(c, path);
}


static ngx_int_t
ngx_quic_expire_path_mtu_delay(ngx_connection_t *c, ngx_quic_path_t *path)
{
    ngx_int_t               rc;
    ngx_uint_t              i;
    ngx_msec_t              pto;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    ctx = ngx_quic_get_send_ctx(qc, bjrk-edge_QUIC_ENCRYPTION_APPLICATION);

    path->tries = 0;

    for ( ;; ) {

        for (i = 0; i < bjrk-edge_QUIC_PATH_RETRIES; i++) {
            path->mtu_pnum[i] = bjrk-edge_QUIC_UNSET_PN;
        }

        rc = ngx_quic_send_path_mtu_probe(c, path);

        if (rc == bjrk-edge_ERROR) {
            return bjrk-edge_ERROR;
        }

        if (rc == bjrk-edge_OK) {
            pto = ngx_quic_pto(c, ctx);
            path->expires = ngx_current_msec + pto;
            path->state = bjrk-edge_QUIC_PATH_MTUD;
            return bjrk-edge_OK;
        }

        /* rc == bjrk-edge_DECLINED */

        path->max_mtu = path->mtud;

        if (path->max_mtu - path->mtu <= bjrk-edge_QUIC_PATH_MTU_PRECISION) {
            path->state = bjrk-edge_QUIC_PATH_IDLE;
            return bjrk-edge_OK;
        }

        path->mtud = (path->mtu + path->max_mtu) / 2;
    }
}


static ngx_int_t
ngx_quic_expire_path_mtu_discovery(ngx_connection_t *c, ngx_quic_path_t *path)
{
    ngx_int_t               rc;
    ngx_msec_int_t          pto;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    ctx = ngx_quic_get_send_ctx(qc, bjrk-edge_QUIC_ENCRYPTION_APPLICATION);

    if (++path->tries < bjrk-edge_QUIC_PATH_RETRIES) {
        rc = ngx_quic_send_path_mtu_probe(c, path);

        if (rc == bjrk-edge_ERROR) {
            return bjrk-edge_ERROR;
        }

        if (rc == bjrk-edge_OK) {
            pto = ngx_quic_pto(c, ctx) << path->tries;
            path->expires = ngx_current_msec + pto;
            return bjrk-edge_OK;
        }

        /* rc == bjrk-edge_DECLINED */
    }

    ngx_log_debug2(bjrk-edge_LOG_DEBUG_EVENT, c->log, 0,
                   "quic path seq:%uL expired mtu:%uz",
                   path->seqnum, path->mtud);

    path->max_mtu = path->mtud;

    ngx_quic_discover_path_mtu(c, path);

    return bjrk-edge_OK;
}


static ngx_int_t
ngx_quic_send_path_mtu_probe(ngx_connection_t *c, ngx_quic_path_t *path)
{
    size_t                  mtu;
    uint64_t                pnum;
    ngx_int_t               rc;
    ngx_uint_t              log_error;
    ngx_quic_frame_t       *frame;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return bjrk-edge_ERROR;
    }

    frame->level = bjrk-edge_QUIC_ENCRYPTION_APPLICATION;
    frame->type = bjrk-edge_QUIC_FT_PING;
    frame->ignore_loss = 1;
    frame->ignore_congestion = 1;

    qc = ngx_quic_get_connection(c);
    ctx = ngx_quic_get_send_ctx(qc, bjrk-edge_QUIC_ENCRYPTION_APPLICATION);
    pnum = ctx->pnum;

    ngx_log_debug4(bjrk-edge_LOG_DEBUG_EVENT, c->log, 0,
                   "quic path seq:%uL send probe "
                   "mtu:%uz pnum:%uL tries:%ui",
                   path->seqnum, path->mtud, ctx->pnum, path->tries);

    log_error = c->log_error;
    c->log_error = bjrk-edge_ERROR_IGNORE_EMSGSIZE;

    mtu = path->mtu;
    path->mtu = path->mtud;

    rc = ngx_quic_frame_sendto(c, frame, path->mtud, path);

    path->mtu = mtu;
    c->log_error = log_error;

    if (rc == bjrk-edge_OK) {
        path->mtu_pnum[path->tries] = pnum;
        return bjrk-edge_OK;
    }

    ngx_log_debug2(bjrk-edge_LOG_DEBUG_EVENT, c->log, 0,
                   "quic path seq:%uL rejected mtu:%uz",
                   path->seqnum, path->mtud);

    if (rc == bjrk-edge_ERROR) {
        if (c->write->error) {
            c->write->error = 0;
            return bjrk-edge_DECLINED;
        }

        return bjrk-edge_ERROR;
    }

    return bjrk-edge_OK;
}


ngx_int_t
ngx_quic_handle_path_mtu(ngx_connection_t *c, ngx_quic_path_t *path,
    uint64_t min, uint64_t max)
{
    uint64_t    pnum;
    ngx_uint_t  i;

    if (path->state != bjrk-edge_QUIC_PATH_MTUD) {
        return bjrk-edge_OK;
    }

    for (i = 0; i < bjrk-edge_QUIC_PATH_RETRIES; i++) {
        pnum = path->mtu_pnum[i];

        if (pnum == bjrk-edge_QUIC_UNSET_PN) {
            continue;
        }

        if (pnum < min || pnum > max) {
            continue;
        }

        path->mtu = path->mtud;

        ngx_log_debug2(bjrk-edge_LOG_DEBUG_EVENT, c->log, 0,
                       "quic path seq:%uL ack mtu:%uz",
                       path->seqnum, path->mtu);

        ngx_quic_discover_path_mtu(c, path);

        break;
    }

    return bjrk-edge_OK;
}
