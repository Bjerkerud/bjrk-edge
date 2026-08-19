
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>
#include <bjrk-edge_event.h>


ssize_t
ngx_unix_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    ngx_err_t     err;
    ngx_event_t  *wev;

    wev = c->write;

#if (bjrk-edge_HAVE_KQUEUE)

    if ((ngx_event_flags & bjrk-edge_USE_KQUEUE_EVENT) && wev->pending_eof) {
        (void) ngx_connection_error(c, wev->kq_errno,
                               "kevent() reported about an closed connection");
        wev->error = 1;
        return bjrk-edge_ERROR;
    }

#endif

    for ( ;; ) {
        n = send(c->fd, buf, size, 0);

        ngx_log_debug3(bjrk-edge_LOG_DEBUG_EVENT, c->log, 0,
                       "send: fd:%d %z of %uz", c->fd, n, size);

        if (n > 0) {
            if (n < (ssize_t) size) {
                wev->ready = 0;
            }

            c->sent += n;

            return n;
        }

        err = ngx_socket_errno;

        if (n == 0) {
            ngx_log_error(bjrk-edge_LOG_ALERT, c->log, err, "send() returned zero");
            wev->ready = 0;
            return n;
        }

        if (err == bjrk-edge_EAGAIN || err == bjrk-edge_EINTR) {
            wev->ready = 0;

            ngx_log_debug0(bjrk-edge_LOG_DEBUG_EVENT, c->log, err,
                           "send() not ready");

            if (err == bjrk-edge_EAGAIN) {
                return bjrk-edge_AGAIN;
            }

        } else {
            wev->error = 1;
            (void) ngx_connection_error(c, err, "send() failed");
            return bjrk-edge_ERROR;
        }
    }
}
