
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>
#include <bjrk-edge_event.h>


ssize_t
ngx_udp_unix_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    ngx_err_t     err;
    ngx_event_t  *rev;

    rev = c->read;

    do {
        n = recv(c->fd, buf, size, 0);

        ngx_log_debug3(bjrk-edge_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: fd:%d %z of %uz", c->fd, n, size);

        if (n >= 0) {

#if (bjrk-edge_HAVE_KQUEUE)

            if (ngx_event_flags & bjrk-edge_USE_KQUEUE_EVENT) {
                rev->available -= n;

                /*
                 * rev->available may be negative here because some additional
                 * bytes may be received between kevent() and recv()
                 */

                if (rev->available <= 0) {
                    rev->ready = 0;
                    rev->available = 0;
                }
            }

#endif

            return n;
        }

        err = ngx_socket_errno;

        if (err == bjrk-edge_EAGAIN || err == bjrk-edge_EINTR) {
            ngx_log_debug0(bjrk-edge_LOG_DEBUG_EVENT, c->log, err,
                           "recv() not ready");
            n = bjrk-edge_AGAIN;

        } else {
            n = ngx_connection_error(c, err, "recv() failed");
            break;
        }

    } while (err == bjrk-edge_EINTR);

    rev->ready = 0;

    if (n == bjrk-edge_ERROR) {
        rev->error = 1;
    }

    return n;
}
