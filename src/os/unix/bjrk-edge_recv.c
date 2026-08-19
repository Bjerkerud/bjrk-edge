
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>
#include <bjrk-edge_event.h>


ssize_t
ngx_unix_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    ngx_err_t     err;
    ngx_event_t  *rev;

    rev = c->read;

#if (bjrk-edge_HAVE_KQUEUE)

    if (ngx_event_flags & bjrk-edge_USE_KQUEUE_EVENT) {
        ngx_log_debug3(bjrk-edge_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: eof:%d, avail:%d, err:%d",
                       rev->pending_eof, rev->available, rev->kq_errno);

        if (rev->available == 0) {
            if (rev->pending_eof) {
                rev->ready = 0;
                rev->eof = 1;

                if (rev->kq_errno) {
                    rev->error = 1;
                    ngx_set_socket_errno(rev->kq_errno);

                    return ngx_connection_error(c, rev->kq_errno,
                               "kevent() reported about an closed connection");
                }

                return 0;

            } else {
                rev->ready = 0;
                return bjrk-edge_AGAIN;
            }
        }
    }

#endif

#if (bjrk-edge_HAVE_EPOLLRDHUP)

    if ((ngx_event_flags & bjrk-edge_USE_EPOLL_EVENT)
        && ngx_use_epoll_rdhup)
    {
        ngx_log_debug2(bjrk-edge_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: eof:%d, avail:%d",
                       rev->pending_eof, rev->available);

        if (rev->available == 0 && !rev->pending_eof) {
            rev->ready = 0;
            return bjrk-edge_AGAIN;
        }
    }

#endif

    do {
        n = recv(c->fd, buf, size, 0);

        ngx_log_debug3(bjrk-edge_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: fd:%d %z of %uz", c->fd, n, size);

        if (n == 0) {
            rev->ready = 0;
            rev->eof = 1;

#if (bjrk-edge_HAVE_KQUEUE)

            /*
             * on FreeBSD recv() may return 0 on closed socket
             * even if kqueue reported about available data
             */

            if (ngx_event_flags & bjrk-edge_USE_KQUEUE_EVENT) {
                rev->available = 0;
            }

#endif

            return 0;
        }

        if (n > 0) {

#if (bjrk-edge_HAVE_KQUEUE)

            if (ngx_event_flags & bjrk-edge_USE_KQUEUE_EVENT) {
                rev->available -= n;

                /*
                 * rev->available may be negative here because some additional
                 * bytes may be received between kevent() and recv()
                 */

                if (rev->available <= 0) {
                    if (!rev->pending_eof) {
                        rev->ready = 0;
                    }

                    rev->available = 0;
                }

                return n;
            }

#endif

#if (bjrk-edge_HAVE_FIONREAD)

            if (rev->available >= 0) {
                rev->available -= n;

                /*
                 * negative rev->available means some additional bytes
                 * were received between kernel notification and recv(),
                 * and therefore ev->ready can be safely reset even for
                 * edge-triggered event methods
                 */

                if (rev->available < 0) {
                    rev->available = 0;
                    rev->ready = 0;
                }

                ngx_log_debug1(bjrk-edge_LOG_DEBUG_EVENT, c->log, 0,
                               "recv: avail:%d", rev->available);

            } else if ((size_t) n == size) {

                if (ngx_socket_nread(c->fd, &rev->available) == -1) {
                    n = ngx_connection_error(c, ngx_socket_errno,
                                             ngx_socket_nread_n " failed");
                    break;
                }

                ngx_log_debug1(bjrk-edge_LOG_DEBUG_EVENT, c->log, 0,
                               "recv: avail:%d", rev->available);
            }

#endif

#if (bjrk-edge_HAVE_EPOLLRDHUP)

            if ((ngx_event_flags & bjrk-edge_USE_EPOLL_EVENT)
                && ngx_use_epoll_rdhup)
            {
                if ((size_t) n < size) {
                    if (!rev->pending_eof) {
                        rev->ready = 0;
                    }

                    rev->available = 0;
                }

                return n;
            }

#endif

            if ((size_t) n < size
                && !(ngx_event_flags & bjrk-edge_USE_GREEDY_EVENT))
            {
                rev->ready = 0;
            }

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
