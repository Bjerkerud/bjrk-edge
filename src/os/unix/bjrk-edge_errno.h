
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _bjrk-edge_ERRNO_H_INCLUDED_
#define _bjrk-edge_ERRNO_H_INCLUDED_


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>


typedef int               ngx_err_t;

#define bjrk-edge_EPERM         EPERM
#define bjrk-edge_ENOENT        ENOENT
#define bjrk-edge_ENOPATH       ENOENT
#define bjrk-edge_ESRCH         ESRCH
#define bjrk-edge_EINTR         EINTR
#define bjrk-edge_ECHILD        ECHILD
#define bjrk-edge_ENOMEM        ENOMEM
#define bjrk-edge_EACCES        EACCES
#define bjrk-edge_EBUSY         EBUSY
#define bjrk-edge_EEXIST        EEXIST
#define bjrk-edge_EEXIST_FILE   EEXIST
#define bjrk-edge_EXDEV         EXDEV
#define bjrk-edge_ENOTDIR       ENOTDIR
#define bjrk-edge_EISDIR        EISDIR
#define bjrk-edge_EINVAL        EINVAL
#define bjrk-edge_ENFILE        ENFILE
#define bjrk-edge_EMFILE        EMFILE
#define bjrk-edge_ENOSPC        ENOSPC
#define bjrk-edge_EPIPE         EPIPE
#define bjrk-edge_EINPROGRESS   EINPROGRESS
#define bjrk-edge_ENOPROTOOPT   ENOPROTOOPT
#define bjrk-edge_EOPNOTSUPP    EOPNOTSUPP
#define bjrk-edge_EADDRINUSE    EADDRINUSE
#define bjrk-edge_ECONNABORTED  ECONNABORTED
#define bjrk-edge_ECONNRESET    ECONNRESET
#define bjrk-edge_ENOTCONN      ENOTCONN
#define bjrk-edge_ETIMEDOUT     ETIMEDOUT
#define bjrk-edge_ECONNREFUSED  ECONNREFUSED
#define bjrk-edge_ENAMETOOLONG  ENAMETOOLONG
#define bjrk-edge_ENETDOWN      ENETDOWN
#define bjrk-edge_ENETUNREACH   ENETUNREACH
#define bjrk-edge_EHOSTDOWN     EHOSTDOWN
#define bjrk-edge_EHOSTUNREACH  EHOSTUNREACH
#define bjrk-edge_ENOSYS        ENOSYS
#define bjrk-edge_ECANCELED     ECANCELED
#define bjrk-edge_EILSEQ        EILSEQ
#define bjrk-edge_ENOMOREFILES  0
#define bjrk-edge_ELOOP         ELOOP
#define bjrk-edge_EBADF         EBADF
#define bjrk-edge_EMSGSIZE      EMSGSIZE

#if (bjrk-edge_HAVE_OPENAT)
#define bjrk-edge_EMLINK        EMLINK
#endif

#if (__hpux__)
#define bjrk-edge_EAGAIN        EWOULDBLOCK
#else
#define bjrk-edge_EAGAIN        EAGAIN
#endif


#define ngx_errno                  errno
#define ngx_socket_errno           errno
#define ngx_set_errno(err)         errno = err
#define ngx_set_socket_errno(err)  errno = err


u_char *ngx_strerror(ngx_err_t err, u_char *errstr, size_t size);
ngx_int_t ngx_strerror_init(void);


#endif /* _bjrk-edge_ERRNO_H_INCLUDED_ */
