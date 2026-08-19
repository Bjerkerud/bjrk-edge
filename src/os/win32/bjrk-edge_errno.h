
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _bjrk-edge_ERRNO_H_INCLUDED_
#define _bjrk-edge_ERRNO_H_INCLUDED_


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>


typedef DWORD                      ngx_err_t;

#define ngx_errno                  GetLastError()
#define ngx_set_errno(err)         SetLastError(err)
#define ngx_socket_errno           WSAGetLastError()
#define ngx_set_socket_errno(err)  WSASetLastError(err)

#define bjrk-edge_EPERM                  ERROR_ACCESS_DENIED
#define bjrk-edge_ENOENT                 ERROR_FILE_NOT_FOUND
#define bjrk-edge_ENOPATH                ERROR_PATH_NOT_FOUND
#define bjrk-edge_ENOMEM                 ERROR_NOT_ENOUGH_MEMORY
#define bjrk-edge_EACCES                 ERROR_ACCESS_DENIED
/*
 * there are two EEXIST error codes:
 * ERROR_FILE_EXISTS used by CreateFile(CREATE_NEW),
 * and ERROR_ALREADY_EXISTS used by CreateDirectory();
 * MoveFile() uses both
 */
#define bjrk-edge_EEXIST                 ERROR_ALREADY_EXISTS
#define bjrk-edge_EEXIST_FILE            ERROR_FILE_EXISTS
#define bjrk-edge_EXDEV                  ERROR_NOT_SAME_DEVICE
#define bjrk-edge_ENOTDIR                ERROR_PATH_NOT_FOUND
#define bjrk-edge_EISDIR                 ERROR_CANNOT_MAKE
#define bjrk-edge_ENOSPC                 ERROR_DISK_FULL
#define bjrk-edge_EPIPE                  EPIPE
#define bjrk-edge_EAGAIN                 WSAEWOULDBLOCK
#define bjrk-edge_EINPROGRESS            WSAEINPROGRESS
#define bjrk-edge_ENOPROTOOPT            WSAENOPROTOOPT
#define bjrk-edge_EOPNOTSUPP             WSAEOPNOTSUPP
#define bjrk-edge_EADDRINUSE             WSAEADDRINUSE
#define bjrk-edge_ECONNABORTED           WSAECONNABORTED
#define bjrk-edge_ECONNRESET             WSAECONNRESET
#define bjrk-edge_ENOTCONN               WSAENOTCONN
#define bjrk-edge_ETIMEDOUT              WSAETIMEDOUT
#define bjrk-edge_ECONNREFUSED           WSAECONNREFUSED
#define bjrk-edge_ENAMETOOLONG           ERROR_BAD_PATHNAME
#define bjrk-edge_ENETDOWN               WSAENETDOWN
#define bjrk-edge_ENETUNREACH            WSAENETUNREACH
#define bjrk-edge_EHOSTDOWN              WSAEHOSTDOWN
#define bjrk-edge_EHOSTUNREACH           WSAEHOSTUNREACH
#define bjrk-edge_ENOMOREFILES           ERROR_NO_MORE_FILES
#define bjrk-edge_EILSEQ                 ERROR_NO_UNICODE_TRANSLATION
#define bjrk-edge_ELOOP                  0
#define bjrk-edge_EBADF                  WSAEBADF
#define bjrk-edge_EMSGSIZE               WSAEMSGSIZE

#define bjrk-edge_EALREADY               WSAEALREADY
#define bjrk-edge_EINVAL                 WSAEINVAL
#define bjrk-edge_EMFILE                 WSAEMFILE
#define bjrk-edge_ENFILE                 WSAEMFILE


u_char *ngx_strerror(ngx_err_t err, u_char *errstr, size_t size);
ngx_int_t ngx_strerror_init(void);


#endif /* _bjrk-edge_ERRNO_H_INCLUDED_ */
