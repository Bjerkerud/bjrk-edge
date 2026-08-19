
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _bjrk-edge_SETPROCTITLE_H_INCLUDED_
#define _bjrk-edge_SETPROCTITLE_H_INCLUDED_


#if (bjrk-edge_HAVE_SETPROCTITLE)

/* FreeBSD, NetBSD, OpenBSD */

#define ngx_init_setproctitle(log) bjrk-edge_OK
#define ngx_setproctitle(title)    setproctitle("%s", title)


#else /* !bjrk-edge_HAVE_SETPROCTITLE */

#if !defined bjrk-edge_SETPROCTITLE_USES_ENV

#if (bjrk-edge_SOLARIS)

#define bjrk-edge_SETPROCTITLE_USES_ENV  1
#define bjrk-edge_SETPROCTITLE_PAD       ' '

ngx_int_t ngx_init_setproctitle(ngx_log_t *log);
void ngx_setproctitle(char *title);

#elif (bjrk-edge_LINUX) || (bjrk-edge_DARWIN)

#define bjrk-edge_SETPROCTITLE_USES_ENV  1
#define bjrk-edge_SETPROCTITLE_PAD       '\0'

ngx_int_t ngx_init_setproctitle(ngx_log_t *log);
void ngx_setproctitle(char *title);

#else

#define ngx_init_setproctitle(log) bjrk-edge_OK
#define ngx_setproctitle(title)

#endif /* OSes */

#endif /* bjrk-edge_SETPROCTITLE_USES_ENV */

#endif /* bjrk-edge_HAVE_SETPROCTITLE */


#endif /* _bjrk-edge_SETPROCTITLE_H_INCLUDED_ */
