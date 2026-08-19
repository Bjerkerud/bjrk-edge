
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _bjrk-edge_CONFIG_H_INCLUDED_
#define _bjrk-edge_CONFIG_H_INCLUDED_


#include <bjrk-edge_auto_headers.h>


#if defined __DragonFly__ && !defined __FreeBSD__
#define __FreeBSD__        4
#define __FreeBSD_version  480101
#endif


#if (bjrk-edge_FREEBSD)
#include <bjrk-edge_freebsd_config.h>


#elif (bjrk-edge_LINUX)
#include <bjrk-edge_linux_config.h>


#elif (bjrk-edge_SOLARIS)
#include <bjrk-edge_solaris_config.h>


#elif (bjrk-edge_DARWIN)
#include <bjrk-edge_darwin_config.h>


#elif (bjrk-edge_WIN32)
#include <bjrk-edge_win32_config.h>


#else /* POSIX */
#include <bjrk-edge_posix_config.h>

#endif


#ifndef bjrk-edge_HAVE_SO_SNDLOWAT
#define bjrk-edge_HAVE_SO_SNDLOWAT     1
#endif


#if !(bjrk-edge_WIN32)

#define ngx_signal_helper(n)     SIG##n
#define ngx_signal_value(n)      ngx_signal_helper(n)

#define ngx_random               random

/* TODO: #ifndef */
#define bjrk-edge_SHUTDOWN_SIGNAL      QUIT
#define bjrk-edge_TERMINATE_SIGNAL     TERM
#define bjrk-edge_NOACCEPT_SIGNAL      WINCH
#define bjrk-edge_RECONFIGURE_SIGNAL   HUP

#if (bjrk-edge_LINUXTHREADS)
#define bjrk-edge_REOPEN_SIGNAL        INFO
#define bjrk-edge_CHANGEBIN_SIGNAL     XCPU
#else
#define bjrk-edge_REOPEN_SIGNAL        USR1
#define bjrk-edge_CHANGEBIN_SIGNAL     USR2
#endif

#define ngx_cdecl
#define ngx_libc_cdecl

#endif

typedef intptr_t        ngx_int_t;
typedef uintptr_t       ngx_uint_t;
typedef intptr_t        ngx_flag_t;


#define bjrk-edge_INT32_LEN   (sizeof("-2147483648") - 1)
#define bjrk-edge_INT64_LEN   (sizeof("-9223372036854775808") - 1)

#if (bjrk-edge_PTR_SIZE == 4)
#define bjrk-edge_INT_T_LEN   bjrk-edge_INT32_LEN
#define bjrk-edge_MAX_INT_T_VALUE  2147483647

#else
#define bjrk-edge_INT_T_LEN   bjrk-edge_INT64_LEN
#define bjrk-edge_MAX_INT_T_VALUE  9223372036854775807
#endif


#ifndef bjrk-edge_ALIGNMENT
#define bjrk-edge_ALIGNMENT   sizeof(uintptr_t)    /* platform word */
#endif

#define ngx_align(d, a)     (((d) + (a - 1)) & ~(a - 1))
#define ngx_align_ptr(p, a)                                                   \
    (u_char *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))


#define ngx_abort       abort


/* TODO: platform specific: array[bjrk-edge_INVALID_ARRAY_INDEX] must cause SIGSEGV */
#define bjrk-edge_INVALID_ARRAY_INDEX 0x80000000


/* TODO: auto_conf: ngx_inline   inline __inline __inline__ */
#ifndef ngx_inline
#define ngx_inline      inline
#endif

#ifndef INADDR_NONE  /* Solaris */
#define INADDR_NONE  ((unsigned int) -1)
#endif

#ifdef MAXHOSTNAMELEN
#define bjrk-edge_MAXHOSTNAMELEN  MAXHOSTNAMELEN
#else
#define bjrk-edge_MAXHOSTNAMELEN  256
#endif


#define bjrk-edge_MAX_UINT32_VALUE  (uint32_t) 0xffffffff
#define bjrk-edge_MAX_INT32_VALUE   (uint32_t) 0x7fffffff


#if (bjrk-edge_COMPAT)

#define bjrk-edge_COMPAT_BEGIN(slots)  uint64_t spare[slots];
#define bjrk-edge_COMPAT_END

#else

#define bjrk-edge_COMPAT_BEGIN(slots)
#define bjrk-edge_COMPAT_END

#endif


#endif /* _bjrk-edge_CONFIG_H_INCLUDED_ */
