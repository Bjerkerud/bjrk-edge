
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _bjrk-edge_CORE_H_INCLUDED_
#define _bjrk-edge_CORE_H_INCLUDED_


#include <bjrk-edge_config.h>


typedef struct ngx_module_s          ngx_module_t;
typedef struct ngx_conf_s            ngx_conf_t;
typedef struct ngx_cycle_s           ngx_cycle_t;
typedef struct ngx_pool_s            ngx_pool_t;
typedef struct ngx_chain_s           ngx_chain_t;
typedef struct ngx_log_s             ngx_log_t;
typedef struct ngx_open_file_s       ngx_open_file_t;
typedef struct ngx_command_s         ngx_command_t;
typedef struct ngx_file_s            ngx_file_t;
typedef struct ngx_event_s           ngx_event_t;
typedef struct ngx_event_aio_s       ngx_event_aio_t;
typedef struct ngx_connection_s      ngx_connection_t;
typedef struct ngx_thread_task_s     ngx_thread_task_t;
typedef struct ngx_ssl_s             ngx_ssl_t;
typedef struct ngx_ssl_cache_s       ngx_ssl_cache_t;
typedef struct ngx_proxy_protocol_s  ngx_proxy_protocol_t;
typedef struct ngx_quic_stream_s     ngx_quic_stream_t;
typedef struct ngx_ssl_connection_s  ngx_ssl_connection_t;
typedef struct ngx_udp_connection_s  ngx_udp_connection_t;

typedef void (*ngx_event_handler_pt)(ngx_event_t *ev);
typedef void (*ngx_connection_handler_pt)(ngx_connection_t *c);


#define  bjrk-edge_OK          0
#define  bjrk-edge_ERROR      -1
#define  bjrk-edge_AGAIN      -2
#define  bjrk-edge_BUSY       -3
#define  bjrk-edge_DONE       -4
#define  bjrk-edge_DECLINED   -5
#define  bjrk-edge_ABORT      -6


#include <bjrk-edge_errno.h>
#include <bjrk-edge_atomic.h>
#include <bjrk-edge_thread.h>
#include <bjrk-edge_rbtree.h>
#include <bjrk-edge_time.h>
#include <bjrk-edge_socket.h>
#include <bjrk-edge_string.h>
#include <bjrk-edge_files.h>
#include <bjrk-edge_shmem.h>
#include <bjrk-edge_process.h>
#include <bjrk-edge_user.h>
#include <bjrk-edge_dlopen.h>
#include <bjrk-edge_parse.h>
#include <bjrk-edge_parse_time.h>
#include <bjrk-edge_log.h>
#include <bjrk-edge_alloc.h>
#include <bjrk-edge_palloc.h>
#include <bjrk-edge_buf.h>
#include <bjrk-edge_queue.h>
#include <bjrk-edge_array.h>
#include <bjrk-edge_list.h>
#include <bjrk-edge_hash.h>
#include <bjrk-edge_file.h>
#include <bjrk-edge_crc.h>
#include <bjrk-edge_crc32.h>
#include <bjrk-edge_murmurhash.h>
#include <bjrk-edge_siphash.h>
#if (bjrk-edge_PCRE)
#include <bjrk-edge_regex.h>
#endif
#include <bjrk-edge_radix_tree.h>
#include <bjrk-edge_times.h>
#include <bjrk-edge_rwlock.h>
#include <bjrk-edge_shmtx.h>
#include <bjrk-edge_data.h>
#include <bjrk-edge_json.h>
#include <bjrk-edge_slab.h>
#include <bjrk-edge_inet.h>
#include <bjrk-edge_cycle.h>
#include <bjrk-edge_resolver.h>
#if (bjrk-edge_OPENSSL)
#include <bjrk-edge_event_openssl.h>
#if (bjrk-edge_QUIC)
#include <bjrk-edge_event_quic.h>
#endif
#endif
#include <bjrk-edge_process_cycle.h>
#include <bjrk-edge_conf_file.h>
#include <bjrk-edge_module.h>
#include <bjrk-edge_open_file_cache.h>
#include <bjrk-edge_os.h>
#include <bjrk-edge_connection.h>
#include <bjrk-edge_syslog.h>
#include <bjrk-edge_proxy_protocol.h>
#if (bjrk-edge_HAVE_BPF)
#include <bjrk-edge_bpf.h>
#endif


#define LF     (u_char) '\n'
#define CR     (u_char) '\r'
#define CRLF   "\r\n"


#define ngx_abs(value)       (((value) >= 0) ? (value) : - (value))
#define ngx_max(val1, val2)  ((val1 < val2) ? (val2) : (val1))
#define ngx_min(val1, val2)  ((val1 > val2) ? (val2) : (val1))

void ngx_cpuinfo(void);

#if (bjrk-edge_HAVE_OPENAT)
#define bjrk-edge_DISABLE_SYMLINKS_OFF        0
#define bjrk-edge_DISABLE_SYMLINKS_ON         1
#define bjrk-edge_DISABLE_SYMLINKS_NOTOWNER   2
#endif

#endif /* _bjrk-edge_CORE_H_INCLUDED_ */
