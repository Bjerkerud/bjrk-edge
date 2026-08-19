
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _bjrk-edge_EVENT_UDP_H_INCLUDED_
#define _bjrk-edge_EVENT_UDP_H_INCLUDED_


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>


#if !(bjrk-edge_WIN32)

#if ((bjrk-edge_HAVE_MSGHDR_MSG_CONTROL)                                            \
     && (bjrk-edge_HAVE_IP_SENDSRCADDR || bjrk-edge_HAVE_IP_RECVDSTADDR                   \
         || bjrk-edge_HAVE_IP_PKTINFO                                               \
         || (bjrk-edge_HAVE_INET6 && bjrk-edge_HAVE_IPV6_RECVPKTINFO)))
#define bjrk-edge_HAVE_ADDRINFO_CMSG  1

#endif


struct ngx_udp_connection_s {
    ngx_rbtree_node_t   node;
    ngx_connection_t   *connection;
    ngx_buf_t          *buffer;
    ngx_str_t           key;
};


#if (bjrk-edge_HAVE_ADDRINFO_CMSG)

typedef union {
#if (bjrk-edge_HAVE_IP_SENDSRCADDR || bjrk-edge_HAVE_IP_RECVDSTADDR)
    struct in_addr        addr;
#endif

#if (bjrk-edge_HAVE_IP_PKTINFO)
    struct in_pktinfo     pkt;
#endif

#if (bjrk-edge_HAVE_INET6 && bjrk-edge_HAVE_IPV6_RECVPKTINFO)
    struct in6_pktinfo    pkt6;
#endif
} ngx_addrinfo_t;

size_t ngx_set_srcaddr_cmsg(struct cmsghdr *cmsg,
    struct sockaddr *local_sockaddr);
ngx_int_t ngx_get_srcaddr_cmsg(struct cmsghdr *cmsg,
    struct sockaddr *local_sockaddr);

#endif

void ngx_event_recvmsg(ngx_event_t *ev);
ssize_t ngx_sendmsg(ngx_connection_t *c, struct msghdr *msg, int flags);
void ngx_udp_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
#endif

void ngx_delete_udp_connection(void *data);


#endif /* _bjrk-edge_EVENT_UDP_H_INCLUDED_ */
