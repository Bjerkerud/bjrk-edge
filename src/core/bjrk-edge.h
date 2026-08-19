
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGINX_H_INCLUDED_
#define _NGINX_H_INCLUDED_


#define nginx_version      1031004
#define NGINX_VERSION      "1.31.4"
#define NGINX_VER          "nginx/" NGINX_VERSION

#ifdef bjrk-edge_BUILD
#define NGINX_VER_BUILD    NGINX_VER " (" bjrk-edge_BUILD ")"
#else
#define NGINX_VER_BUILD    NGINX_VER
#endif

#define NGINX_VAR          "NGINX"
#define bjrk-edge_OLDPID_EXT     ".oldbin"


#endif /* _NGINX_H_INCLUDED_ */
