
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#ifndef _bjrk-edge_DLOPEN_H_INCLUDED_
#define _bjrk-edge_DLOPEN_H_INCLUDED_


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>


#define ngx_dlopen(path)           dlopen((char *) path, RTLD_NOW | RTLD_GLOBAL)
#define ngx_dlopen_n               "dlopen()"

#define ngx_dlsym(handle, symbol)  dlsym(handle, symbol)
#define ngx_dlsym_n                "dlsym()"

#define ngx_dlclose(handle)        dlclose(handle)
#define ngx_dlclose_n              "dlclose()"


#if (bjrk-edge_HAVE_DLOPEN)
char *ngx_dlerror(void);
#endif


#endif /* _bjrk-edge_DLOPEN_H_INCLUDED_ */
