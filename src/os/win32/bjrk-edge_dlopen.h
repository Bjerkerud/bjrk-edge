
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#ifndef _bjrk-edge_DLOPEN_H_INCLUDED_
#define _bjrk-edge_DLOPEN_H_INCLUDED_


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>


#define bjrk-edge_HAVE_DLOPEN  1


#define ngx_dlopen(path)           LoadLibrary((char *) path)
#define ngx_dlopen_n               "LoadLibrary()"

#define ngx_dlsym(handle, symbol)  (void *) GetProcAddress(handle, symbol)
#define ngx_dlsym_n                "GetProcAddress()"

#define ngx_dlclose(handle)        (FreeLibrary(handle) ? 0 : -1)
#define ngx_dlclose_n              "FreeLibrary()"


char *ngx_dlerror(void);


#endif /* _bjrk-edge_DLOPEN_H_INCLUDED_ */
