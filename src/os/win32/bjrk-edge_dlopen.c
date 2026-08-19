
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>


char *
ngx_dlerror(void)
{
    u_char         *p;
    static u_char   errstr[bjrk-edge_MAX_ERROR_STR];

    p = ngx_strerror(ngx_errno, errstr, bjrk-edge_MAX_ERROR_STR);
    *p = '\0';

    return (char *) errstr;
}
