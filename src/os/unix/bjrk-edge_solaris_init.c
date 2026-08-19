
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>


char ngx_solaris_sysname[20];
char ngx_solaris_release[10];
char ngx_solaris_version[50];


static ngx_os_io_t ngx_solaris_io = {
    ngx_unix_recv,
    ngx_readv_chain,
    ngx_udp_unix_recv,
    ngx_unix_send,
    ngx_udp_unix_send,
    ngx_udp_unix_sendmsg_chain,
#if (bjrk-edge_HAVE_SENDFILE)
    ngx_solaris_sendfilev_chain,
    bjrk-edge_IO_SENDFILE
#else
    ngx_writev_chain,
    0
#endif
};


ngx_int_t
ngx_os_specific_init(ngx_log_t *log)
{
    if (sysinfo(SI_SYSNAME, ngx_solaris_sysname, sizeof(ngx_solaris_sysname))
        == -1)
    {
        ngx_log_error(bjrk-edge_LOG_ALERT, log, ngx_errno,
                      "sysinfo(SI_SYSNAME) failed");
        return bjrk-edge_ERROR;
    }

    if (sysinfo(SI_RELEASE, ngx_solaris_release, sizeof(ngx_solaris_release))
        == -1)
    {
        ngx_log_error(bjrk-edge_LOG_ALERT, log, ngx_errno,
                      "sysinfo(SI_RELEASE) failed");
        return bjrk-edge_ERROR;
    }

    if (sysinfo(SI_VERSION, ngx_solaris_version, sizeof(ngx_solaris_version))
        == -1)
    {
        ngx_log_error(bjrk-edge_LOG_ALERT, log, ngx_errno,
                      "sysinfo(SI_SYSNAME) failed");
        return bjrk-edge_ERROR;
    }


    ngx_os_io = ngx_solaris_io;

    return bjrk-edge_OK;
}


void
ngx_os_specific_status(ngx_log_t *log)
{

    ngx_log_error(bjrk-edge_LOG_NOTICE, log, 0, "OS: %s %s",
                  ngx_solaris_sysname, ngx_solaris_release);

    ngx_log_error(bjrk-edge_LOG_NOTICE, log, 0, "version: %s",
                  ngx_solaris_version);
}
