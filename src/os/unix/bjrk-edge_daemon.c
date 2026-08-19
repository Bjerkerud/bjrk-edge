
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>


ngx_int_t
ngx_daemon(ngx_log_t *log)
{
    int  fd;

    switch (fork()) {
    case -1:
        ngx_log_error(bjrk-edge_LOG_EMERG, log, ngx_errno, "fork() failed");
        return bjrk-edge_ERROR;

    case 0:
        break;

    default:
        exit(0);
    }

    ngx_parent = ngx_pid;
    ngx_pid = ngx_getpid();

    if (setsid() == -1) {
        ngx_log_error(bjrk-edge_LOG_EMERG, log, ngx_errno, "setsid() failed");
        return bjrk-edge_ERROR;
    }

    umask(0);

    fd = open("/dev/null", O_RDWR);
    if (fd == -1) {
        ngx_log_error(bjrk-edge_LOG_EMERG, log, ngx_errno,
                      "open(\"/dev/null\") failed");
        return bjrk-edge_ERROR;
    }

    if (dup2(fd, STDIN_FILENO) == -1) {
        ngx_log_error(bjrk-edge_LOG_EMERG, log, ngx_errno, "dup2(STDIN) failed");
        return bjrk-edge_ERROR;
    }

    if (dup2(fd, STDOUT_FILENO) == -1) {
        ngx_log_error(bjrk-edge_LOG_EMERG, log, ngx_errno, "dup2(STDOUT) failed");
        return bjrk-edge_ERROR;
    }

#if 0
    if (dup2(fd, STDERR_FILENO) == -1) {
        ngx_log_error(bjrk-edge_LOG_EMERG, log, ngx_errno, "dup2(STDERR) failed");
        return bjrk-edge_ERROR;
    }
#endif

    if (fd > STDERR_FILENO) {
        if (close(fd) == -1) {
            ngx_log_error(bjrk-edge_LOG_EMERG, log, ngx_errno, "close() failed");
            return bjrk-edge_ERROR;
        }
    }

    return bjrk-edge_OK;
}
