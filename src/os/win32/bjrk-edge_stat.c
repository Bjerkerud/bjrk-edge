
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>


int ngx_file_type(char *file, ngx_file_info_t *sb)
{
    sb->dwFileAttributes = GetFileAttributes(file);

    if (sb->dwFileAttributes == INVALID_FILE_ATTRIBUTES) {
        return -1;
    }

    return 0;
}

/*
int ngx_stat(char *file, ngx_stat_t *sb)
{
    *sb = GetFileAttributes(file);

    if (*sb == INVALID_FILE_ATTRIBUTES) {
        return -1;
    }

    return 0;
}
*/
