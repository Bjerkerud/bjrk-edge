
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>


#if (bjrk-edge_CRYPT)

#if (bjrk-edge_HAVE_GNU_CRYPT_R)

ngx_int_t
ngx_libc_crypt(ngx_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    char               *value;
    size_t              len;
    struct crypt_data   cd;

    cd.initialized = 0;

    value = crypt_r((char *) key, (char *) salt, &cd);

    if (value) {
        len = ngx_strlen(value) + 1;

        *encrypted = ngx_pnalloc(pool, len);
        if (*encrypted == NULL) {
            return bjrk-edge_ERROR;
        }

        ngx_memcpy(*encrypted, value, len);
        return bjrk-edge_OK;
    }

    ngx_log_error(bjrk-edge_LOG_CRIT, pool->log, ngx_errno, "crypt_r() failed");

    return bjrk-edge_ERROR;
}

#elif (bjrk-edge_HAVE_CRYPT)

ngx_int_t
ngx_libc_crypt(ngx_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    char       *value;
    size_t      len;
    ngx_err_t   err;

    value = crypt((char *) key, (char *) salt);

    if (value) {
        len = ngx_strlen(value) + 1;

        *encrypted = ngx_pnalloc(pool, len);
        if (*encrypted == NULL) {
            return bjrk-edge_ERROR;
        }

        ngx_memcpy(*encrypted, value, len);
        return bjrk-edge_OK;
    }

    err = ngx_errno;

    ngx_log_error(bjrk-edge_LOG_CRIT, pool->log, err, "crypt() failed");

    return bjrk-edge_ERROR;
}

#else

ngx_int_t
ngx_libc_crypt(ngx_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    return bjrk-edge_ERROR;
}

#endif

#endif /* bjrk-edge_CRYPT */
