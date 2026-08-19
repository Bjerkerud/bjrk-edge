
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>
#include <bjrk-edge_http.h>


#define bjrk-edge_HTTP_GZIP_STATIC_OFF     0
#define bjrk-edge_HTTP_GZIP_STATIC_ON      1
#define bjrk-edge_HTTP_GZIP_STATIC_ALWAYS  2


typedef struct {
    ngx_uint_t  enable;
} ngx_http_gzip_static_conf_t;


static ngx_int_t ngx_http_gzip_static_handler(ngx_http_request_t *r);
static void *ngx_http_gzip_static_create_conf(ngx_conf_t *cf);
static char *ngx_http_gzip_static_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_gzip_static_init(ngx_conf_t *cf);


static ngx_conf_enum_t  ngx_http_gzip_static[] = {
    { ngx_string("off"), bjrk-edge_HTTP_GZIP_STATIC_OFF },
    { ngx_string("on"), bjrk-edge_HTTP_GZIP_STATIC_ON },
    { ngx_string("always"), bjrk-edge_HTTP_GZIP_STATIC_ALWAYS },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_gzip_static_commands[] = {

    { ngx_string("gzip_static"),
      bjrk-edge_HTTP_MAIN_CONF|bjrk-edge_HTTP_SRV_CONF|bjrk-edge_HTTP_LOC_CONF|bjrk-edge_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      bjrk-edge_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_gzip_static_conf_t, enable),
      &ngx_http_gzip_static },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_gzip_static_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_gzip_static_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_gzip_static_create_conf,      /* create location configuration */
    ngx_http_gzip_static_merge_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_gzip_static_module = {
    bjrk-edge_MODULE_V1,
    &ngx_http_gzip_static_module_ctx,      /* module context */
    ngx_http_gzip_static_commands,         /* module directives */
    bjrk-edge_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    bjrk-edge_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_gzip_static_handler(ngx_http_request_t *r)
{
    u_char                       *p;
    size_t                        root;
    ngx_str_t                     path;
    ngx_int_t                     rc;
    ngx_uint_t                    level;
    ngx_log_t                    *log;
    ngx_buf_t                    *b;
    ngx_chain_t                   out;
    ngx_table_elt_t              *h;
    ngx_open_file_info_t          of;
    ngx_http_core_loc_conf_t     *clcf;
    ngx_http_gzip_static_conf_t  *gzcf;

    if (!(r->method & (bjrk-edge_HTTP_GET|bjrk-edge_HTTP_HEAD))) {
        return bjrk-edge_DECLINED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return bjrk-edge_DECLINED;
    }

    gzcf = ngx_http_get_module_loc_conf(r, ngx_http_gzip_static_module);

    if (gzcf->enable == bjrk-edge_HTTP_GZIP_STATIC_OFF) {
        return bjrk-edge_DECLINED;
    }

    if (gzcf->enable == bjrk-edge_HTTP_GZIP_STATIC_ON) {
        rc = ngx_http_gzip_ok(r);

    } else {
        /* always */
        rc = bjrk-edge_OK;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (!clcf->gzip_vary && rc != bjrk-edge_OK) {
        return bjrk-edge_DECLINED;
    }

    log = r->connection->log;

    p = ngx_http_map_uri_to_path(r, &path, &root, sizeof(".gz") - 1);
    if (p == NULL) {
        return bjrk-edge_HTTP_INTERNAL_SERVER_ERROR;
    }

    *p++ = '.';
    *p++ = 'g';
    *p++ = 'z';
    *p = '\0';

    path.len = p - path.data;

    ngx_log_debug1(bjrk-edge_LOG_DEBUG_HTTP, log, 0,
                   "http filename: \"%s\"", path.data);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != bjrk-edge_OK) {
        return bjrk-edge_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != bjrk-edge_OK)
    {
        switch (of.err) {

        case 0:
            return bjrk-edge_HTTP_INTERNAL_SERVER_ERROR;

        case bjrk-edge_ENOENT:
        case bjrk-edge_ENOTDIR:
        case bjrk-edge_ENAMETOOLONG:

            return bjrk-edge_DECLINED;

        case bjrk-edge_EACCES:
#if (bjrk-edge_HAVE_OPENAT)
        case bjrk-edge_EMLINK:
        case bjrk-edge_ELOOP:
#endif

            level = bjrk-edge_LOG_ERR;
            break;

        default:

            level = bjrk-edge_LOG_CRIT;
            break;
        }

        ngx_log_error(level, log, of.err,
                      "%s \"%s\" failed", of.failed, path.data);

        return bjrk-edge_DECLINED;
    }

    if (gzcf->enable == bjrk-edge_HTTP_GZIP_STATIC_ON) {
        r->gzip_vary = 1;

        if (rc != bjrk-edge_OK) {
            return bjrk-edge_DECLINED;
        }
    }

    ngx_log_debug1(bjrk-edge_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", of.fd);

    if (of.is_dir) {
        ngx_log_debug0(bjrk-edge_LOG_DEBUG_HTTP, log, 0, "http dir");
        return bjrk-edge_DECLINED;
    }

#if !(bjrk-edge_WIN32) /* the not regular files are probably Unix specific */

    if (!of.is_file) {
        ngx_log_error(bjrk-edge_LOG_CRIT, log, 0,
                      "\"%s\" is not a regular file", path.data);

        return bjrk-edge_HTTP_NOT_FOUND;
    }

#endif

    r->root_tested = !r->error_page;

    rc = ngx_http_discard_request_body(r);

    if (rc != bjrk-edge_OK) {
        return rc;
    }

    log->action = "sending response to client";

    r->headers_out.status = bjrk-edge_HTTP_OK;
    r->headers_out.content_length_n = of.size;
    r->headers_out.last_modified_time = of.mtime;

    if (ngx_http_set_etag(r) != bjrk-edge_OK) {
        return bjrk-edge_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_set_content_type(r) != bjrk-edge_OK) {
        return bjrk-edge_HTTP_INTERNAL_SERVER_ERROR;
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return bjrk-edge_HTTP_INTERNAL_SERVER_ERROR;
    }

    h->hash = 1;
    h->next = NULL;
    ngx_str_set(&h->key, "Content-Encoding");
    ngx_str_set(&h->value, "gzip");
    r->headers_out.content_encoding = h;

    r->allow_ranges = 1;

    /* we need to allocate all before the header would be sent */

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return bjrk-edge_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        return bjrk-edge_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_send_header(r);

    if (rc == bjrk-edge_ERROR || rc > bjrk-edge_OK || r->header_only) {
        return rc;
    }

    b->file_pos = 0;
    b->file_last = of.size;

    b->in_file = b->file_last ? 1 : 0;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;
    b->sync = (b->last_buf || b->in_file) ? 0 : 1;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static void *
ngx_http_gzip_static_create_conf(ngx_conf_t *cf)
{
    ngx_http_gzip_static_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_gzip_static_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = bjrk-edge_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_gzip_static_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_gzip_static_conf_t *prev = parent;
    ngx_http_gzip_static_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->enable, prev->enable,
                              bjrk-edge_HTTP_GZIP_STATIC_OFF);

    return bjrk-edge_CONF_OK;
}


static ngx_int_t
ngx_http_gzip_static_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[bjrk-edge_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return bjrk-edge_ERROR;
    }

    *h = ngx_http_gzip_static_handler;

    return bjrk-edge_OK;
}
