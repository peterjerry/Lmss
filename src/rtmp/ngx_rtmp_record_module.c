
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_netcall_module.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_rtmp_record_module.h"


ngx_rtmp_record_done_pt             ngx_rtmp_record_done;


static ngx_rtmp_publish_pt          next_publish;
static ngx_rtmp_close_stream_pt     next_close_stream;
static ngx_rtmp_stream_begin_pt     next_stream_begin;
static ngx_rtmp_stream_eof_pt       next_stream_eof;


static char *ngx_rtmp_record_recorder(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static ngx_int_t ngx_rtmp_record_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_record_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_record_merge_app_conf(ngx_conf_t *cf,
       void *parent, void *child);
static ngx_int_t ngx_rtmp_record_write_frame(ngx_rtmp_session_t *s,
       ngx_rtmp_record_rec_ctx_t *rctx,
       ngx_rtmp_header_t *h, ngx_chain_t *in, ngx_int_t inc_nframes);
static ngx_int_t ngx_rtmp_record_av(ngx_rtmp_session_t *s,
       ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_record_node_av(ngx_rtmp_session_t *s,
       ngx_rtmp_record_rec_ctx_t *rctx, ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_record_node_open(ngx_rtmp_session_t *s,
       ngx_rtmp_record_rec_ctx_t *rctx, ngx_rtmp_record_ctx_t  *ctx);
static ngx_int_t ngx_rtmp_record_node_close(ngx_rtmp_session_t *s,
       ngx_rtmp_record_rec_ctx_t *rctx);
static void  ngx_rtmp_record_make_path(ngx_rtmp_session_t *s,
       ngx_rtmp_record_rec_ctx_t *rctx, ngx_rtmp_record_ctx_t *ctx, ngx_str_t *path);
static ngx_int_t ngx_rtmp_record_init(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_record_create_fulldir(ngx_rtmp_session_t *s, ngx_rtmp_record_rec_ctx_t  *rctx);
static ngx_int_t ngx_rtmp_record_init_indexfile(ngx_rtmp_session_t *s, ngx_rtmp_record_ctx_t *ctx,
	   ngx_rtmp_record_rec_ctx_t *rctx);
static ngx_int_t ngx_rtmp_record_write_indexfile(ngx_rtmp_session_t *s, ngx_rtmp_record_ctx_t *ctx,
	   ngx_rtmp_record_rec_ctx_t *rctx, u_char *index, ngx_uint_t is_over);

static ngx_conf_bitmask_t  ngx_rtmp_record_mask[] = {
    { ngx_string("off"),                NGX_RTMP_RECORD_OFF         },
    { ngx_string("all"),                NGX_RTMP_RECORD_AUDIO       |
                                        NGX_RTMP_RECORD_VIDEO       },
    { ngx_string("audio"),              NGX_RTMP_RECORD_AUDIO       },
    { ngx_string("video"),              NGX_RTMP_RECORD_VIDEO       },
    { ngx_string("keyframes"),          NGX_RTMP_RECORD_KEYFRAMES   },
    { ngx_string("manual"),             NGX_RTMP_RECORD_MANUAL      },
    { ngx_null_string,                  0                           }
};


static ngx_command_t  ngx_rtmp_record_commands[] = {

    { ngx_string("record"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, flags),
      ngx_rtmp_record_mask },

    { ngx_string("record_path"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, path),
      NULL },

    { ngx_string("record_suffix"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, suffix),
      NULL },

    { ngx_string("record_unique"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, unique),
      NULL },

    { ngx_string("record_append"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, append),
      NULL },

    { ngx_string("record_lock"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, lock_file),
      NULL },

    { ngx_string("record_max_size"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, max_size),
      NULL },

    { ngx_string("record_max_frames"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, max_frames),
      NULL },

    { ngx_string("record_interval"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, interval),
      NULL },

    { ngx_string("record_usr_id"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, usr_id),
      NULL },

    { ngx_string("record_is_public"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, is_public),
      NULL },

    { ngx_string("record_vod_id"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, vdoid),
      NULL },

    { ngx_string("record_bucket"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, bucket),
      NULL },
      
	{ ngx_string("record_notify_url"),
	  NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
					     NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, notify_url),
	  NULL },
      
    { ngx_string("record_notify"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|
                         NGX_RTMP_REC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_record_app_conf_t, notify),
      NULL },

    { ngx_string("recorder"),
      NGX_RTMP_APP_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_rtmp_record_recorder,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },


      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_record_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_record_postconfiguration,      /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_record_create_app_conf,        /* create app configuration */
    ngx_rtmp_record_merge_app_conf          /* merge app configuration */
};


ngx_module_t  ngx_rtmp_record_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_record_module_ctx,            /* module context */
    ngx_rtmp_record_commands,               /* module directives */
    NGX_RTMP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_rtmp_record_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_record_app_conf_t      *racf;

    racf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_record_app_conf_t));

    if (racf == NULL) {
        return NULL;
    }

    racf->max_size = NGX_CONF_UNSET_SIZE;
    racf->max_frames = NGX_CONF_UNSET_SIZE;
    racf->vdoid = NGX_CONF_UNSET_SIZE;
    racf->interval = NGX_CONF_UNSET_MSEC;
    racf->unique = NGX_CONF_UNSET;
    racf->append = NGX_CONF_UNSET;
    racf->lock_file = NGX_CONF_UNSET;
    racf->notify = NGX_CONF_UNSET;
    racf->url = NGX_CONF_UNSET_PTR;
	
    if (ngx_array_init(&racf->rec, cf->pool, 1, sizeof(void *)) != NGX_OK) {
        return NULL;
    }

    return racf;
}


static char *
ngx_rtmp_record_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_record_app_conf_t     *prev = parent;
    ngx_rtmp_record_app_conf_t     *conf = child;
    ngx_rtmp_record_app_conf_t    **rracf;

    ngx_conf_merge_str_value(conf->path, prev->path, "");
    ngx_conf_merge_str_value(conf->suffix, prev->suffix, ".flv");
    ngx_conf_merge_size_value(conf->max_size, prev->max_size, 0);
    ngx_conf_merge_size_value(conf->max_frames, prev->max_frames, 0);
    ngx_conf_merge_value(conf->unique, prev->unique, 0);
    ngx_conf_merge_value(conf->append, prev->append, 0);
    ngx_conf_merge_value(conf->lock_file, prev->lock_file, 0);
    ngx_conf_merge_value(conf->notify, prev->notify, 0);
    ngx_conf_merge_msec_value(conf->interval, prev->interval,
                              (ngx_msec_t) NGX_CONF_UNSET);
	
    ngx_conf_merge_str_value(conf->usr_id, prev->usr_id, "");
    ngx_conf_merge_str_value(conf->is_public, prev->is_public, "");
    ngx_conf_merge_str_value(conf->bucket, prev->bucket, "");
    ngx_conf_merge_str_value(conf->notify_url, prev->notify_url, "");
    ngx_conf_merge_size_value(conf->vdoid, prev->vdoid, 0);
	
    ngx_conf_merge_bitmask_value(conf->flags, prev->flags, 0);
    ngx_conf_merge_ptr_value(conf->url, prev->url, NULL);

    if (conf->flags) {
        rracf = ngx_array_push(&conf->rec);
        if (rracf == NULL) {
            return NGX_CONF_ERROR;
        }

        *rracf = conf;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_record_write_header(ngx_file_t *file)
{
    static u_char       flv_header[] = {
        0x46, /* 'F' */
        0x4c, /* 'L' */
        0x56, /* 'V' */
        0x01, /* version = 1 */
        0x05, /* 00000 1 0 1 = has audio & video */
        0x00,
        0x00,
        0x00,
        0x09, /* header size */
        0x00,
        0x00,
        0x00,
        0x00  /* PreviousTagSize0 (not actually a header) */
    };

    return ngx_write_file(file, flv_header, sizeof(flv_header), 0) == NGX_ERROR
           ? NGX_ERROR
           : NGX_OK;
}


static ngx_rtmp_record_rec_ctx_t *
ngx_rtmp_record_get_node_ctx(ngx_rtmp_session_t *s, ngx_uint_t n)
{
    ngx_rtmp_record_ctx_t          *ctx;
    ngx_rtmp_record_rec_ctx_t      *rctx;

    if (ngx_rtmp_record_init(s) != NGX_OK) {
        return NULL;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    if (n >= ctx->rec.nelts) {
        return NULL;
    }

    rctx = ctx->rec.elts;

    return &rctx[n];
}


ngx_int_t
ngx_rtmp_record_open(ngx_rtmp_session_t *s, ngx_uint_t n, ngx_str_t *path)
{
    ngx_rtmp_record_rec_ctx_t      *rctx;
    ngx_int_t                       rc;
    ngx_rtmp_record_ctx_t           *ctx;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: #%ui manual open", n);

    rctx = ngx_rtmp_record_get_node_ctx(s, n);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);
	
    if (rctx == NULL || ctx == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_rtmp_record_node_open(s, rctx, ctx);
    if (rc != NGX_OK) {
        return rc;
    }
	

    if (path) {
        ngx_rtmp_record_make_path(s, rctx, ctx, path);
    }

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_record_close(ngx_rtmp_session_t *s, ngx_uint_t n, ngx_str_t *path)
{
    ngx_rtmp_record_rec_ctx_t      *rctx;
    ngx_int_t                       rc;
	ngx_rtmp_record_ctx_t          *ctx;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: #%ui manual close", n);

    rctx = ngx_rtmp_record_get_node_ctx(s, n);
	ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    if (rctx == NULL || ctx ==  NULL) {
        return NGX_ERROR;
    }

    rc = ngx_rtmp_record_node_close(s, rctx);
    if (rc != NGX_OK) {
        return rc;
    }

    if (path) {
        ngx_rtmp_record_make_path(s, rctx, ctx, path);
    }

    return NGX_OK;
}


ngx_uint_t
ngx_rtmp_record_find(ngx_rtmp_record_app_conf_t *racf, ngx_str_t *id)
{
    ngx_rtmp_record_app_conf_t    **pracf, *rracf;
    ngx_uint_t                      n;

    pracf = racf->rec.elts;

    for (n = 0; n < racf->rec.nelts; ++n, ++pracf) {
        rracf = *pracf;

        if (rracf->id.len == id->len &&
            ngx_strncmp(rracf->id.data, id->data, id->len) == 0)
        {
            return n;
        }
    }

    return NGX_CONF_UNSET_UINT;
}


/* This funcion returns pointer to a static buffer */
static void
ngx_rtmp_record_make_path(ngx_rtmp_session_t *s,
                          ngx_rtmp_record_rec_ctx_t *rctx, ngx_rtmp_record_ctx_t *ctx, ngx_str_t *path)
{
    //ngx_rtmp_record_ctx_t          *ctx;
    ngx_rtmp_record_app_conf_t     *rracf;
    u_char                         *p, *l;
    struct tm                       tm;

    static u_char                   buf[NGX_TIME_T_LEN + 1];
    static u_char                   pbuf[NGX_MAX_PATH + 1];

    rracf = rctx->conf;

    /* create file path */
    p = pbuf;
    l = pbuf + sizeof(pbuf) - 1;

    p = ngx_cpymem(p, rctx->abs_path,
    			ngx_min(ngx_strlen(rctx->abs_path), (size_t)(l - p - 1)));
	
    p = (u_char *)ngx_escape_uri(p, ctx->name, ngx_min(ngx_strlen(ctx->name),
                (size_t)(l - p)), NGX_ESCAPE_URI_COMPONENT);

    /* append timestamp */
    if (rracf->unique) {
        p = ngx_cpymem(p, buf, ngx_min(ngx_sprintf(buf, "-%T",
                       rctx->timestamp) - buf, l - p));
    }

    if (ngx_strchr(rracf->suffix.data, '%')) {
        ngx_libc_localtime(rctx->timestamp, &tm);
        p += strftime((char *) p, l - p, (char *) rracf->suffix.data, &tm);
    } else {
        p = ngx_cpymem(p, rracf->suffix.data,
                ngx_min(rracf->suffix.len, (size_t)(l - p)));
    }

    *p = 0;
    path->data = pbuf;
    path->len  = p - pbuf;

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: %V path: '%V'", &rracf->id, path);
}


static void
ngx_rtmp_record_notify_error(ngx_rtmp_session_t *s,
                             ngx_rtmp_record_rec_ctx_t *rctx)
{
    ngx_rtmp_record_app_conf_t *rracf = rctx->conf;

    rctx->failed = 1;

    if (!rracf->notify) {
        return;
    }

    ngx_rtmp_send_status(s, "NetStream.Record.Failed", "error",
                         rracf->id.data ? (char *) rracf->id.data : "");
}


static ngx_int_t
ngx_rtmp_record_node_open(ngx_rtmp_session_t *s,
                          ngx_rtmp_record_rec_ctx_t *rctx, ngx_rtmp_record_ctx_t *ctx)
{
    ngx_rtmp_record_app_conf_t *rracf;
    ngx_err_t                   err;
    ngx_str_t                   path;
    ngx_int_t                   mode, create_mode;
    u_char                      buf[8], *p;
    off_t                       file_size;
    uint32_t                    tag_size, mlen, timestamp;
    u_char                      *abs_path, *publish_time;

    rracf = rctx->conf;
	abs_path = rctx->abs_path;
	publish_time = rctx->publish_time;
    tag_size = 0;

    if (rctx->file.fd != NGX_INVALID_FILE) {
        return NGX_AGAIN;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: %V opening", &rracf->id);

    ngx_memzero(rctx, sizeof(*rctx));
    rctx->conf = rracf;
	rctx->abs_path = abs_path;
    rctx->publish_time = publish_time;
	
    rctx->last = *ngx_cached_time;
    rctx->timestamp = ngx_cached_time->sec;

    ngx_rtmp_record_make_path(s, rctx, ctx, &path);

    mode = rracf->append ? NGX_FILE_RDWR : NGX_FILE_WRONLY;
    create_mode = rracf->append ? NGX_FILE_CREATE_OR_OPEN : NGX_FILE_TRUNCATE;

    ngx_memzero(&rctx->file, sizeof(rctx->file));
    rctx->file.offset = 0;
    rctx->file.log = s->connection->log;
    rctx->file.fd = ngx_open_file(path.data, mode, create_mode,
                                  NGX_FILE_DEFAULT_ACCESS);
    ngx_str_set(&rctx->file.name, "recorded");

    if (rctx->file.fd == NGX_INVALID_FILE) {
		
        err = ngx_errno;
        if (err != NGX_ENOENT) {
            ngx_log_error(NGX_LOG_CRIT, s->connection->log, err,
                          "record: %V failed to open file '%V'",
                          &rracf->id, &path);
        }

        ngx_rtmp_record_notify_error(s, rctx);

        return NGX_OK;
    }

#if !(NGX_WIN32)
    if (rracf->lock_file) {
        err = ngx_lock_fd(rctx->file.fd);
        if (err) {
            ngx_log_error(NGX_LOG_CRIT, s->connection->log, err,
                          "record: %V lock failed", &rracf->id);
        }
    }
#endif

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: %V opened '%V'", &rracf->id, &path);

    if (rracf->notify) {
        ngx_rtmp_send_status(s, "NetStream.Record.Start", "status",
                             rracf->id.data ? (char *) rracf->id.data : "");
    }

    if (rracf->append) {

        file_size = 0;
        timestamp = 0;

#if (NGX_WIN32)
        {
            LONG  lo, hi;

            lo = 0;
            hi = 0;
            lo = SetFilePointer(rctx->file.fd, lo, &hi, FILE_END);
            file_size = (lo == INVALID_SET_FILE_POINTER ?
                         (off_t) -1 : (off_t) hi << 32 | (off_t) lo);
        }
#else
        file_size = lseek(rctx->file.fd, 0, SEEK_END);
#endif
        if (file_size == (off_t) -1) {
            ngx_log_error(NGX_LOG_CRIT, s->connection->log, ngx_errno,
                          "record: %V seek failed", &rracf->id);
            goto done;
        }

        if (file_size < 4) {
            goto done;
        }

        if (ngx_read_file(&rctx->file, buf, 4, file_size - 4) != 4) {
            ngx_log_error(NGX_LOG_CRIT, s->connection->log, ngx_errno,
                          "record: %V tag size read failed", &rracf->id);
            goto done;
        }

        p = (u_char *) &tag_size;
        p[0] = buf[3];
        p[1] = buf[2];
        p[2] = buf[1];
        p[3] = buf[0];

        if (tag_size == 0 || tag_size + 4 > file_size) {
            file_size = 0;
            goto done;
        }

        if (ngx_read_file(&rctx->file, buf, 8, file_size - tag_size - 4) != 8)
        {
            ngx_log_error(NGX_LOG_CRIT, s->connection->log, ngx_errno,
                          "record: %V tag read failed", &rracf->id);
            goto done;
        }

        p = (u_char *) &mlen;
        p[0] = buf[3];
        p[1] = buf[2];
        p[2] = buf[1];
        p[3] = 0;

        if (tag_size != mlen + 11) {
            ngx_log_error(NGX_LOG_CRIT, s->connection->log, ngx_errno,
                          "record: %V tag size mismatch: "
                          "tag_size=%uD, mlen=%uD", &rracf->id, tag_size, mlen);
            goto done;
        }

        p = (u_char *) &timestamp;
        p[3] = buf[7];
        p[0] = buf[6];
        p[1] = buf[5];
        p[2] = buf[4];

done:
        rctx->file.offset = file_size;
        rctx->time_shift = timestamp;

        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "record: append offset=%O, time=%uD, tag_size=%uD",
                       file_size, timestamp, tag_size);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_record_init(ngx_rtmp_session_t *s)
{
    ngx_rtmp_record_app_conf_t     *racf, **rracf;
    ngx_rtmp_record_rec_ctx_t      *rctx;
    ngx_rtmp_record_ctx_t          *ctx;
    ngx_uint_t                      n;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    if (ctx) {
        return NGX_OK;
    }

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);

    if (racf == NULL || racf->rec.nelts == 0) {
        return NGX_OK;
    }

    ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_record_ctx_t));

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_record_module);

    if (ngx_array_init(&ctx->rec, s->connection->pool, racf->rec.nelts,
                       sizeof(ngx_rtmp_record_rec_ctx_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    rracf = racf->rec.elts;

    rctx = ngx_array_push_n(&ctx->rec, racf->rec.nelts);

    if (rctx == NULL) {
        return NGX_ERROR;
    }

    for (n = 0; n < racf->rec.nelts; ++n, ++rracf, ++rctx) {
		
        ngx_memzero(rctx, sizeof(*rctx));
        rctx->conf = *rracf;
        rctx->abs_path = ngx_palloc(s->connection->pool, 1024);
        rctx->publish_time = ngx_palloc(s->connection->pool, 256);
        rctx->file.fd = NGX_INVALID_FILE;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_record_create_fulldir(ngx_rtmp_session_t *s, ngx_rtmp_record_rec_ctx_t  *rctx)
{

	//ngx_rtmp_record_app_conf_t	   *racf;
	u_char                         *p;
	ngx_file_info_t				   fi;

	ngx_memzero(rctx->abs_path, 1024);
	ngx_memzero(rctx->publish_time, 256);
	
	ngx_sprintf(rctx->publish_time, "%T", ngx_cached_time->sec);

	if (rctx->conf->path.data[rctx->conf->path.len - 1] != '/') {

		p = ngx_snprintf(rctx->abs_path, NGX_MAX_PATH, "%V/", &rctx->conf->path);
	} else {

		p = ngx_snprintf(rctx->abs_path, NGX_MAX_PATH, "%V", &rctx->conf->path);
	}

    p = ngx_cpymem(p, s->host_in.data, s->host_in.len);
    *p++ = '/';

    p = ngx_cpymem(p, s->app.data, s->app.len);
    *p++ = '/';
	
    p = ngx_cpymem(p, s->name, ngx_strlen(s->name));
    *p++ = '/';
	
    p = ngx_cpymem(p, rctx->publish_time, ngx_strlen(rctx->publish_time));
    *p++ = '/';

    if (ngx_file_info(rctx->abs_path, &fi) == NGX_FILE_ERROR) {

        if (ngx_errno != NGX_ENOENT) {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, ngx_errno,
                          "record_create_indexfile: " ngx_file_info_n " failed on '%s'",
                          rctx->abs_path);
            return NGX_ERROR;
        }

        /* ENOENT */

        if (ngx_create_full_path(rctx->abs_path, 0777) == NGX_FILE_ERROR) {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, ngx_errno,
                          "record_create_indexfile: " ngx_create_dir_n " failed on '%s'",
                          rctx->abs_path);
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "record_create_indexfile: directory '%s' created", rctx->abs_path);

    } else {

        if (!ngx_is_dir(&fi)) {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                          "hls: '%s' exists and is not a directory",
                          rctx->abs_path);
            return  NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "record_create_indexfile: directory '%s' exists", rctx->abs_path);
    }	
	
	return NGX_OK;
}

static ngx_int_t
ngx_rtmp_record_init_indexfile(ngx_rtmp_session_t *s, ngx_rtmp_record_ctx_t *ctx,
  	ngx_rtmp_record_rec_ctx_t  *rctx)
{
	u_char                         path[1024], *p;
    static u_char                  buffer[1024];
	ngx_int_t                      n;
	ngx_uint_t                     is_picture;
        
	ngx_memzero(path, 1024);
    ngx_str_set(&rctx->file_index.name, "index.txt");
    p = ngx_snprintf(path, 1024, "%s", rctx->abs_path);
    p = ngx_snprintf(p, 1024, "index.txt");

    ngx_memzero(&rctx->file_index, sizeof(rctx->file_index));
    rctx->file_index.log = s->connection->log;
    rctx->file_index.fd = ngx_open_file(path, NGX_FILE_WRONLY,
                             NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (rctx->file_index.fd == NGX_INVALID_FILE) {
    	ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                  "init_indexfile: error creating index file");
    	return NGX_ERROR;
	}

	if((rctx->conf->flags & NGX_RTMP_RECORD_VIDEO) && 
		(rctx->conf->flags & NGX_RTMP_RECORD_KEYFRAMES)) {

		is_picture = 1;
	} else {
	
		is_picture = 0;
	}
	
    if (ngx_strlen(s->vdoid) > 0) {
    	p = ngx_snprintf(buffer, sizeof(buffer),
                 "usr_id %V\r\n"
                 "vdoid %s\r\n"
                 "is_public %V\r\n"
                 "bucket %V\r\n"
                 "notify_url %V\r\n"
                 "interval %ui\r\n"
                 "is_picture %ui"
                 "\r\n"
	             "\r\n", 
	    &rctx->conf->usr_id, s->vdoid, &rctx->conf->is_public, 
	    	&rctx->conf->bucket, &rctx->conf->notify_url, rctx->conf->interval/1000, is_picture);
    }else {
    	p = ngx_snprintf(buffer, sizeof(buffer),
                 "usr_id %V\r\n"
                 "is_public %V\r\n"
                 "bucket %V\r\n"
                 "notify_url %V\r\n"
                 "interval %ui\r\n"
                 "is_picture %ui"
                 "\r\n"
	         	 "\r\n", 
	    &rctx->conf->usr_id, &rctx->conf->is_public,
	    	&rctx->conf->bucket, &rctx->conf->notify_url, rctx->conf->interval/1000, is_picture);
    }

 	n = ngx_write_fd(rctx->file_index.fd, buffer, p - buffer);
	if (n < 0) {
    	ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                  "init_indexfile: " ngx_write_fd_n " failed: '%V'",
                  path);
    	ngx_close_file(rctx->file_index.fd);
    	return NGX_ERROR;
	}

    ngx_close_file(rctx->file_index.fd);
	
	return NGX_OK;
}

static ngx_int_t
ngx_rtmp_record_write_indexfile(ngx_rtmp_session_t *s, ngx_rtmp_record_ctx_t *ctx,
	ngx_rtmp_record_rec_ctx_t *rctx, u_char *index, ngx_uint_t is_over)
{

    ngx_int_t	    	mode, create_mode;
    u_char          	path[NGX_MAX_PATH], *p;
    size_t          	file_size;
    ngx_file_info_t     fi;
    static char         *p_over = "\r\n";

	ngx_memzero(path, NGX_MAX_PATH);	
    mode = NGX_FILE_WRONLY;
    create_mode = NGX_FILE_APPEND;

	p = ngx_snprintf(path, NGX_MAX_PATH, "%sindex.txt", rctx->abs_path);
    ngx_memzero(&rctx->file_index, sizeof(rctx->file_index));
    ngx_str_set(&rctx->file_index.name, "index.txt");
    rctx->file_index.offset = 0;
    rctx->file_index.log = s->connection->log;
    rctx->file_index.fd = ngx_open_file(path, mode, create_mode,
                              NGX_FILE_DEFAULT_ACCESS);

	if (rctx->file_index.fd == NGX_INVALID_FILE) {

		return NGX_ERROR;
	}
	if (ngx_link_info((char *)path, &fi) == NGX_FILE_ERROR) {

		return NGX_ERROR;
	}
	
	file_size = ngx_file_size(&fi);
	rctx->file_index.offset = file_size;

	if (is_over == 0) {
		if (ngx_write_file(&rctx->file_index, index, ngx_strlen(index), rctx->file_index.offset) == NGX_ERROR) {

			return NGX_ERROR;
		}
	} else {

		if (ngx_write_file(&rctx->file_index, (u_char *)p_over, ngx_strlen(p_over), rctx->file_index.offset) == NGX_ERROR) {

			return NGX_ERROR;
		}
	}
	
	ngx_close_file(rctx->file_index.fd);
	
	return NGX_OK;
}

static void
ngx_rtmp_record_start(ngx_rtmp_session_t *s)
{
    ngx_rtmp_record_app_conf_t     *racf;
    ngx_rtmp_record_rec_ctx_t      *rctx;
    ngx_rtmp_record_ctx_t          *ctx;
    ngx_uint_t                      n;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);
    if (racf == NULL || racf->rec.nelts == 0) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);
    if (ctx == NULL) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: start");

    rctx = ctx->rec.elts;
    for (n = 0; n < ctx->rec.nelts; ++n, ++rctx) {
        if (rctx->conf->flags & (NGX_RTMP_RECORD_OFF|NGX_RTMP_RECORD_MANUAL)) {
            continue;
        }
        ngx_rtmp_record_create_fulldir(s, rctx);
        ngx_rtmp_record_node_open(s, rctx, ctx);
        ngx_rtmp_record_init_indexfile(s, ctx, rctx);
    }
}


static void
ngx_rtmp_record_stop(ngx_rtmp_session_t *s)
{
    ngx_rtmp_record_app_conf_t     *racf;
    ngx_rtmp_record_rec_ctx_t      *rctx;
    ngx_rtmp_record_ctx_t          *ctx;
    ngx_uint_t                      n;

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);
    if (racf == NULL || racf->rec.nelts == 0) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);
    if (ctx == NULL) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: stop");

    rctx = ctx->rec.elts;
    for (n = 0; n < ctx->rec.nelts; ++n, ++rctx) {
        ngx_rtmp_record_node_close(s, rctx);
    }
}


static ngx_int_t
ngx_rtmp_record_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_record_app_conf_t     *racf;
    ngx_rtmp_record_ctx_t          *ctx;
    u_char                         *p;

    if (s->relay_type != NGX_NONE_RELAY) {
        goto next;
    }

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_record_module);

    if (racf == NULL || racf->rec.nelts == 0) {
        goto next;
    }

    if (ngx_rtmp_record_init(s) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: publish %ui nodes",
                   racf->rec.nelts);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    ngx_memcpy(ctx->name, v->name, sizeof(ctx->name));
    ngx_memcpy(ctx->args, v->args, sizeof(ctx->args));

    /* terminate name on /../ */
    for (p = ctx->name; *p; ++p) {
        if (ngx_path_separator(p[0]) &&
            p[1] == '.' && p[2] == '.' &&
            ngx_path_separator(p[3]))
        {
            *p = 0;
            break;
        }
    }

    ngx_rtmp_record_start(s);

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_record_stream_begin(ngx_rtmp_session_t *s, ngx_rtmp_stream_begin_t *v)
{
    if (s->relay_type != NGX_NONE_RELAY) {
        goto next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: stream_begin");

    ngx_rtmp_record_start(s);

next:
    return next_stream_begin(s, v);
}


static ngx_int_t
ngx_rtmp_record_stream_eof(ngx_rtmp_session_t *s, ngx_rtmp_stream_begin_t *v)
{
    if (s->relay_type != NGX_NONE_RELAY) {
        goto next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: stream_eof");

    ngx_rtmp_record_stop(s);

next:
    return next_stream_eof(s, v);
}


static ngx_int_t
ngx_rtmp_record_node_close(ngx_rtmp_session_t *s,
                           ngx_rtmp_record_rec_ctx_t *rctx)
{
    ngx_rtmp_record_app_conf_t  *rracf;
    ngx_err_t                   err;
    void                        **app_conf;
    ngx_int_t                   rc;
    ngx_rtmp_record_done_t      v;
    u_char                      av, *p, *p1;
    ngx_rtmp_record_ctx_t       *ctx;
	u_char                      index_path[NGX_MAX_PATH];
	
    rracf = rctx->conf;
	ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);
	if (ctx == NULL) {

	}
	
    if (rctx->file.fd == NGX_INVALID_FILE) {
        return NGX_AGAIN;
    }

    if (rctx->initialized) {
        av = 0;

        if (rctx->video) {
            av |= 0x01;
        }

        if (rctx->audio) {
            av |= 0x04;
        }

        if (ngx_write_file(&rctx->file, &av, 1, 4) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, s->connection->log, ngx_errno,
                          "record: %V error writing av mask", &rracf->id);
        }
    }

    if (ngx_close_file(rctx->file.fd) == NGX_FILE_ERROR) {
        err = ngx_errno;
        ngx_log_error(NGX_LOG_CRIT, s->connection->log, err,
                      "record: %V error closing file", &rracf->id);

        ngx_rtmp_record_notify_error(s, rctx);
    }

    rctx->file.fd = NGX_INVALID_FILE;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: %V closed", &rracf->id);

    if (rracf->notify) {
        ngx_rtmp_send_status(s, "NetStream.Record.Stop", "status",
                             rracf->id.data ? (char *) rracf->id.data : "");
    }

    app_conf = s->app_conf;

    if (rracf->rec_conf) {
        s->app_conf = rracf->rec_conf;
    }

    v.recorder = rracf->id;
    ngx_rtmp_record_make_path(s, rctx, ctx, &v.path);

    ngx_memzero(index_path, NGX_MAX_PATH);
    p1 = v.path.data + ngx_strlen(rctx->abs_path);
    
    p = ngx_cpymem(index_path, p1, v.path.len - ngx_strlen(rctx->abs_path));
    p = ngx_cpymem(p, "\r\n", ngx_strlen("\r\n"));
    ngx_rtmp_record_write_indexfile(s, ctx, rctx, index_path, 0);

    rc = ngx_rtmp_record_done(s, &v);

    s->app_conf = app_conf;

    return rc;
}


static ngx_int_t
ngx_rtmp_record_close_stream(ngx_rtmp_session_t *s,
                             ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_record_rec_ctx_t      *rctx;
    ngx_rtmp_record_ctx_t          *ctx;
    ngx_uint_t                      n;
	

    if (s->relay_type != NGX_NONE_RELAY) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: close_stream");

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                   "record: close_stream");

    ngx_rtmp_record_stop(s);
	
    rctx = ctx->rec.elts;
    for (n = 0; n < ctx->rec.nelts; ++n, ++rctx) {

    	ngx_rtmp_record_write_indexfile(s, ctx, rctx, NULL, 1);
    }
	
next:
    return next_close_stream(s, v);
}


static ngx_int_t
ngx_rtmp_record_write_frame(ngx_rtmp_session_t *s,
                            ngx_rtmp_record_rec_ctx_t *rctx,
                            ngx_rtmp_header_t *h, ngx_chain_t *in,
                            ngx_int_t inc_nframes)
{
    u_char                      hdr[11], *p, *ph;
    uint32_t                    timestamp, tag_size;
    ngx_rtmp_record_app_conf_t *rracf;

    rracf = rctx->conf;

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "record: %V frame: mlen=%uD",
                   &rracf->id, h->mlen);

    if (h->type == NGX_RTMP_MSG_VIDEO) {
        rctx->video = 1;
    } else {
        rctx->audio = 1;
    }

    timestamp = h->timestamp - rctx->epoch;

    if ((int32_t) timestamp < 0) {
        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "record: %V cut timestamp=%D", &rracf->id, timestamp);

        timestamp = 0;
    }

    /* write tag header */
    ph = hdr;

    *ph++ = (u_char)h->type;

    p = (u_char*)&h->mlen;
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];

    p = (u_char*)&timestamp;
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];
    *ph++ = p[3];

    *ph++ = 0;
    *ph++ = 0;
    *ph++ = 0;

    tag_size = (ph - hdr) + h->mlen;

    if (ngx_write_file(&rctx->file, hdr, ph - hdr, rctx->file.offset)
        == NGX_ERROR)
    {
        ngx_rtmp_record_notify_error(s, rctx);

        ngx_close_file(rctx->file.fd);

        return NGX_ERROR;
    }

    /* write tag body
     * FIXME: NGINX
     * ngx_write_chain seems to fit best
     * but it suffers from uncontrollable
     * allocations.
     * we're left with plain writing */
    for(; in; in = in->next) {
        if (in->buf->pos == in->buf->last) {
            continue;
        }

        if (ngx_write_file(&rctx->file, in->buf->pos, in->buf->last
                           - in->buf->pos, rctx->file.offset)
            == NGX_ERROR)
        {
            return NGX_ERROR;
        }
    }

    /* write tag size */
    ph = hdr;
    p = (u_char*)&tag_size;

    *ph++ = p[3];
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];

    if (ngx_write_file(&rctx->file, hdr, ph - hdr,
                       rctx->file.offset)
        == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    rctx->nframes += inc_nframes;

    /* watch max size */
    if ((rracf->max_size && rctx->file.offset >= (ngx_int_t) rracf->max_size) ||
        (rracf->max_frames && rctx->nframes >= rracf->max_frames))
    {
        ngx_rtmp_record_node_close(s, rctx);
    }

    return NGX_OK;
}


static size_t
ngx_rtmp_record_get_chain_mlen(ngx_chain_t *in)
{
    size_t                          ret;

    for (ret = 0; in; in = in->next) {
        ret += (in->buf->last - in->buf->pos);
    }

    return ret;
}


static ngx_int_t
ngx_rtmp_record_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                   ngx_chain_t *in)
{
    ngx_rtmp_record_ctx_t          *ctx;
    ngx_rtmp_record_rec_ctx_t      *rctx;
    ngx_uint_t                      n;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    rctx = ctx->rec.elts;

    for (n = 0; n < ctx->rec.nelts; ++n, ++rctx) {
        ngx_rtmp_record_node_av(s, rctx, h, in);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_record_node_av(ngx_rtmp_session_t *s, ngx_rtmp_record_rec_ctx_t *rctx,
                        ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_time_t                      next;
    ngx_rtmp_header_t               ch;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_int_t                       keyframe, brkframe;
    ngx_rtmp_record_app_conf_t     *rracf;
    ngx_rtmp_record_ctx_t           *ctx;
    rracf = rctx->conf;


	ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);
	if (ctx == NULL) {

		return NGX_ERROR;
	}
	
    if (rracf->flags & NGX_RTMP_RECORD_OFF) {
        ngx_rtmp_record_node_close(s, rctx);
        return NGX_OK;
    }

    keyframe = (h->type == NGX_RTMP_MSG_VIDEO)
             ? (ngx_rtmp_get_video_frame_type(in) == NGX_RTMP_VIDEO_KEY_FRAME)
             : 0;

    brkframe = (h->type == NGX_RTMP_MSG_VIDEO)
             ? keyframe
             : (rracf->flags & NGX_RTMP_RECORD_VIDEO) == 0;

    if (brkframe && (rracf->flags & NGX_RTMP_RECORD_MANUAL) == 0) {

        if (rracf->interval != (ngx_msec_t) NGX_CONF_UNSET) {

            next = rctx->last;
            next.msec += rracf->interval;
            next.sec  += (next.msec / 1000);
            next.msec %= 1000;

            if (ngx_cached_time->sec  > next.sec ||
               (ngx_cached_time->sec == next.sec &&
                ngx_cached_time->msec > next.msec))
            {
                ngx_rtmp_record_node_close(s, rctx);
                ngx_rtmp_record_node_open(s, rctx, ctx);
            }

        } else if (!rctx->failed) {
            ngx_rtmp_record_node_open(s, rctx, ctx);
        }
    }

    if ((rracf->flags & NGX_RTMP_RECORD_MANUAL) &&
        !brkframe && rctx->nframes == 0)
    {
        return NGX_OK;
    }

    if (rctx->file.fd == NGX_INVALID_FILE) {
        return NGX_OK;
    }

    if (h->type == NGX_RTMP_MSG_AUDIO &&
       (rracf->flags & NGX_RTMP_RECORD_AUDIO) == 0)
    {
        return NGX_OK;
    }

    if (h->type == NGX_RTMP_MSG_VIDEO &&
       (rracf->flags & NGX_RTMP_RECORD_VIDEO) == 0 &&
       ((rracf->flags & NGX_RTMP_RECORD_KEYFRAMES) == 0 || !keyframe))
    {
        return NGX_OK;
    }

    if (!rctx->initialized) {

        rctx->initialized = 1;
        rctx->epoch = h->timestamp - rctx->time_shift;

        if (rctx->file.offset == 0 &&
            ngx_rtmp_record_write_header(&rctx->file) != NGX_OK)
        {
            ngx_rtmp_record_node_close(s, rctx);
            return NGX_OK;
        }
    }

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (codec_ctx) {
        ch = *h;

        /* AAC header */
        if (!rctx->aac_header_sent && codec_ctx->aac_header &&
           (rracf->flags & NGX_RTMP_RECORD_AUDIO))
        {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "record: %V writing AAC header", &rracf->id);

            ch.type = NGX_RTMP_MSG_AUDIO;
            ch.mlen = ngx_rtmp_record_get_chain_mlen(codec_ctx->aac_header);

            if (ngx_rtmp_record_write_frame(s, rctx, &ch,
                                            codec_ctx->aac_header, 0)
                != NGX_OK)
            {
                return NGX_OK;
            }

            rctx->aac_header_sent = 1;
        }

        /* AVC header */
        if (!rctx->avc_header_sent && codec_ctx->avc_header &&
           (rracf->flags & (NGX_RTMP_RECORD_VIDEO|
                            NGX_RTMP_RECORD_KEYFRAMES)))
        {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "record: %V writing AVC header", &rracf->id);

            ch.type = NGX_RTMP_MSG_VIDEO;
            ch.mlen = ngx_rtmp_record_get_chain_mlen(codec_ctx->avc_header);

            if (ngx_rtmp_record_write_frame(s, rctx, &ch,
                                            codec_ctx->avc_header, 0)
                != NGX_OK)
            {
                return NGX_OK;
            }

            rctx->avc_header_sent = 1;
        }
    }

    if (h->type == NGX_RTMP_MSG_VIDEO) {
        if (codec_ctx && codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H264 &&
            !rctx->avc_header_sent)
        {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "record: %V skipping until H264 header", &rracf->id);
            return NGX_OK;
        }

        if (ngx_rtmp_get_video_frame_type(in) == NGX_RTMP_VIDEO_KEY_FRAME &&
            ((codec_ctx && codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H264) ||
             !ngx_rtmp_is_codec_header(in)))
        {
            rctx->video_key_sent = 1;
        }

        if (!rctx->video_key_sent) {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "record: %V skipping until keyframe", &rracf->id);
            return NGX_OK;
        }

    } else {
        if (codec_ctx && codec_ctx->audio_codec_id == NGX_RTMP_AUDIO_AAC &&
            !rctx->aac_header_sent)
        {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "record: %V skipping until AAC header", &rracf->id);
            return NGX_OK;
        }
    }

    return ngx_rtmp_record_write_frame(s, rctx, h, in, 1);
}


static ngx_int_t
ngx_rtmp_record_done_init(ngx_rtmp_session_t *s, ngx_rtmp_record_done_t *v)
{
    return NGX_OK;
}


static char *
ngx_rtmp_record_recorder(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *rv;
    ngx_int_t                   i;
    ngx_str_t                  *value;
    ngx_conf_t                  save;
    ngx_rtmp_module_t          *module;
    ngx_rtmp_core_app_conf_t   *cacf, **pcacf, *rcacf;
    ngx_rtmp_record_app_conf_t *racf, **pracf, *rracf;
    ngx_rtmp_conf_ctx_t        *ctx, *pctx;

    value = cf->args->elts;

    cacf = ngx_rtmp_conf_get_module_app_conf(cf, ngx_rtmp_core_module);

    racf = ngx_rtmp_conf_get_module_app_conf(cf, ngx_rtmp_record_module);

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    pctx = cf->ctx;

    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf  = pctx->srv_conf;

    ctx->app_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (ctx->app_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_RTMP_MODULE) {
            continue;
        }

        module = ngx_modules[i]->ctx;

        if (module->create_app_conf) {
            ctx->app_conf[ngx_modules[i]->ctx_index] =
                                module->create_app_conf(cf);
            if (ctx->app_conf[ngx_modules[i]->ctx_index] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }

    /* add to sub-applications */
    rcacf = ctx->app_conf[ngx_rtmp_core_module.ctx_index];
    rcacf->app_conf = ctx->app_conf;
    pcacf = ngx_array_push(&cacf->applications);
    if (pcacf == NULL) {
        return NGX_CONF_ERROR;
    }
    *pcacf = rcacf;

    /* add to recorders */
    rracf = ctx->app_conf[ngx_rtmp_record_module.ctx_index];
    rracf->rec_conf = ctx->app_conf;
    pracf = ngx_array_push(&racf->rec);
    if (pracf == NULL) {
        return NGX_CONF_ERROR;
    }
    *pracf = rracf;

    rracf->id = value[1];


    save = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_RTMP_REC_CONF;

    rv = ngx_conf_parse(cf, NULL);
    *cf= save;

    return rv;
}


static ngx_int_t
ngx_rtmp_record_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;

    ngx_rtmp_record_done = ngx_rtmp_record_done_init;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_record_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_record_av;

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_record_publish;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_record_close_stream;

    next_stream_begin = ngx_rtmp_stream_begin;
    ngx_rtmp_stream_begin = ngx_rtmp_record_stream_begin;

    next_stream_eof = ngx_rtmp_stream_eof;
    ngx_rtmp_stream_eof = ngx_rtmp_record_stream_eof;

    return NGX_OK;
}
