
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_rtmp_notify_module.h"
#include "ngx_rtmp_bitop.h"

#define NGX_RTMP_LIVE_GOP_SIZE          100 /* gop cache */

static ngx_rtmp_connect_pt              next_connect;
static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_play_pt                 next_play;
static ngx_rtmp_delete_stream_pt        next_delete_stream;
static ngx_rtmp_close_stream_pt         next_close_stream;
static ngx_rtmp_pause_pt                next_pause;
static ngx_rtmp_stream_begin_pt         next_stream_begin;
static ngx_rtmp_stream_eof_pt           next_stream_eof;

extern ngx_uint_t ngx_rtmp_publishing;
extern ngx_uint_t ngx_rtmp_playing;

static ngx_int_t ngx_rtmp_live_postconfiguration(ngx_conf_t *cf);
static void *ngx_rtmp_live_create_main_conf(ngx_conf_t *cf);
static void *ngx_rtmp_live_create_app_conf(ngx_conf_t *cf);
static char *ngx_rtmp_live_merge_app_conf(ngx_conf_t *cf,
       void *parent, void *child);
static char *ngx_rtmp_live_set_msec_slot(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static void ngx_rtmp_live_start(ngx_rtmp_session_t *s);
static void ngx_rtmp_live_stop(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_live_connect(ngx_rtmp_session_t *s, ngx_rtmp_connect_t *v);
extern ngx_int_t ngx_rtmp_relay_relaying(ngx_rtmp_session_t *s, ngx_str_t *name);
extern ngx_int_t ngx_rtmp_relay_player_dry(ngx_rtmp_session_t *s, ngx_str_t *name);
extern ngx_int_t ngx_rtmp_relay_player_new(ngx_rtmp_session_t *s, ngx_str_t *name);


static ngx_command_t  ngx_rtmp_live_commands[] = {

    { ngx_string("live"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, live),
      NULL },

    { ngx_string("stream_buckets"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, nbuckets),
      NULL },

    { ngx_string("buffer"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, buflen),
      NULL },

    { ngx_string("sync"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_live_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, sync),
      NULL },

    { ngx_string("interleave"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, interleave),
      NULL },

    { ngx_string("gop_cache"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, gop_cache),
      NULL },

    { ngx_string("wait_key"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, wait_key),
      NULL },

    { ngx_string("wait_video"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, wait_video),
      NULL },

    { ngx_string("publish_notify"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, publish_notify),
      NULL },

    { ngx_string("play_restart"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, play_restart),
      NULL },

    { ngx_string("idle_streams"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, idle_streams),
      NULL },

    { ngx_string("idle_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_live_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, idle_timeout),
      NULL },

	{ ngx_string("check_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_live_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_conf_t, check_timeout),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_live_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_live_postconfiguration,        /* postconfiguration */
    ngx_rtmp_live_create_main_conf,         /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_live_create_app_conf,          /* create app configuration */
    ngx_rtmp_live_merge_app_conf            /* merge app configuration */
};


ngx_module_t  ngx_rtmp_live_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_live_module_ctx,              /* module context */
    ngx_rtmp_live_commands,                 /* module directives */
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
ngx_rtmp_live_create_main_conf(ngx_conf_t *cf)
{
    ngx_rtmp_live_main_conf_t      *lmcf;

    lmcf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_live_main_conf_t));
    if (lmcf == NULL) {
        return NULL;
    }

    ngx_rtmp_live_main_conf = lmcf;

    lmcf->pool = ngx_create_pool(4096, &cf->cycle->new_log);
    if (lmcf->pool == NULL) {
        return NGX_CONF_ERROR;
    }

    return lmcf;
}


static void *
ngx_rtmp_live_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_live_app_conf_t      *lacf;

    lacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_live_app_conf_t));
    if (lacf == NULL) {
        return NULL;
    }

    lacf->live = NGX_CONF_UNSET;
    lacf->nbuckets = NGX_CONF_UNSET;
    lacf->buflen = NGX_CONF_UNSET_MSEC;
    lacf->sync = NGX_CONF_UNSET_MSEC;
    lacf->idle_timeout = NGX_CONF_UNSET_MSEC;
    lacf->interleave = NGX_CONF_UNSET;
    lacf->gop_cache = NGX_CONF_UNSET;
    lacf->wait_key = NGX_CONF_UNSET;
    lacf->wait_video = NGX_CONF_UNSET;
    lacf->publish_notify = NGX_CONF_UNSET;
    lacf->play_restart = NGX_CONF_UNSET;
    lacf->idle_streams = NGX_CONF_UNSET;
    lacf->check_timeout = NGX_CONF_UNSET;

    return lacf;
}


static char *
ngx_rtmp_live_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_live_app_conf_t *prev = parent;
    ngx_rtmp_live_app_conf_t *conf = child;

    ngx_conf_merge_value(conf->live, prev->live, 1);
    ngx_conf_merge_value(conf->nbuckets, prev->nbuckets, 1024);
    ngx_conf_merge_msec_value(conf->buflen, prev->buflen, 0);
    ngx_conf_merge_msec_value(conf->sync, prev->sync, 300);
    ngx_conf_merge_msec_value(conf->idle_timeout, prev->idle_timeout, 0);
    ngx_conf_merge_value(conf->interleave, prev->interleave, 0);
    ngx_conf_merge_value(conf->gop_cache, prev->gop_cache, 1);
    ngx_conf_merge_value(conf->wait_key, prev->wait_key, 1);
    ngx_conf_merge_value(conf->wait_video, prev->wait_video, 1);
    ngx_conf_merge_value(conf->publish_notify, prev->publish_notify, 0);
    ngx_conf_merge_value(conf->play_restart, prev->play_restart, 0);
    ngx_conf_merge_value(conf->idle_streams, prev->idle_streams, 1);
    ngx_conf_merge_value(conf->check_timeout, prev->check_timeout, 2000);

    conf->pool = ngx_create_pool(4096, &cf->cycle->new_log);
    if (conf->pool == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->streams = ngx_pcalloc(cf->pool,
            sizeof(ngx_rtmp_live_stream_t *) * conf->nbuckets);

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_live_set_msec_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *p = conf;
    ngx_str_t                  *value;
    ngx_msec_t                 *msp;

    msp = (ngx_msec_t *) (p + cmd->offset);

    value = cf->args->elts;

    if (value[1].len == sizeof("off") - 1 &&
        ngx_strncasecmp(value[1].data, (u_char *) "off", value[1].len) == 0)
    {
        *msp = 0;
        return NGX_CONF_OK;
    }

    return ngx_conf_set_msec_slot(cf, cmd, conf);
}


static ngx_rtmp_live_stream_t **
ngx_rtmp_live_get_stream(ngx_rtmp_session_t *s, u_char *name, int create)
{
    ngx_rtmp_live_app_conf_t   *lacf;
    ngx_rtmp_live_stream_t    **stream;
    size_t                      len;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return NULL;
    }

    len = ngx_strlen(name);
    stream = &lacf->streams[ngx_hash_key(name, len) % lacf->nbuckets];

    for (; *stream; stream = &(*stream)->next) {
        if (ngx_strcmp(name, (*stream)->name) == 0) {
            return stream;
        }
    }

    if (!create) {
        return NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "live: create stream '%s'", name);

    if (lacf->free_streams) {
        *stream = lacf->free_streams;
        lacf->free_streams = lacf->free_streams->next;
    } else {
        *stream = ngx_palloc(lacf->pool, sizeof(ngx_rtmp_live_stream_t));
    }

    ngx_memzero(*stream, sizeof(ngx_rtmp_live_stream_t));
    ngx_memcpy((*stream)->name, name, ngx_min(sizeof((*stream)->name) - 1, len));
    (*stream)->epoch = ngx_current_msec;
    (*stream)->check_evt_msec = lacf->check_timeout;

    return stream;
}


ngx_rtmp_live_dyn_srv_t **
ngx_rtmp_live_get_srv_dynamic(ngx_rtmp_live_main_conf_t *lmcf, ngx_str_t *uniqname, int create)
{
    ngx_rtmp_live_dyn_srv_t   **srv;

    if (lmcf == NULL) {
        return NULL;
    }

    srv = &lmcf->srvs[ngx_hash_key(uniqname->data, uniqname->len) % NGX_RTMP_MAX_SRV_NBUCKET];
    for (; *srv; srv = &(*srv)->next) {
        if (ngx_strlen((*srv)->name) == uniqname->len &&
            ngx_strncmp(uniqname->data, (*srv)->name, uniqname->len) == 0) {
            return srv;
        }
    }

    if (!create) {
        return NULL;
    }

    if (lmcf->free_srvs) {
        *srv = lmcf->free_srvs;
        lmcf->free_srvs = lmcf->free_srvs->next;
    } else {
        *srv = ngx_palloc(lmcf->pool, sizeof(ngx_rtmp_live_dyn_srv_t));
    }

    ngx_memzero(*srv, sizeof(ngx_rtmp_live_dyn_srv_t));
    ngx_memcpy((*srv)->name, uniqname->data, ngx_min(sizeof((*srv)->name) - 1, uniqname->len));
    (*srv)->napp = 0;

    return srv;
}


ngx_rtmp_live_dyn_app_t **
ngx_rtmp_live_get_app_dynamic(ngx_rtmp_live_main_conf_t *lmcf, ngx_rtmp_live_dyn_srv_t **srv, ngx_str_t *appname, int create)
{
    ngx_rtmp_live_dyn_app_t   **app;

    if (lmcf == NULL) {
        return NULL;
    }

    app = &(*srv)->apps[ngx_hash_key(appname->data, appname->len) % NGX_RTMP_MAX_APP_NBUCKET];
    for (; *app; app = &(*app)->next) {
        if (ngx_strlen((*app)->name) == appname->len &&
            ngx_strncmp(appname->data, (*app)->name, appname->len) == 0) {
            return app;
        }
    }

    if (!create) {
        return NULL;
    }

    if (lmcf->free_apps) {
        *app = lmcf->free_apps;
        lmcf->free_apps = lmcf->free_apps->next;
    } else {
        *app = ngx_palloc(lmcf->pool, sizeof(ngx_rtmp_live_dyn_app_t));
    }

    ngx_memzero(*app, sizeof(ngx_rtmp_live_dyn_app_t));
    ngx_memcpy((*app)->name, appname->data, ngx_min(sizeof((*app)->name) - 1, appname->len));
    (*app)->nstream = 0;
    (*srv)->napp ++;

    return app;
}


ngx_rtmp_live_stream_t **
ngx_rtmp_live_get_name_dynamic(ngx_rtmp_live_main_conf_t *lmcf, ngx_rtmp_live_app_conf_t *lacf,
    ngx_rtmp_live_dyn_app_t **app, ngx_str_t *name, int create)
{
    ngx_rtmp_live_stream_t   **stream;

    if (lmcf == NULL || lacf == NULL) {
        return NULL;
    }

    stream = &(*app)->streams[ngx_hash_key(name->data, name->len) % NGX_RTMP_MAX_STREAM_NBUCKET];
    for (; *stream; stream = &(*stream)->next) {
        if (ngx_strlen((*stream)->name) == name->len &&
            ngx_strncmp(name->data, (*stream)->name, name->len) == 0) {
            return stream;
        }
    }

    if (!create) {
        return NULL;
    }

    if (lmcf->free_streams) {
        *stream = lmcf->free_streams;
        lmcf->free_streams = lmcf->free_streams->next;
    } else {
        *stream = ngx_palloc(lmcf->pool, sizeof(ngx_rtmp_live_stream_t));
    }

    ngx_memzero(*stream, sizeof(ngx_rtmp_live_stream_t));
    ngx_memcpy((*stream)->name, name->data, ngx_min(sizeof((*stream)->name) - 1, name->len));
    (*stream)->epoch = ngx_current_msec;
    (*stream)->check_evt_msec = lacf->check_timeout;
    (*app)->nstream ++;

    return stream;
}


static ngx_rtmp_live_stream_t **
ngx_rtmp_live_get_stream_dynamic(ngx_rtmp_session_t *s, int create, ngx_rtmp_live_dyn_srv_t ***srv,
    ngx_rtmp_live_dyn_app_t ***app)
{
    ngx_rtmp_live_app_conf_t   *lacf;
    ngx_rtmp_live_main_conf_t  *lmcf;
    ngx_rtmp_live_stream_t    **stream;
    ngx_rtmp_live_ctx_t        *ctx;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return NULL;
    }

    lmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_live_module);
    if (lmcf == NULL) {
        return NULL;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return NULL;
    }

    *srv = ngx_rtmp_live_get_srv_dynamic(lmcf, &s->dynamic_cf->unique_name, create);
    if (*srv == NULL) {
        return NULL;
    }

    *app = ngx_rtmp_live_get_app_dynamic(lmcf, *srv, &s->app, create);
    if (*app == NULL) {
        return NULL;
    }

    stream = ngx_rtmp_live_get_name_dynamic(lmcf, lacf, *app, &s->name, create);
    if (stream == NULL) {
        return NULL;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "live: dynamic create unique_name='%V' app='%V' stream='%V'",
            &s->dynamic_cf->unique_name, &s->app, &s->name);

    return stream;
}


static void
ngx_rtmp_live_checking_callback(ngx_event_t *e)
{
	static ngx_rtmp_play_t      v;

    ngx_rtmp_session_t         *s;
    ngx_rtmp_live_stream_t     *stream;
    ngx_rtmp_session_t         *player;

    stream = e->data;
    if (NULL == stream->ctx || NULL == stream->ctx->session)
        return;
    if (stream->publishing)
        return;

    s = stream->ctx->session;

	*ngx_cpymem(v.name, s->name.data, s->name.len) = 0;
	*ngx_cpymem(v.args, s->args.data, s->args.len) = 0;
	v.start = s->start;
	v.duration = s->duration;
	v.reset = s->reset;
	v.silent = s->silent;

    ngx_rtmp_notify_play1(s, &v);

    player = stream->ctx->session;
    e = &stream->check_evt;
    e->data = stream;
    e->log = player->connection->log;
    e->handler = ngx_rtmp_live_checking_callback;

    ngx_add_timer(&stream->check_evt, stream->check_evt_msec);
}


static ngx_int_t
ngx_rtmp_live_checking_publish(ngx_rtmp_session_t *s, ngx_rtmp_live_stream_t *stream)
{
    ngx_rtmp_session_t             *player;
    ngx_event_t                    *e;

    if (stream->check_evt.timer_set) {
		ngx_log_debug(NGX_LOG_WARN, s->connection->log, 0,
                   "ngx_rtmp_live_publish_checking: check_evt has been set already.",
                   stream->check_evt_msec);
        return NGX_OK;
    }

    player = stream->ctx->session;

    e = &stream->check_evt;
    e->data = stream;
    e->log = player->connection->log;
    e->handler = ngx_rtmp_live_checking_callback;

    ngx_add_timer(&stream->check_evt, stream->check_evt_msec);

    return NGX_OK;
}


static void
ngx_rtmp_live_idle(ngx_event_t *pev)
{
    ngx_connection_t           *c;
    ngx_rtmp_session_t         *s;

    c = pev->data;
    s = !ngx_rtmp_type(c->protocol) ? c->http_data : c->data;

    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                  "live: drop idle publisher");

    ngx_rtmp_finalize_session(s);
}


static void
ngx_rtmp_live_set_status(ngx_rtmp_session_t *s, ngx_chain_t *control,
                         ngx_chain_t **status, size_t nstatus,
                         unsigned active)
{
    ngx_rtmp_live_app_conf_t   *lacf;
    ngx_rtmp_live_ctx_t        *ctx, *pctx;
    ngx_chain_t               **cl;
    ngx_event_t                *e;
    size_t                      n;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: set active=%ui", active);

    if (ctx->active == active) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "live: unchanged active=%ui", active);
        return;
    }

    ctx->active = active;

    if (ctx->publishing) {

        /* publisher */

        if (ngx_rtmp_get_attr_conf(lacf, idle_timeout) && s->relay_type == NGX_NONE_RELAY) {
            e = &ctx->idle_evt;

            if (active && !ctx->idle_evt.timer_set) {
                e->data = s->connection;
                e->log = s->connection->log;
                e->handler = ngx_rtmp_live_idle;

                ngx_add_timer(e, ngx_rtmp_get_attr_conf(lacf, idle_timeout));

            } else if (!active && ctx->idle_evt.timer_set) {
                ngx_del_timer(e);
            }
        }

        ctx->stream->active = active;

        for (pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
            if (pctx->publishing == 0) {
                ngx_rtmp_live_set_status(pctx->session, control, status,
                                         nstatus, active);
            }
        }

        return;
    }

    /* subscriber */

    if (control && ngx_rtmp_send_message(s, control, 0) != NGX_OK) {
        ngx_rtmp_finalize_session(s);
        return;
    }

    if (!ctx->silent) {
        cl = status;

        for (n = 0; n < nstatus; ++n, ++cl) {
            if (*cl && ngx_rtmp_send_message(s, *cl, 0) != NGX_OK) {
                ngx_rtmp_finalize_session(s);
                return;
            }
        }
    }

    ctx->cs[0].active = 0;
    ctx->cs[0].dropped = 0;

    ctx->cs[1].active = 0;
    ctx->cs[1].dropped = 0;
}


static void
ngx_rtmp_live_start(ngx_rtmp_session_t *s)
{
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_live_app_conf_t   *lacf;
    ngx_chain_t                *control;
    ngx_chain_t                *status[3];
    size_t                      n, nstatus;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);

    control = ngx_rtmp_create_stream_begin(s, NGX_RTMP_MSID);

    nstatus = 0;

    if (lacf->play_restart) {
        status[nstatus++] = ngx_rtmp_create_status(s, "NetStream.Play.Start",
                                                   "status", "Start live");
        status[nstatus++] = ngx_rtmp_create_sample_access(s);
    }

    if (lacf->publish_notify) {
        status[nstatus++] = ngx_rtmp_create_status(s,
                                                 "NetStream.Play.PublishNotify",
                                                 "status", "Start publishing");
    }

    ngx_rtmp_live_set_status(s, control, status, nstatus, 1);

    if (control) {
        ngx_rtmp_free_shared_chain(cscf, control);
    }

    for (n = 0; n < nstatus; ++n) {
        ngx_rtmp_free_shared_chain(cscf, status[n]);
    }
}


static void
ngx_rtmp_live_stop(ngx_rtmp_session_t *s)
{
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_live_app_conf_t   *lacf;
    ngx_chain_t                *control;
    ngx_chain_t                *status[3];
    size_t                      n, nstatus;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);

    control = ngx_rtmp_create_stream_eof(s, NGX_RTMP_MSID);

    nstatus = 0;

    if (lacf->play_restart) {
        status[nstatus++] = ngx_rtmp_create_status(s, "NetStream.Play.Stop",
                                                   "status", "Stop live");
    }

    if (lacf->publish_notify) {
        status[nstatus++] = ngx_rtmp_create_status(s,
                                               "NetStream.Play.UnpublishNotify",
                                               "status", "Stop publishing");
    }

    ngx_rtmp_live_set_status(s, control, status, nstatus, 0);

    if (control) {
        ngx_rtmp_free_shared_chain(cscf, control);
    }

    for (n = 0; n < nstatus; ++n) {
        ngx_rtmp_free_shared_chain(cscf, status[n]);
    }
}


static ngx_int_t
ngx_rtmp_live_stream_begin(ngx_rtmp_session_t *s, ngx_rtmp_stream_begin_t *v)
{
    ngx_rtmp_live_ctx_t    *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    if (ctx == NULL ||
        ctx->stream == NULL ||
        !ctx->publishing) {

        goto next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: stream_begin");

    ngx_rtmp_live_start(s);

next:
    return next_stream_begin(s, v);
}


ngx_chain_t *
ngx_rtmp_gop_alloc_chain(ngx_array_t *a)
{
    u_char                     *p;
    ngx_buf_t                  *b;
    ngx_chain_t                *out, **free = a->elts;
    size_t                      size;

    if (*free) {
        out = *free;
        *free = (*free)->next;

    } else {

        size = NGX_RTMP_DEFAULT_CHUNK_SIZE;

        p = ngx_pcalloc(a->pool, sizeof(ngx_chain_t)
                        + sizeof(ngx_buf_t) + size);
        if (p == NULL) {
            return NULL;
        }

        out = (ngx_chain_t *)p;

        p += sizeof(ngx_chain_t);
        out->buf = (ngx_buf_t *)p;

        p += sizeof(ngx_buf_t);
        out->buf->start = p;
        out->buf->end = p + size;
    }

    out->next = NULL;
    b = out->buf;
    b->pos = b->last = b->start;
    b->memory = 1;

    return out;
}


static ngx_int_t
ngx_rtmp_live_stream_eof(ngx_rtmp_session_t *s, ngx_rtmp_stream_eof_t *v)
{
    ngx_rtmp_live_ctx_t    *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    if (ctx == NULL ||
        ctx->stream == NULL ||
        !ctx->publishing) {

        goto next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: stream_eof");

    ngx_rtmp_live_stop(s);

next:
    return next_stream_eof(s, v);
}


static void
ngx_rtmp_live_join(ngx_rtmp_session_t *s, u_char *name, unsigned publisher)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_live_dyn_srv_t       **srv;
    ngx_rtmp_live_dyn_app_t       **app;
    ngx_rtmp_live_stream_t        **stream;
    ngx_rtmp_live_app_conf_t       *lacf;
    int                             create;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx && ctx->stream) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "live: already joined");
        return;
    }

    if (ctx == NULL) {
        ctx = ngx_palloc(s->connection->pool, sizeof(ngx_rtmp_live_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_live_module);
    }

    ngx_memzero(ctx, sizeof(*ctx));

    ctx->session = s;
    srv = NULL;
    app = NULL;
    stream = NULL;

    create = publisher || lacf->idle_streams || s->relay_type != NGX_NONE_RELAY;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: join '%s'", name);

    if (ngx_rtmp_remote_conf()) {
        stream = ngx_rtmp_live_get_stream_dynamic(s, create, &srv, &app);
    } else {
        stream = ngx_rtmp_live_get_stream(s, name, create);
    }

    if (stream == NULL ||
        !(publisher || (*stream)->publishing || lacf->idle_streams || s->relay_type != NGX_NONE_RELAY ))
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "live: stream not found");

        ngx_rtmp_send_status(s, "NetStream.Play.StreamNotFound", "error",
                             "No such stream");

        ngx_rtmp_finalize_session(s);

        return;
    }

    if (publisher) {
        if ((*stream)->publishing) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "live: '%V/%s', already publishing", &s->app, name);

            ngx_rtmp_send_status(s, "NetStream.Publish.BadName", "error",
                                 "Already publishing");

            return;
        }

        (*stream)->publishing = 1;

         //del checking timer
         ngx_del_timer(&(*stream)->check_evt);
    } else {
    	ngx_str_t strname;
		strname.data = name;
		strname.len  = ngx_strlen(name);
    	ngx_rtmp_relay_player_new(s, &strname);
    }

    if (ngx_rtmp_remote_conf()) {
        ctx->srv = *srv;
        ctx->app = *app;
    }

    ctx->stream = *stream;
    ctx->publishing = publisher;
    ctx->next = (*stream)->ctx;
    ctx->protocol = s->protocol;

	(*stream)->ctx = ctx;

    if (lacf->buflen) {
        s->out_buffer = 1;
    }

    ctx->cs[0].csid = NGX_RTMP_CSID_VIDEO;
    ctx->cs[1].csid = NGX_RTMP_CSID_AUDIO;

    if (!ctx->publishing && ctx->stream->active) {
        ngx_rtmp_live_start(s);
    }

	if (!publisher && !(*stream)->publishing) {
		ngx_str_t strname;
		strname.data = name;
		strname.len  = ngx_strlen(name);
		if (ngx_rtmp_relay_relaying(s, &strname) == NGX_ERROR) {
			ngx_rtmp_live_checking_publish(s, *stream);
		}
	}
}


static void
ngx_rtmp_live_empty_leave(ngx_rtmp_session_t *s, ngx_rtmp_live_stream_t **stream)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_live_app_conf_t       *lacf;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return;
    }

    *stream = (*stream)->next;

    ctx->stream->next = lacf->free_streams;
    lacf->free_streams = ctx->stream;
    ctx->stream = NULL;
}


static void
ngx_rtmp_live_empty_leave_dynamic(ngx_rtmp_session_t *s, ngx_rtmp_live_stream_t **stream, ngx_rtmp_live_dyn_srv_t **srv,
    ngx_rtmp_live_dyn_app_t **app)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_live_main_conf_t      *lmcf;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return;
    }

    lmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_live_module);
    if (lmcf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "live_empty_leave: dynamic unique_name='%V' app='%V' stream='%V'",
            &s->dynamic_cf->unique_name, &s->app, &s->name);

    *stream = (*stream)->next;
    (*app)->nstream --;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "live_empty_leave: dynamic unique_name='%V' app='%V' stream='%V' nstream='%d'",
            &s->dynamic_cf->unique_name, &s->app, &s->name, (*app)->nstream);

    ctx->stream->next = lmcf->free_streams;
    lmcf->free_streams = ctx->stream;
    ctx->stream = NULL;

    if ((*app)->nstream == 0) {
        *app = (*app)->next;
        (*srv)->napp --;

        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "live_empty_leave: dynamic unique_name='%V' app='%V' stream='%V' napp='%d'",
                &s->dynamic_cf->unique_name, &s->app, &s->name, (*srv)->napp);

        ctx->app->next = lmcf->free_apps;
        lmcf->free_apps = ctx->app;
        ctx->app = NULL;

        if ((*srv)->napp == 0) {
            *srv = (*srv)->next;

            ctx->srv->next = lmcf->free_srvs;
            lmcf->free_srvs = ctx->srv;
            ctx->srv = NULL;
        }
    }
}


static void
ngx_rtmp_live_close(ngx_rtmp_session_t *s)
{
    ngx_rtmp_session_t             *ss;
    ngx_rtmp_live_ctx_t            *ctx, **cctx, *pctx;
    ngx_rtmp_live_stream_t        **stream;
    ngx_rtmp_live_dyn_srv_t       **srv;
    ngx_rtmp_live_dyn_app_t       **app;
    ngx_rtmp_live_app_conf_t       *lacf;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return;
    }

    if (ctx->stream == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "live: not joined");
        return;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                   "live: leave '%s', publisher=%i, ctx->stream->publishing=%i",
                   ctx->stream->name, ctx->publishing, ctx->stream->publishing);

    if (ctx->stream->publishing && ctx->publishing) {
        ctx->stream->publishing = 0;
    }

    for (cctx = &ctx->stream->ctx; *cctx; cctx = &(*cctx)->next) {
        if (*cctx == ctx) {
            *cctx = ctx->next;
            break;
        }
    }

    if (ctx->publishing || ctx->stream->active) {
        ngx_rtmp_live_stop(s);
    }

    if (ctx->publishing) {
        ngx_rtmp_send_status(s, "NetStream.Unpublish.Success",
                             "status", "Stop publishing");
		ctx->stream->bw_in.bandwidth = 0;
		ctx->stream->bw_real.bandwidth = 0;
		ctx->stream->bw_out.bandwidth = 0;
        if (ngx_rtmp_publishing > 0) {

            --ngx_rtmp_publishing;
        }

        if (!lacf->idle_streams) {
            for (pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
                if (pctx->publishing == 0) {
                    ss = pctx->session;
                    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                                   "live: no publisher");
                    ngx_rtmp_finalize_session(ss);
                }
            }
        } else {
        	ngx_uint_t nplayer = 0;
            for (pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
				if (pctx->publishing == 0) {
                    ss = pctx->session;
	                if (ss->relay_type != NGX_NONE_RELAY) {
	                    ngx_log_error(NGX_LOG_INFO, ss->connection->log, 0,
	                                   "live: close relay session");
	                    ngx_rtmp_finalize_session(ss);
	                }
					nplayer++;
				}
            }

			if (nplayer > 0) {
				ngx_rtmp_live_checking_publish(s, ctx->stream);
			}
        }
    } else {

		if (ctx->stream->ctx != NULL &&
			ctx->stream->ctx->next == NULL &&
			ctx->stream->ctx->publishing) {
			ngx_str_t strname;
			strname.data = ctx->stream->name;
			strname.len  = ngx_strlen(ctx->stream->name);
			ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
					"live: last player close his connection.");
			ngx_rtmp_relay_player_dry(s, &strname);
		}

	    if (ngx_rtmp_playing > 0) {

			--ngx_rtmp_playing;
	    }
    }

    if (ctx->stream->ctx) {
        ctx->stream = NULL;
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: delete empty stream '%s'",
                   ctx->stream->name);

	ngx_del_timer(&(ctx->stream->check_evt));

    if (ngx_rtmp_remote_conf()) {
        stream = ngx_rtmp_live_get_stream_dynamic(s, 0, &srv, &app);
    } else {
        stream = ngx_rtmp_live_get_stream(s, ctx->stream->name, 0);
    }

    if (stream == NULL) {
        return;
    }

    if (ngx_rtmp_remote_conf()) {
        ngx_rtmp_live_empty_leave_dynamic(s, stream, srv, app);
    } else {
        ngx_rtmp_live_empty_leave(s, stream);
    }

    if (!ctx->silent && !ctx->publishing && !lacf->play_restart) {
        ngx_rtmp_send_status(s, "NetStream.Play.Stop", "status", "Stop live");
    }
}


static ngx_int_t
ngx_rtmp_live_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_live_close(s);

    return next_close_stream(s, v);
}


static ngx_int_t
ngx_rtmp_live_delete_stream(ngx_rtmp_session_t *s, ngx_rtmp_delete_stream_t *v)
{
    ngx_rtmp_live_close(s);

    return next_delete_stream(s, v);
}


static ngx_int_t
ngx_rtmp_live_pause(ngx_rtmp_session_t *s, ngx_rtmp_pause_t *v)
{
    ngx_rtmp_live_ctx_t            *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    if (ctx == NULL ||
        ctx->stream == NULL) {

        goto next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: pause=%i timestamp=%f",
                   (ngx_int_t) v->pause, v->position);

    if (v->pause) {
        if (ngx_rtmp_send_status(s, "NetStream.Pause.Notify", "status",
                                 "Paused live")
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        ctx->paused = 1;

        ngx_rtmp_live_stop(s);

    } else {
        if (ngx_rtmp_send_status(s, "NetStream.Unpause.Notify", "status",
                                 "Unpaused live")
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        ctx->paused = 0;

        ngx_rtmp_live_start(s);
    }

next:
    return next_pause(s, v);
}


extern ngx_rtmp_bandwidth_t ngx_rtmp_bw_real;
static void ngx_rtmp_update_total_real_bandwidth(ngx_rtmp_bandwidth_t *bw, ngx_rtmp_live_app_conf_t *lacf)
{
    ngx_rtmp_live_stream_t  *stream;
    ngx_int_t    n;
    uint64_t total_bandwidth=0;
    uint64_t total_bytes=0;
	
    if (ngx_cached_time->sec > bw->intl_end) {
		
        for (n=0; n<lacf->nbuckets; ++n) {
			
            for (stream = lacf->streams[n]; stream; stream = stream->next) {	
				
                total_bandwidth += stream->bw_real.bandwidth;
            }
        }

        bw->bandwidth = total_bandwidth;
        bw->bytes = total_bytes;
        bw->intl_end = ngx_cached_time->sec + NGX_RTMP_BANDWIDTH_INTERVAL;
   }
}


static ngx_rtmp_live_gop_cache_t *
ngx_rtmp_live_gop_cache_alloc(ngx_rtmp_session_t *s)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_live_gop_cache_t      *cache;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return NULL;
    }

    if (!ctx->gop_pool) {
        ctx->gop_pool = ngx_create_pool(4096, s->connection->log);
    }

    cache = ngx_pcalloc(ctx->gop_pool, sizeof(ngx_rtmp_live_gop_cache_t));
    if (cache == NULL) {
        return NULL;
    }

    return cache;
}


static void
ngx_rtmp_live_gop_cache_link(ngx_rtmp_session_t *s, ngx_rtmp_live_gop_cache_t *new)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_live_gop_cache_t      *cache;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return;
    }

    if (ctx->gop_cache == NULL) {

        ctx->gop_cache = new;
    } else {

        for (cache = ctx->gop_cache; cache->next; cache = cache->next);

        cache->next = new;
    }
}


static void
ngx_rtmp_live_gop_cache_clean(ngx_rtmp_session_t *s)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_gop_cache_t      *cache;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return;
    }

    for (cache = ctx->gop_cache; cache; cache = cache->next) {

        if (cache->frame) {
            ngx_rtmp_free_shared_chain(cscf, cache->frame);
        }
    }

    if (ctx->gop_pool) {
        ngx_destroy_pool(ctx->gop_pool);
    }

    ctx->gop_pool = ngx_create_pool(4096, s->connection->log);

    ctx->gop_cache = NULL;
}


static void
ngx_rtmp_live_gop_cache(ngx_rtmp_session_t *s, ngx_uint_t prio, ngx_rtmp_header_t *ch, ngx_chain_t *frame)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_live_gop_cache_t      *cache;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return;
    }

    if (!ngx_rtmp_get_attr_conf(lacf, gop_cache)) {
        return;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        return;
    }

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    // got video, update the video count if acceptable
    if (ch->type == NGX_RTMP_MSG_VIDEO) {

        // drop video when not h.264
        if (!codec_ctx ||
            codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H264) {

            return;
        }

        ctx->cached_video_cnt ++;
        ctx->audio_after_last_video_cnt = 0;
    }

    // pure audio?
    if (ctx->cached_video_cnt == 0) {
        return;
    }

    if (ch->type == NGX_RTMP_MSG_AUDIO) {
        ctx->audio_after_last_video_cnt ++;
    }

    if (ctx->audio_after_last_video_cnt > NGX_RTMP_LIVE_PURE_AUDIO_GUESS_CNT) {

        ngx_rtmp_live_gop_cache_clean(s);

        return;
    }

    if (ch->type == NGX_RTMP_MSG_VIDEO &&
        prio == NGX_RTMP_VIDEO_KEY_FRAME) {

        ngx_rtmp_live_gop_cache_clean(s);

        ctx->cached_video_cnt = 1;
    }

    cache = ngx_rtmp_live_gop_cache_alloc(s);
    if (cache == NULL) {
        return;
    }

    cache->h = *ch;
    cache->prio = prio;
    cache->next = NULL;
    cache->frame = ngx_rtmp_append_shared_bufs(cscf, NULL, frame);

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
               "gop_cache: cache packet type='%s' timestamp='%uD'",
               cache->h.type == NGX_RTMP_MSG_AUDIO ? "audio" : "video", cache->h.timestamp);

    ngx_rtmp_live_gop_cache_link(s, cache);
}


static void
ngx_rtmp_live_gop_cache_send(ngx_rtmp_session_t *ss)
{
    ngx_rtmp_session_t             *s;
    ngx_chain_t                    *pkt, *apkt, *meta, *header;
    ngx_rtmp_live_ctx_t            *pctx, *publisher, *player;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_live_gop_cache_t      *cache;
    ngx_rtmp_header_t               ch, lh;
    ngx_uint_t                      meta_version;
    uint32_t                        delta;
    ngx_int_t                       csidx;
    ngx_rtmp_live_chunk_stream_t   *cs;

    lacf = ngx_rtmp_get_module_app_conf(ss, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return;
    }

    if (!ngx_rtmp_get_attr_conf(lacf, gop_cache)) {
        return;
    }

    cscf = ngx_rtmp_get_module_srv_conf(ss, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return;
    }

    player = ngx_rtmp_get_module_ctx(ss, ngx_rtmp_live_module);
    if (player == NULL) {
        return;
    }

    if (!ngx_rtmp_type(ss->protocol)) {
        return;
    }

    for (pctx = player->stream->ctx; pctx; pctx = pctx->next) {
        if (pctx->publishing) {
            break;
        }
    }

    if (pctx == NULL) {
        return;
    }

    pkt = NULL;
    apkt = NULL;
    meta = NULL;
    header = NULL;
    meta_version = 0;    

    publisher = pctx;
    s         = publisher->session;
	ss        = player->session;

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (codec_ctx == NULL) {
        return;
    }

    if (codec_ctx->meta) {
        meta = codec_ctx->meta;
        meta_version = codec_ctx->meta_version;
    }

    /* send metadata */

    if (meta && meta_version != player->meta_version) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                       "live: meta");

        if (ngx_rtmp_send_message(ss, meta, 0) == NGX_OK) {
            player->meta_version = meta_version;
        }
    }

    for (cache = publisher->gop_cache; cache; cache = cache->next) {

        csidx = !(lacf->interleave || cache->h.type == NGX_RTMP_MSG_VIDEO);

        cs = &player->cs[csidx];

        lh = ch = cache->h;

        if (cs->active) {

            lh.timestamp = cs->timestamp;
        }

        delta = ch.timestamp - lh.timestamp;

        if (!cs->active) {

            header = cache->h.type == NGX_RTMP_MSG_VIDEO ? codec_ctx->avc_header : codec_ctx->aac_header;
            if (header) {

                apkt = ngx_rtmp_append_shared_bufs(cscf, NULL, header);
                ngx_rtmp_prepare_message(s, &lh, NULL, apkt);
            }

            if (ngx_rtmp_send_message(ss, apkt, cache->prio) != NGX_OK) {

                return;
            }

            cs->timestamp = lh.timestamp;
            cs->active = 1;
            ss->current_time = cs->timestamp;
        }

        pkt = ngx_rtmp_append_shared_bufs(cscf, NULL, cache->frame);

        ngx_rtmp_prepare_message(s, &ch, &lh, pkt);

        if (ngx_rtmp_send_message(ss, pkt, 0) != NGX_OK) {
            ++pctx->ndropped;

            cs->dropped += delta;

            return;
        }

        if (pkt) {
            ngx_rtmp_free_shared_chain(cscf, pkt);
            pkt = NULL;
        }

        if (apkt) {
            ngx_rtmp_free_shared_chain(cscf, apkt);
            apkt = NULL;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
               "gop_send: send tag type='%s' ltimestamp='%uD'",
               cache->h.type == NGX_RTMP_MSG_AUDIO ? "audio" : "video",
               lh.timestamp);

        cs->timestamp += delta;
        ss->current_time = cs->timestamp;
    }
}


static ngx_int_t
ngx_rtmp_live_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                 ngx_chain_t *in)
{
    ngx_rtmp_live_ctx_t            *ctx, *pctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx = NULL;
    ngx_chain_t                    *header, *coheader, *meta,
                                   *apkt, *aapkt, *acopkt, *rpkt = NULL;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_session_t             *ss;
    ngx_rtmp_header_t               ch, lh, clh;
    ngx_int_t                       rc, mandatory, dummy_audio;
    ngx_uint_t                      prio;
    ngx_uint_t                      peers;
    ngx_uint_t                      meta_version;
    ngx_uint_t                      csidx;
    uint32_t                        delta = 0;
    ngx_rtmp_live_chunk_stream_t   *cs;
#ifdef NGX_DEBUG
    const char                     *type_s;

    type_s = (h->type == NGX_RTMP_MSG_VIDEO ? "video" : "audio");
#endif

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return NGX_ERROR;
    }

    if (!ngx_rtmp_get_attr_conf(lacf, live)) {
        return NGX_OK;
    }

    if (in == NULL || in->buf == NULL) {
        return NGX_OK;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        return NGX_OK;
    }

    if (ctx->publishing == 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "live: %s from non-publisher", type_s);
        return NGX_OK;
    }

    if (!ctx->stream->active) {
        ngx_rtmp_live_start(s);
    }

    if (ctx->idle_evt.timer_set) {
        ngx_add_timer(&ctx->idle_evt, ngx_rtmp_get_attr_conf(lacf, idle_timeout));
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: %s packet timestamp=%uD",
                   type_s, h->timestamp);

    s->current_time = h->timestamp;

    peers = 0;
    apkt = NULL;
    aapkt = NULL;
    acopkt = NULL;
    header = NULL;
    coheader = NULL;
    meta = NULL;
    meta_version = 0;
    mandatory = 0;

    prio = (h->type == NGX_RTMP_MSG_VIDEO ?
            ngx_rtmp_get_video_frame_type(in) : 0);

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    csidx = !(lacf->interleave || h->type == NGX_RTMP_MSG_VIDEO);

    cs = &ctx->cs[csidx];

    ngx_memzero(&ch, sizeof(ch));

    ch.timestamp = h->timestamp;
    ch.msid = NGX_RTMP_MSID;
    ch.csid = cs->csid;
    ch.type = h->type;

    lh = ch;

    if (cs->active) {
        lh.timestamp = cs->timestamp;
    }

    clh = lh;
    clh.type = (h->type == NGX_RTMP_MSG_AUDIO ? NGX_RTMP_MSG_VIDEO :
                                                NGX_RTMP_MSG_AUDIO);

    cs->active = 1;
    cs->timestamp = ch.timestamp;

    delta = ch.timestamp - lh.timestamp;
/*
    if (delta >> 31) {
        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "live: clipping non-monotonical timestamp %uD->%uD",
                       lh.timestamp, ch.timestamp);

        delta = 0;

        ch.timestamp = lh.timestamp;
    }
*/

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (codec_ctx) {

        if (h->type == NGX_RTMP_MSG_AUDIO) {
            header = codec_ctx->aac_header;

            if (lacf->interleave) {
                coheader = codec_ctx->avc_header;
            }

            if (codec_ctx->audio_codec_id == NGX_RTMP_AUDIO_AAC &&
                ngx_rtmp_is_codec_header(in)) // is or not audio header
            {
                prio = 0;
                mandatory = 1;
            }

        } else {
            header = codec_ctx->avc_header;

            if (lacf->interleave) {
                coheader = codec_ctx->aac_header;
            }

            if (codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H264 &&
                ngx_rtmp_is_codec_header(in)) // is or not video header
            {
                prio = 0;
                mandatory = 1;
            }
        }

        if (codec_ctx->meta) {
            meta = codec_ctx->meta;
            meta_version = codec_ctx->meta_version;
        }
    }

    /* broadcast to all subscribers */
    rpkt = ngx_rtmp_append_shared_bufs(cscf, NULL, in);

    ngx_rtmp_prepare_message(s, &ch, &lh, rpkt);

    ngx_rtmp_live_gop_cache(s, prio, &ch, in);

    for (pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
        if (pctx == ctx || pctx->paused) {
            continue;
        }

        ss = pctx->session;
        cs = &pctx->cs[csidx];

        if (!ngx_rtmp_type(ss->protocol)) {
            continue;
        }

        /* send metadata */

        if (meta && meta_version != pctx->meta_version) {
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                           "live: meta");

            if (ngx_rtmp_send_message(ss, meta, 0) == NGX_OK) {
                pctx->meta_version = meta_version;
            }
        }

        /* sync stream */

        if (cs->active && (lacf->sync && cs->dropped > lacf->sync)) {
            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                           "live: sync %s dropped=%uD", type_s, cs->dropped);

            cs->active = 0;
            cs->dropped = 0;
        }

        /* absolute packet */

        if (!cs->active) {

            if (mandatory) {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live: skipping header");
                continue;
            }

            if (lacf->wait_video && h->type == NGX_RTMP_MSG_AUDIO &&
				!pctx->cs[0].active)
            {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live: waiting for video");
                continue;
            }

            if (lacf->wait_key && prio != NGX_RTMP_VIDEO_KEY_FRAME &&
               (lacf->interleave || h->type == NGX_RTMP_MSG_VIDEO))
            {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live: skip non-key");
                continue;
            }

            dummy_audio = 0;
            if (lacf->wait_video && h->type == NGX_RTMP_MSG_VIDEO &&
                !pctx->cs[1].active)
            {
                dummy_audio = 1;
                if (aapkt == NULL) {
                    aapkt = ngx_rtmp_alloc_shared_buf(cscf);
                    ngx_rtmp_prepare_message(s, &clh, NULL, aapkt);
                }
            }

            if (header || coheader) {

                /* send absolute codec header */

                ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live: abs %s header timestamp=%uD",
                               type_s, lh.timestamp);

                if (header) {
                    if (apkt == NULL) {
                        apkt = ngx_rtmp_append_shared_bufs(cscf, NULL, header);
                        ngx_rtmp_prepare_message(s, &lh, NULL, apkt);
                    }

                    rc = ngx_rtmp_send_message(ss, apkt, 0);
                    if (rc != NGX_OK) {
                        continue;
                    }
                }

                if (coheader) {
                    if (acopkt == NULL) {
                        acopkt = ngx_rtmp_append_shared_bufs(cscf, NULL, coheader);
                        ngx_rtmp_prepare_message(s, &clh, NULL, acopkt);
                    }

                    rc = ngx_rtmp_send_message(ss, acopkt, 0);
                    if (rc != NGX_OK) {
                        continue;
                    }

                } else if (dummy_audio) {
                    ngx_rtmp_send_message(ss, aapkt, 0);
                }

                cs->timestamp = lh.timestamp;
                cs->active = 1;
                ss->current_time = cs->timestamp;

            } else {

                /* send absolute packet */

                ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live: abs %s packet timestamp=%uD",
                               type_s, ch.timestamp);

                if (apkt == NULL) {
                    apkt = ngx_rtmp_append_shared_bufs(cscf, NULL, in);
                    ngx_rtmp_prepare_message(s, &ch, NULL, apkt);
                }

                rc = ngx_rtmp_send_message(ss, apkt, prio);
                if (rc != NGX_OK) {
                    continue;
                }

                cs->timestamp = ch.timestamp;
                cs->active = 1;
                ss->current_time = cs->timestamp;

                ++peers;

                if (dummy_audio) {
                    ngx_rtmp_send_message(ss, aapkt, 0);
                }

                continue;
            }
        }

        /* send relative packet */

        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                       "live: rel %s packet delta=%uD",
                       type_s, delta);

        if (ngx_rtmp_send_message(ss, rpkt, prio) != NGX_OK) {
            ++pctx->ndropped;

            cs->dropped += delta;

            if (mandatory) {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live: mandatory packet failed");
                ngx_rtmp_finalize_session(ss);
            }

            continue;
        }

        cs->timestamp += delta;
        ++peers;
        ss->current_time = cs->timestamp;
    }

    if (rpkt) {
        ngx_rtmp_free_shared_chain(cscf, rpkt);
    }

    if (apkt) {
        ngx_rtmp_free_shared_chain(cscf, apkt);
    }

    if (aapkt) {
        ngx_rtmp_free_shared_chain(cscf, aapkt);
    }

    if (acopkt) {
        ngx_rtmp_free_shared_chain(cscf, acopkt);
    }

    ngx_rtmp_update_bandwidth(&ctx->stream->bw_in, h->mlen);
    ngx_rtmp_update_bandwidth_real(&ctx->stream->bw_real, h->mlen, h->timestamp / 1000);
    ngx_rtmp_update_total_real_bandwidth(&ngx_rtmp_bw_real, lacf);

	if (ctx && ctx->stream) {

		if (s->relay_type == NGX_NONE_RELAY) {

			ngx_rtmp_update_bandwidth(&ctx->stream->bw_billing_in, h->mlen);
		}
	}

    ngx_rtmp_update_bandwidth(h->type == NGX_RTMP_MSG_AUDIO ?
                              &ctx->stream->bw_in_audio :
                              &ctx->stream->bw_in_video,
                              h->mlen);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_live_connect(ngx_rtmp_session_t *s, ngx_rtmp_connect_t *v)
{	
    if (s->auto_pushed || s->relay) {
		
        goto next;
    }

    if (ngx_rtmp_remote_conf()) {
		
        if (s->dynamic_cf && !(s->dynamic_cf->live)) {
			
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "live is off......");
            return NGX_ERROR;
        }
    }
	
next:
    return next_connect(s, v);
    
}


static ngx_int_t
ngx_rtmp_live_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_live_ctx_t            *ctx;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        goto next;
    }

    if (ngx_hls_type(s->protocol)) {
        goto next;
    }

    if (!ngx_rtmp_get_attr_conf(lacf, live)) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                   "live_publish: name='%s' type='%s', page_url[len=%i]='%V', addr_text='%V', tc_url='%V'",
                   v->name, v->type, s->page_url.len, &s->page_url, s->addr_text, &s->tc_url);

    /* join stream as publisher */
    ngx_rtmp_live_join(s, v->name, 1);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || !ctx->publishing) {
        goto next;
    }

    ctx->silent = v->silent;

    if (!ctx->silent) {
        ngx_rtmp_send_status(s, "NetStream.Publish.Start",
                             "status", "Start publishing");
    }

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_live_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_live_ctx_t            *ctx;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        goto next;
    }

    if (!ngx_rtmp_get_attr_conf(lacf, live)) {
        goto next;
    }

    if (ngx_hls_type(s->protocol)) {
        goto next;
    }

    /* join stream as subscriber */
    ngx_rtmp_live_join(s, v->name, 0);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                   "live_play: name='%s' start=%uD duration=%uD reset=%d page_url='%V' addr_text='%V' tc_url='%V' flashver='%V'",
                   v->name, (uint32_t) v->start,
                   (uint32_t) v->duration, (uint32_t) v->reset, 
                   &s->page_url, s->addr_text, &s->tc_url, &s->flashver);

    ctx->silent = v->silent;

    if (!ctx->silent && !lacf->play_restart) {
    	ngx_rtmp_send_status(s, "NetStream.Play.Start",
                             "status", "Start live");
        ngx_rtmp_send_sample_access(s);

		s->start = v->start;
		s->duration = v->duration;
		s->reset = v->reset;
		s->silent = v->silent;
    }

    ngx_rtmp_live_gop_cache_send(s);

    ngx_rtmp_playing++;

next:
    return next_play(s, v);
}


static ngx_int_t
ngx_rtmp_live_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    /* register raw event handlers */

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_live_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_live_av;

    /* chain handlers */
    next_connect = ngx_rtmp_connect;
    ngx_rtmp_connect = ngx_rtmp_live_connect;
	
    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_live_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_live_play;

    next_delete_stream = ngx_rtmp_delete_stream;
    ngx_rtmp_delete_stream = ngx_rtmp_live_delete_stream;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_live_close_stream;

    next_pause = ngx_rtmp_pause;
    ngx_rtmp_pause = ngx_rtmp_live_pause;

    next_stream_begin = ngx_rtmp_stream_begin;
    ngx_rtmp_stream_begin = ngx_rtmp_live_stream_begin;

    next_stream_eof = ngx_rtmp_stream_eof;
    ngx_rtmp_stream_eof = ngx_rtmp_live_stream_eof;

    return NGX_OK;
}
