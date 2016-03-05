
/*
 * Copyright (C) Roman Arutyunyan
 */


#ifndef _NGX_RTMP_LIVE_H_INCLUDED_
#define _NGX_RTMP_LIVE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_bandwidth.h"
#include "ngx_rtmp_streams.h"
#include <ngx_http.h>
#include "hls/ngx_rtmp_hls_module.h"


#define NGX_RTMP_LIVE_PURE_AUDIO_GUESS_CNT    115


typedef struct ngx_rtmp_live_ctx_s ngx_rtmp_live_ctx_t;
typedef struct ngx_rtmp_live_stream_s ngx_rtmp_live_stream_t;
typedef struct ngx_rtmp_live_gop_cache_s ngx_rtmp_live_gop_cache_t;
typedef struct ngx_rtmp_live_dyn_srv_s ngx_rtmp_live_dyn_srv_t;
typedef struct ngx_rtmp_live_dyn_app_s ngx_rtmp_live_dyn_app_t;


typedef struct {
    unsigned                            active:1;
    uint32_t                            timestamp;
    uint32_t                            csid;
    uint32_t                            dropped;
} ngx_rtmp_live_chunk_stream_t;


struct ngx_rtmp_live_gop_cache_s {
    ngx_rtmp_header_t                   h;
    ngx_uint_t                          prio;
    ngx_chain_t                        *frame;
    ngx_rtmp_live_gop_cache_t          *next;
};


struct ngx_rtmp_live_ctx_s {
    ngx_rtmp_session_t                 *session;
    ngx_rtmp_live_dyn_srv_t            *srv;
    ngx_rtmp_live_dyn_app_t            *app;
    ngx_rtmp_live_stream_t             *stream;
    ngx_rtmp_live_ctx_t                *next;
    ngx_rtmp_live_gop_cache_t          *gop_cache;
    ngx_pool_t                         *gop_pool;
    ngx_uint_t                          cached_video_cnt;
    ngx_uint_t                          audio_after_last_video_cnt;
    ngx_uint_t                          ndropped;
    ngx_rtmp_live_chunk_stream_t        cs[2];
    ngx_uint_t                          meta_version;
    ngx_uint_t                          flv_meta_version;
    ngx_event_t                         idle_evt;
    unsigned                            active:1;
    unsigned                            publishing:1;
    unsigned                            silent:1;
    unsigned                            paused:1;
	unsigned                            protocol:4;
};


struct ngx_rtmp_live_stream_s {
    u_char                              name[NGX_RTMP_MAX_NAME];
    ngx_rtmp_live_stream_t             *next;
    ngx_rtmp_live_ctx_t                *ctx;
    ngx_rtmp_bandwidth_t                bw_in;
    ngx_rtmp_bandwidth_t                bw_real;
    ngx_rtmp_bandwidth_t                bw_in_audio;
    ngx_rtmp_bandwidth_t                bw_in_video;
    ngx_rtmp_bandwidth_t                bw_out;
    ngx_rtmp_bandwidth_t				bw_billing_in;
    ngx_rtmp_bandwidth_t				bw_billing_out;

    ngx_msec_t                          epoch;
    unsigned                            active:1;
    unsigned                            publishing:1;

	//for http output , Edward.Wu
	ngx_http_request_t 				   *http_r;

    ngx_event_t                         check_evt;
    ngx_msec_t                          check_evt_msec;
};


typedef struct {
    ngx_int_t                           nbuckets;
    ngx_rtmp_live_stream_t            **streams;
    ngx_flag_t                          live;
    ngx_flag_t                          meta;
    ngx_msec_t                          sync;
    ngx_msec_t                          idle_timeout;
    ngx_flag_t                          atc;
    ngx_flag_t                          interleave;
	ngx_flag_t                          gop_cache;
    ngx_flag_t                          wait_key;
    ngx_flag_t                          wait_video;
    ngx_flag_t                          publish_notify;
    ngx_flag_t                          play_restart;
    ngx_flag_t                          idle_streams;
    ngx_msec_t                          buflen;
    ngx_pool_t                         *pool;
    ngx_rtmp_live_stream_t             *free_streams;
	ngx_flag_t                          check_timeout;
} ngx_rtmp_live_app_conf_t;


struct ngx_rtmp_live_dyn_app_s {
    ngx_rtmp_live_stream_t             *streams[NGX_RTMP_MAX_STREAM_NBUCKET];
    u_char                              name[NGX_RTMP_MAX_NAME];
    ngx_rtmp_live_dyn_app_t            *next;
    ngx_uint_t                          nstream;
};


struct ngx_rtmp_live_dyn_srv_s {
    ngx_rtmp_live_dyn_app_t            *apps[NGX_RTMP_MAX_APP_NBUCKET];
    u_char                              name[NGX_RTMP_MAX_NAME];
    ngx_rtmp_live_dyn_srv_t            *next;
    ngx_uint_t                          napp;
};


typedef struct {
    ngx_rtmp_live_dyn_srv_t            *srvs[NGX_RTMP_MAX_SRV_NBUCKET];
    ngx_rtmp_live_dyn_srv_t            *free_srvs;
    ngx_rtmp_live_dyn_app_t            *free_apps;
    ngx_rtmp_live_stream_t             *free_streams;
    ngx_pool_t                         *pool;
} ngx_rtmp_live_main_conf_t;


extern ngx_module_t  ngx_rtmp_live_module;

ngx_int_t
ngx_rtmp_relay_player_dry(ngx_rtmp_session_t *s, ngx_str_t *name);
ngx_rtmp_live_dyn_srv_t **
ngx_rtmp_live_get_srv_dynamic(ngx_rtmp_live_main_conf_t *lmcf, ngx_str_t *uniqname, int create);
ngx_rtmp_live_dyn_app_t **
ngx_rtmp_live_get_app_dynamic(ngx_rtmp_live_main_conf_t *lmcf, ngx_rtmp_live_dyn_srv_t **srv, ngx_str_t *appname, int create);
ngx_rtmp_live_stream_t **
ngx_rtmp_live_get_name_dynamic(ngx_rtmp_live_main_conf_t *lmcf, ngx_rtmp_live_app_conf_t *lacf, ngx_rtmp_live_dyn_app_t **app, ngx_str_t *name, int create);

ngx_rtmp_live_main_conf_t *ngx_rtmp_live_main_conf;


#endif /* _NGX_RTMP_LIVE_H_INCLUDED_ */
