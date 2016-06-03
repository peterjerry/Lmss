
/*
 * Copyright (C) Gino Hu
 */


#ifndef _NGX_RTMP_HLS_H_INCLUDED_
#define _NGX_RTMP_HLS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_rtmp_cmd_module.h>
#include <ngx_rtmp_relay_module.h>
#include <ngx_rtmp_netcall_module.h>
#include "ngx_rtmp.h"

#define NGX_RTMP_HLS_EXIPRE_FILE_NAME     ".expinfo"
#define NGX_RTMP_HLS_EXIPRE_FILE_NAME_BAK NGX_RTMP_HLS_EXIPRE_FILE_NAME".bak"
#define NGX_RTMP_HLS_DIR_ACCESS           0744
#define ngx_rtmp_hls_get_module_app_conf(app_conf, module)  (app_conf ? \
					app_conf[module.ctx_index] : NULL)

typedef struct ngx_rtmp_hls_ctx_s ngx_rtmp_hls_ctx_t;

typedef struct {
    uint64_t                            id;
    double                              duration;
    unsigned                            active:1;
    unsigned                            discont:1; /* before */
} ngx_rtmp_hls_frag_t;


typedef struct {
    ngx_str_t                           suffix;
    ngx_array_t                         args;
} ngx_rtmp_hls_variant_t;


struct ngx_rtmp_hls_ctx_s {
    ngx_file_t                          file, vodfile, indexfile, m3u8file, m3u8filebak;
    ngx_file_t                          expire_file;
    u_char                              time[128];
    uint64_t                            ts_time;
    ngx_uint_t                          vod_max_frag;
    ngx_str_t                           upstream_url;
    ngx_str_t                           playlist;
    ngx_str_t                           vodlist, vodm3u8tmp, vodm3u8bak, vodm3u8;
    ngx_str_t                           playlist_bak;
    ngx_str_t                           var_playlist;
    ngx_str_t                           var_playlist_bak;
    ngx_str_t                           stream;
    ngx_str_t                           expire;
    ngx_str_t                           vodstream;
    uint64_t                            frag;
    uint64_t                            frag_ts;
    uint64_t                            frag_ts_system;
    uint64_t                            frag_seq;
    ngx_uint_t                          nfrags;
    ngx_uint_t                          winfrags;
    ngx_rtmp_hls_frag_t                *frags; /* circular 2 * winfrags + 1 */
    ngx_uint_t                          audio_cc;
    ngx_uint_t                          video_cc;
    ngx_uint_t                          psi_cc;
    uint64_t                            aframe_base;
    uint64_t                            aframe_num;
    ngx_buf_t                          *aframe;
    uint64_t                            aframe_pts;
    ngx_rtmp_hls_variant_t             *var;
    ngx_event_handler_pt                write_handler_backup;
    uint32_t                            base_timestamp;
    unsigned                            m3u8_header:1;
    unsigned                            publisher:1;
    unsigned                            opened:1;
    unsigned                            gen_ts:1;
    unsigned                            closed:1;
};


typedef struct {
    ngx_flag_t                          hls;
    ngx_msec_t                          hls_fragment;
    ngx_msec_t                          hls_playlist_length;
    ngx_flag_t                          hls_vod;
    ngx_msec_t                          vod_fraglen;
    ngx_msec_t                          max_fraglen;
    ngx_msec_t                          muxdelay;
    ngx_msec_t                          sync;
    ngx_uint_t                          winfrags;
    ngx_flag_t                          continuous;
    ngx_flag_t                          nested;
    ngx_str_t                           path;
    ngx_str_t                           vod_path;
    ngx_uint_t                          naming;
    ngx_uint_t                          slicing;
    ngx_uint_t                          type;
    ngx_path_t                         *slot;
    ngx_msec_t                          max_audio_delay;
    size_t                              audio_buffer_size;
    ngx_flag_t                          cleanup;
    ngx_array_t                        *variant;
    ngx_str_t                           base_url;

    ngx_int_t                           user_id;
    ngx_int_t                           hls_vod_is_public;

    ngx_str_t                           hls_vod_bucket;
    ngx_str_t                           hls_vod_url;
    
    ngx_flag_t                          mp4_vod;
    ngx_int_t                           mp4_vod_is_public;
    ngx_str_t                           mp4_vod_bucket;
    ngx_str_t                           mp4_vod_url;

    ngx_str_t                          region_mp4;
    ngx_str_t                          region_hls;
    
    ngx_str_t                          host_mp4;
    ngx_str_t                          host_hls;
    
    ngx_flag_t                         hls_vod_auto_merge;

    ngx_int_t                           granularity;
} ngx_rtmp_hls_app_conf_t;


ngx_int_t ngx_rtmp_http_hls_build_url(ngx_rtmp_session_t *s, ngx_str_t *remote_ip, ngx_int_t remote_port);


#endif /* _NGX_RTMP_HLS_H_INCLUDED_ */

