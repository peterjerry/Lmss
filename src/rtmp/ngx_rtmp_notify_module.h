
/*
 * Copyright (C) Roman Arutyunyan
 */


#ifndef _NGX_RTMP_NOTIFY_H_INCLUDED_
#define _NGX_RTMP_NOTIFY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "json-c/json.h"

typedef struct {

    u_char        *v_codec;
    u_char        *a_codec;
    char          *v_profile;
    char          *a_profile;
	
    ngx_uint_t     level;
    ngx_uint_t     width;
    ngx_uint_t     height;
    ngx_uint_t     frame_rate;
    ngx_uint_t     compat;
    ngx_uint_t     channels;
    ngx_uint_t     sample_rate;
}codec_st;

ngx_int_t ngx_rtmp_notify_play1(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v);


#endif /* _NGX_RTMP_NOTIFY_H_INCLUDED_ */
