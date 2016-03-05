
/*
 * Copyright (C) Roman Arutyunyan
 */


#ifndef _NGX_RTMP_MPEGTS_H_INCLUDED_
#define _NGX_RTMP_MPEGTS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#define NGX_RTMP_HLS_BUFSIZE            (1024*1024)

typedef struct {
    uint64_t    pts;
    uint64_t    dts;
    ngx_uint_t  pid;
    ngx_uint_t  sid;
    ngx_uint_t  cc;
    unsigned    key:1;
} ngx_rtmp_mpegts_frame_t;


//x_int_t ngx_rtmp_mpegts_write_header(ngx_file_t *file);
ngx_int_t ngx_rtmp_mpegts_write_header(ngx_file_t *file, ngx_uint_t psi_cc);

ngx_int_t ngx_rtmp_mpegts_write_frame(ngx_file_t *file,
          ngx_rtmp_mpegts_frame_t *f, ngx_buf_t *b);
ngx_int_t ngx_rtmp_mpegts_write_frame_buffer(ngx_file_t *file, ngx_rtmp_mpegts_frame_t *f,
          ngx_buf_t *b, u_char* out_buffer, ngx_uint_t* out_size);


#endif /* _NGX_RTMP_MPEGTS_H_INCLUDED_ */
