#ifndef _NGX_RTMP_BILLING_MODULE_H_
#define _NGX_RTMP_BILLING_MODULE_H_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_log.h>
#include <ngx_string.h>
#include "ngx_rtmp.h"

#define NGX_RTMP_BILLING_MOVE_TIME_MAX 5
#define NGX_RTMP_BILLING_NAME_MAX_SIZE 256
#define NGX_RTMP_BILLING_DIR_ACCESS    0744


typedef struct {
    ngx_event_t                *ev;     //event of billing interval
    ngx_peer_connection_t      *pc;
    ngx_msec_t                  timeout;
    ngx_uint_t                  bufsize;
    ngx_chain_t                *send_buf;
    ngx_url_t                  *url;
    ngx_log_t                  *log;
    ngx_uint_t                  send_flag;
} ngx_rtmp_billing_session_t;


typedef struct {
	ngx_rtmp_bandwidth_t 		bd_in;
	ngx_rtmp_bandwidth_t		bd_out;
	u_char                      name[128];
} ngx_rtmp_billing_bandwidth_t;


typedef struct {
    ngx_flag_t                  billing;
    ngx_event_t                 billing_evt;
    ngx_event_t                 billing_move_evt;
    ngx_msec_t                  billing_interval;
    ngx_str_t                   billing_path;
    ngx_str_t                   event_name_src;
    ngx_str_t                   event_name_dst;
    ngx_str_t                   flow_name_src;
    ngx_str_t                   flow_name_dst;
    ngx_str_t                   delay_name_src;
    ngx_str_t                   delay_name_des;
    ngx_file_t                  event_file;
    ngx_file_t                  flow_file;
    ngx_file_t                  delay_file;
    ngx_log_t                  *log;
} ngx_rtmp_billing_main_conf_t;


#endif

