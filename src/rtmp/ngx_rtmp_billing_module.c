
#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"

#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_bandwidth.h"
#include "ngx_rtmp_billing_module.h"

static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_play_pt                 next_play;

extern ngx_uint_t ngx_rtmp_publishing;
extern ngx_uint_t ngx_rtmp_playing;

static ngx_int_t ngx_rtmp_billing_postconfiguration(ngx_conf_t *cf);
static void *ngx_rtmp_billing_create_main_conf(ngx_conf_t *cf);
static char *ngx_rtmp_billing_init_main_conf(ngx_conf_t *cf, void *conf);
static void ngx_rtmp_billing_server_r(ngx_rtmp_billing_main_conf_t *bmcf, ngx_rtmp_live_dyn_srv_t *cscf);
static void ngx_rtmp_billing_application_r(ngx_rtmp_billing_main_conf_t *bmcf, ngx_rtmp_live_dyn_app_t *cacf);

static ngx_command_t ngx_rtmp_billing_commands[] = {

    { ngx_string("billing"),
        NGX_RTMP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_RTMP_MAIN_CONF_OFFSET,
        offsetof(ngx_rtmp_billing_main_conf_t, billing),
        NULL },

    { ngx_string("billing_interval"),
        NGX_RTMP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_RTMP_MAIN_CONF_OFFSET,
        offsetof(ngx_rtmp_billing_main_conf_t, billing_interval),
        NULL },

    { ngx_string("billing_path"),
        NGX_RTMP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_RTMP_MAIN_CONF_OFFSET,
        offsetof(ngx_rtmp_billing_main_conf_t, billing_path),
        NULL },
      
      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_billing_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_billing_postconfiguration,     /* postconfiguration */

    ngx_rtmp_billing_create_main_conf,      /* create main configuration */
    ngx_rtmp_billing_init_main_conf,        /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    NULL,                                   /* create app configuration */
    NULL                                    /* merge app configuration */
};


ngx_module_t  ngx_rtmp_billing_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_billing_module_ctx,           /* module context */
    ngx_rtmp_billing_commands,              /* module directives */
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
ngx_rtmp_billing_create_main_conf(ngx_conf_t *cf)
{
    ngx_rtmp_billing_main_conf_t  *bmcf;
    
    bmcf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_billing_main_conf_t));
    if (bmcf == NULL) {
		
        return NULL;
    }

    bmcf->billing = NGX_CONF_UNSET;
    bmcf->billing_interval = NGX_CONF_UNSET_MSEC;
    bmcf->log = &cf->cycle->new_log;
    bmcf->event_file.log = &cf->cycle->new_log;
    bmcf->event_file.fd = NGX_INVALID_FILE;
    bmcf->flow_file.log = &cf->cycle->new_log;
    bmcf->flow_file.fd = NGX_INVALID_FILE;
    bmcf->billing_path.len = 0;

    return bmcf;
}


static char *
ngx_rtmp_billing_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_rtmp_billing_main_conf_t *bmcf = conf;

    ngx_conf_init_value(bmcf->billing, 0);
    ngx_conf_init_msec_value(bmcf->billing_interval, 60 * 1 * 1000);
    if (bmcf->billing_path.len == 0)  {
        ngx_str_set(&bmcf->billing_path, "/data/logs/billing/");
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_billing_ensure_directory(ngx_rtmp_billing_main_conf_t *bmcf)
{
    ngx_file_info_t           fi;
    u_char                    filename[256];

#define NGX_RTMP_BILLING_ENSURE_DIR() \
    do { \
        if (ngx_file_info(filename, &fi) == NGX_FILE_ERROR) { \
            if (ngx_errno != NGX_ENOENT) { \
                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, bmcf->log, ngx_errno, \
                              "billing: " ngx_file_info_n " failed on '%s'", \
                              filename); \
                return NGX_ERROR; \
            } \
            if (ngx_create_full_path(filename, NGX_RTMP_BILLING_DIR_ACCESS) == NGX_FILE_ERROR) { \
                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, ngx_errno, \
                              "billing: " ngx_create_dir_n " failed on '%s'", \
                              filename); \
                return NGX_ERROR; \
            } \
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, bmcf->log, 0, \
                           "billing: directory '%V' created", &bmcf->dir); \
        } else { \
            if (!ngx_is_dir(&fi)) { \
                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, bmcf->log, 0, \
                              "billing: '%s' exists and is not a directory", \
                              filename); \
                return NGX_ERROR; \
            } \
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, bmcf->log, 0, \
                           "billing: directory '%s' exists", filename); \
        } \
    } while(0)

    ngx_memzero(filename, sizeof(filename));
    ngx_memcpy(filename, bmcf->billing_path.data, bmcf->billing_path.len);

    *ngx_cpymem(filename + bmcf->billing_path.len, "tmp/", ngx_strlen("tmp/")) = 0;
    NGX_RTMP_BILLING_ENSURE_DIR();

    *ngx_cpymem(filename + bmcf->billing_path.len, "flow/", ngx_strlen("flow/")) = 0;
    NGX_RTMP_BILLING_ENSURE_DIR();

    *ngx_cpymem(filename + bmcf->billing_path.len, "event/", ngx_strlen("event/")) = 0;
    NGX_RTMP_BILLING_ENSURE_DIR();

#undef NGX_RTMP_BILLING_ENSURE_DIR

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_billing_rename_file(u_char *src, u_char *dst)
{
    /* rename file with overwrite */

#if (NGX_WIN32)
    return MoveFileEx((LPCTSTR) src, (LPCTSTR) dst, MOVEFILE_REPLACE_EXISTING);
#else
    return ngx_rename_file(src, dst);
#endif
}


static ngx_int_t
ngx_rtmp_billing_file_move(ngx_rtmp_billing_main_conf_t *bmcf, ngx_rtmp_core_main_conf_t *cmcf)
{
    if (bmcf == NULL) {

        return NGX_ERROR;
    }

    if (bmcf->event_file.fd != NGX_INVALID_FILE) {
        ngx_close_file(bmcf->event_file.fd);
        bmcf->event_file.fd = NGX_INVALID_FILE;

        if (ngx_rtmp_billing_rename_file(bmcf->event_name_src.data, bmcf->event_name_dst.data)
            == NGX_FILE_ERROR)
        {
            ngx_log_error(NGX_LOG_ERR, bmcf->log, ngx_errno,
                          "billing: rename failed: '%V'->'%V'",
                          &bmcf->event_name_src, &bmcf->event_name_dst);
        } else {

            ngx_log_debug2(NGX_LOG_ERR, bmcf->log, 0,
                          "billing: rename ok: '%V'->'%V'",
                          &bmcf->event_name_src, &bmcf->event_name_dst);
        }
    }

    if (bmcf->flow_file.fd != NGX_INVALID_FILE) {
        ngx_close_file(bmcf->flow_file.fd);
        bmcf->flow_file.fd = NGX_INVALID_FILE;

        if (ngx_rtmp_billing_rename_file(bmcf->flow_name_src.data, bmcf->flow_name_dst.data)
            == NGX_FILE_ERROR)
        {
            ngx_log_error(NGX_LOG_ERR, bmcf->log, ngx_errno,
                          "billing: rename failed: '%V'->'%V'",
                          &bmcf->flow_name_src, &bmcf->flow_name_dst);
        } else {

            ngx_log_debug2(NGX_LOG_ERR, bmcf->log, 0,
                          "billing: rename ok: '%V'->'%V'",
                          &bmcf->flow_name_src, &bmcf->flow_name_dst);
        }
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, bmcf->log, 0, "billing: close file");

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_billing_event_open(ngx_rtmp_billing_main_conf_t *bmcf, ngx_rtmp_core_main_conf_t *cmcf)
{
    ngx_tm_t        tm;
    time_t          now;
    u_char         *p;

    if (ngx_rtmp_billing_ensure_directory(bmcf) != NGX_OK) {

        return NGX_ERROR;
    }

    now = ngx_time();
    ngx_localtime(now, &tm);

    p = ngx_sprintf(bmcf->event_name_src.data + bmcf->billing_path.len + ngx_strlen("tmp/"),
            "%04d-%02d-%02d-%02d%02d-%02d%02d_%d:%d_ksyun_rtmp_event_%d_%d.log",
            tm.ngx_tm_year, tm.ngx_tm_mon, tm.ngx_tm_mday, tm.ngx_tm_hour, (tm.ngx_tm_min / 5) * 5,
			tm.ngx_tm_min >= 55 ? tm.ngx_tm_hour + 1 : tm.ngx_tm_hour, ((tm.ngx_tm_min/5 + 1) * 5) % 60,
			cmcf->cluster_id, cmcf->nginx_id, now, ngx_process_slot);

    *p = 0;

    p = ngx_sprintf(bmcf->event_name_dst.data + bmcf->billing_path.len + ngx_strlen("event/"),
            "%04d-%02d-%02d-%02d%02d-%02d%02d_%d:%d_ksyun_rtmp_event_%d_%d.log",
            tm.ngx_tm_year, tm.ngx_tm_mon, tm.ngx_tm_mday, tm.ngx_tm_hour, (tm.ngx_tm_min / 5) * 5,
			tm.ngx_tm_min >= 55 ? tm.ngx_tm_hour + 1 : tm.ngx_tm_hour, ((tm.ngx_tm_min/5 + 1) * 5) % 60,
			cmcf->cluster_id, cmcf->nginx_id, now, ngx_process_slot);

    *p = 0;

    if (bmcf->event_file.fd == NGX_INVALID_FILE) {

        bmcf->event_file.fd = ngx_open_file(bmcf->event_name_src.data,
                NGX_FILE_WRONLY, NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);
    	if(bmcf->event_file.fd == NGX_INVALID_FILE) {

            ngx_log_error(NGX_LOG_ERR, bmcf->log, ngx_errno, ngx_open_file_n " '%V' failed",
                &bmcf->event_name_src);
    		return NGX_ERROR;
    	}
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_billing_flow_open(ngx_rtmp_billing_main_conf_t *bmcf, ngx_rtmp_core_main_conf_t *cmcf)
{
    ngx_tm_t        tm;
    time_t          now;
    u_char         *p;

    if (ngx_rtmp_billing_ensure_directory(bmcf) != NGX_OK) {

        return NGX_ERROR;
    }

    now = ngx_time();
    ngx_localtime(now, &tm);

    p = ngx_sprintf(bmcf->flow_name_src.data + bmcf->billing_path.len + ngx_strlen("tmp/"),
            "%04d-%02d-%02d-%02d%02d-%02d%02d_%d:%d_ksyun_rtmp_flow_%d_%d.log",
            tm.ngx_tm_year, tm.ngx_tm_mon, tm.ngx_tm_mday, tm.ngx_tm_hour, (tm.ngx_tm_min / 5) * 5,
			tm.ngx_tm_min >= 55 ? tm.ngx_tm_hour + 1 : tm.ngx_tm_hour, ((tm.ngx_tm_min/5 + 1) * 5) % 60,
            cmcf->cluster_id, cmcf->nginx_id, now, ngx_process_slot);

    *p = 0;

    p = ngx_sprintf(bmcf->flow_name_dst.data + bmcf->billing_path.len + ngx_strlen("flow/"),
            "%04d-%02d-%02d-%02d%02d-%02d%02d_%d:%d_ksyun_rtmp_flow_%d_%d.log",
            tm.ngx_tm_year, tm.ngx_tm_mon, tm.ngx_tm_mday, tm.ngx_tm_hour, (tm.ngx_tm_min / 5) * 5,
			tm.ngx_tm_min >= 55 ? tm.ngx_tm_hour + 1 : tm.ngx_tm_hour, ((tm.ngx_tm_min/5 + 1) * 5) % 60,
            cmcf->cluster_id, cmcf->nginx_id, now, ngx_process_slot);

    *p = 0;

    if (bmcf->flow_file.fd == NGX_INVALID_FILE) {

        bmcf->flow_file.fd = ngx_open_file(bmcf->flow_name_src.data,
                NGX_FILE_WRONLY, NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);
        if(bmcf->flow_file.fd == NGX_INVALID_FILE) {

    		ngx_log_error(NGX_LOG_ERR, bmcf->log, ngx_errno, ngx_open_file_n " '%V' failed",
                &bmcf->flow_name_src);

    		return NGX_ERROR;
    	}
    }

    return NGX_OK;
}


static void
ngx_rtmp_billing_live(ngx_rtmp_billing_main_conf_t *bmcf, ngx_rtmp_live_app_conf_t *lacf,  ngx_rtmp_live_dyn_app_t *dyn_app)
{
    ngx_rtmp_core_main_conf_t      *cmcf;
    ngx_rtmp_live_stream_t         *stream = NULL;
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_session_t             *spub;
    ngx_int_t                       n, nplayer, nbuckets;
    ngx_tm_t                        tm;
    u_char 							*p, buffer[1024];
    time_t							now, delay;

    cmcf = ngx_rtmp_core_main_conf;

    ngx_log_debug0(NGX_LOG_INFO, bmcf->log, 0, "billing live");

    if (lacf && !dyn_app) {

        nbuckets = lacf->nbuckets;
    }else if(!lacf && dyn_app) {

        nbuckets = NGX_RTMP_MAX_STREAM_NBUCKET;
    }else{
        return;
    }

#define ngx_rtmp_set_stat_tream(lacf, n) ((lacf)->streams[n])

	for (n = 0; n < nbuckets; ++n) {

	    if (lacf && !dyn_app) {
			
              stream = ngx_rtmp_set_stat_tream(lacf, n);
          }else if(!lacf && dyn_app) {

              stream = ngx_rtmp_set_stat_tream(dyn_app, n);
          }else{

	   }
      
         for (; stream; stream = stream->next) {

         	ctx = stream->ctx;
            spub = ctx->session;
            for (nplayer = 0; ctx; ctx = ctx->next) {

                if (ctx->publishing ||spub->relay_type) {

                    continue;
                }

                ++ nplayer;
            }

            ctx = stream->ctx;

            if (spub == NULL) {

                continue;
            }

			now = ngx_time();
            ngx_localtime(now, &tm);
			delay = ngx_min(now - spub->connect_time, (time_t) bmcf->billing_interval);

			p = ngx_sprintf(buffer, "%04d-%02d-%02d-%02d%02d %V rtmp://%V:%d/%V/%V %V %d %d %l %l %d %d\r\n",
							tm.ngx_tm_year, tm.ngx_tm_mon, tm.ngx_tm_mday, tm.ngx_tm_hour, tm.ngx_tm_min,
							&spub->host_in, 
							&spub->host_in, spub->port_in, &spub->app, &spub->name, 
							&spub->connection->addr_text, 
							now, spub->connect_time,
							stream->bw_billing_in.bytes, stream->bw_billing_out.bytes,
							delay, nplayer); // current connects

			stream->bw_billing_in.bytes = 0;
			stream->bw_billing_out.bytes = 0;

            if (!p) {
                continue;
            }

            *p = 0;

            if (bmcf->flow_file.fd == NGX_INVALID_FILE) {

                if (ngx_rtmp_billing_flow_open(bmcf, cmcf) != NGX_OK) {

                    return;
                }
            }

            ngx_log_debug1(NGX_LOG_INFO, bmcf->log, 0, "billing flow write '%s'", buffer);

	        ngx_write_file(&bmcf->flow_file, buffer, p - buffer, bmcf->flow_file.offset);
	}
	}

	return;
}


ngx_int_t
ngx_rtmp_billing_event_write(ngx_rtmp_session_t *s, char *event, char *pResult, ngx_int_t status)
{
    static const char *g_relay_str[] = {
		"None_relay",
		"Cluster_relay",
		"Remote_relay",
		"Local_relay"
    };

    static const char *g_public_str[] = {
        "Private",
        "Public"
    };

    static const char *g_drm_str[] = {
    	"NDRM",
    	"Drm"
    };

    ngx_rtmp_billing_main_conf_t    *bmcf;
    ngx_rtmp_core_main_conf_t       *cmcf;
    u_char                           log_buf[1024], *p;
    ngx_tm_t                         tm;
    time_t                           now;

    const char *p_relay, *p_public, *p_drm;

    bmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_billing_module);
    if (bmcf == NULL || !bmcf->billing) {

        return NGX_OK;
    }

    cmcf = ngx_rtmp_core_main_conf;

    // if protocol wasn't rtmp then we drop it.
    if(!ngx_rtmp_type(s->protocol)) {

        return NGX_OK;
    }

    if(s->relay_type > NGX_ERROR_RELAY ||
        s->is_public > NGX_RTMP_ERROR_PUBLIC ||
        s->is_drm > NGX_RTMP_ERROR_DRM) {

    	ngx_log_error(NGX_LOG_ERR, bmcf->log, 0, "give up write event because of the relay or public or drm type is no except..");
    	return NGX_ERROR;
    }

	p_relay = g_relay_str[s->relay_type];
	p_public = g_public_str[s->is_public];
	p_drm = g_drm_str[s->is_drm];

    now = ngx_time();
    ngx_localtime(now, &tm);

	p = ngx_sprintf(log_buf, "%04d-%02d-%02d-%02d%02d %p %V %V%s%V %s %d:%d %V %s %d %s %s %s %s %d\r\n",
            tm.ngx_tm_year, tm.ngx_tm_mon, tm.ngx_tm_mday, tm.ngx_tm_hour, tm.ngx_tm_min,
            s, &s->host_in, &s->tc_url, 
            s->name.len == 0 ? "" : "/", &s->name, event,
            cmcf->cluster_id, cmcf->nginx_id,
            &s->connection->addr_text, "-",
            now, p_public, p_drm, p_relay, pResult, status);

	if(!p) {

		return NGX_ERROR;
	}

	*p = 0;

    if (bmcf->event_file.fd == NGX_INVALID_FILE) {

        if (ngx_rtmp_billing_event_open(bmcf, cmcf) != NGX_OK) {

            return NGX_ERROR;
        }
    }

    ngx_log_debug1(NGX_LOG_INFO, bmcf->log, 0, "billing event write '%s'", log_buf);

	ngx_write_file(&bmcf->event_file, log_buf, p - log_buf, bmcf->event_file.offset);

    return NGX_OK;	
}


static void
ngx_rtmp_billing_application(ngx_rtmp_billing_main_conf_t *bmcf, ngx_rtmp_core_app_conf_t *cacf)
{
    ngx_rtmp_billing_live(bmcf, cacf->app_conf[ngx_rtmp_live_module.ctx_index], NULL);

	return;
}


static void
ngx_rtmp_billing_application_r(ngx_rtmp_billing_main_conf_t *bmcf, ngx_rtmp_live_dyn_app_t *cacf)
{

    ngx_rtmp_billing_live(bmcf, NULL, cacf);

    return;
}


static void
ngx_rtmp_billing_server(ngx_rtmp_billing_main_conf_t *bmcf, ngx_rtmp_core_srv_conf_t *cscf)
{
    ngx_uint_t					  n;
    ngx_rtmp_core_app_conf_t    **cacfp;

    cacfp = cscf->applications.elts;
    for (n = 0; n < cscf->applications.nelts; ++n, ++cacfp) {
    
        ngx_rtmp_billing_application(bmcf, *cacfp);
    }

    return;
}


static void
ngx_rtmp_billing_server_r(ngx_rtmp_billing_main_conf_t *bmcf, ngx_rtmp_live_dyn_srv_t *cscf)
{

    ngx_rtmp_live_dyn_app_t    **app_dyn;
    ngx_int_t                              i;
    
    for (i =0; i< NGX_RTMP_MAX_APP_NBUCKET; i++){
    
        app_dyn =  &cscf->apps[i];
        for(; *app_dyn; app_dyn = &(*app_dyn)->next){

            ngx_rtmp_billing_application_r(bmcf, *app_dyn);
        }
    }

    return;
}


static void
ngx_rtmp_billing_flow_write(ngx_event_t *ev)
{
    ngx_rtmp_billing_main_conf_t    *bmcf;
    ngx_rtmp_core_main_conf_t       *cmcf;
    ngx_rtmp_core_srv_conf_t       **pcscf;
    ngx_uint_t                       n;
    ngx_rtmp_live_dyn_srv_t   **srv;
    ngx_int_t                         i;

    bmcf = ev->data;
    cmcf = ngx_rtmp_core_main_conf;

    if (!ngx_rtmp_remote_conf()) {

        pcscf = cmcf->servers.elts;
        for (n = 0; n < cmcf->servers.nelts; ++n, ++pcscf) {

    		ngx_rtmp_billing_server(bmcf, *pcscf);
        }
    } else {

        if (ngx_rtmp_live_main_conf) {
			
            for(i =0; i< NGX_RTMP_MAX_SRV_NBUCKET; i++){
				
                srv = &ngx_rtmp_live_main_conf->srvs[i];
                for (; *srv; srv = &(*srv)->next) {
    
                    if (*srv) {
                        ngx_rtmp_billing_server_r(bmcf, *srv);
                    }
                }
    	     }
        }
        // TO DO..
    }

    ngx_add_timer(&bmcf->billing_evt, bmcf->billing_interval);
}


static void
ngx_rtmp_billing_move(ngx_event_t *ev)
{
    ngx_rtmp_billing_main_conf_t    *bmcf;
    ngx_rtmp_core_main_conf_t       *cmcf;

    bmcf = ev->data;
    cmcf = ngx_rtmp_core_main_conf;

    ngx_log_debug0(NGX_LOG_INFO, bmcf->log, 0, "billing_move");

    ngx_rtmp_billing_file_move(bmcf, cmcf);

    ngx_add_timer(&bmcf->billing_move_evt, bmcf->billing_interval * NGX_RTMP_BILLING_MOVE_TIME_MAX);
}


static ngx_int_t
ngx_rtmp_billing_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_billing_main_conf_t   *bmcf;

    bmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_billing_module);
    if (bmcf == NULL || !bmcf->billing) {
        goto next;
    }

    if (bmcf->billing_evt.timer_set || bmcf->billing_move_evt.timer_set) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                   "billing_publish: name='%s' type='%s' billing_interval='%d'",
                   v->name, v->type, bmcf->billing_interval);

    bmcf->billing_evt.data = bmcf;
    bmcf->billing_evt.log = bmcf->log;
    bmcf->billing_evt.handler = ngx_rtmp_billing_flow_write;

    ngx_add_timer(&bmcf->billing_evt, bmcf->billing_interval);

    bmcf->billing_move_evt.data = bmcf;
    bmcf->billing_move_evt.log = bmcf->log;
    bmcf->billing_move_evt.handler = ngx_rtmp_billing_move;

    ngx_add_timer(&bmcf->billing_move_evt, bmcf->billing_interval * NGX_RTMP_BILLING_MOVE_TIME_MAX);

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_billing_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_billing_main_conf_t   *bmcf;

    bmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_billing_module);
    if (bmcf == NULL || !bmcf->billing) {
        goto next;
    }

    if (bmcf->billing_evt.timer_set || bmcf->billing_move_evt.timer_set) {
        goto next;
    }

    bmcf->billing_evt.data = bmcf;
    bmcf->billing_evt.log = bmcf->log;
    bmcf->billing_evt.handler = ngx_rtmp_billing_flow_write;

    ngx_add_timer(&bmcf->billing_evt, bmcf->billing_interval);

    bmcf->billing_move_evt.data = bmcf;
    bmcf->billing_move_evt.log = bmcf->log;
    bmcf->billing_move_evt.handler = ngx_rtmp_billing_move;

    ngx_add_timer(&bmcf->billing_move_evt, bmcf->billing_interval * NGX_RTMP_BILLING_MOVE_TIME_MAX);

next:
    return next_play(s, v);
}


static ngx_int_t
ngx_rtmp_billing_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_billing_main_conf_t *bmcf;
    u_char                       *p;

    bmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_billing_module);

    if (bmcf->billing_path.data[bmcf->billing_path.len - 1] != '/') {

        p = bmcf->billing_path.data;
        bmcf->billing_path.data = ngx_palloc(cf->pool, bmcf->billing_path.len + 1);
        p = ngx_cpymem(p, bmcf->billing_path.data, bmcf->billing_path.len);
        ++ bmcf->billing_path.len;
        *p = '/';
    }

    bmcf->event_name_dst.len = bmcf->billing_path.len + 6 + 1 + NGX_RTMP_BILLING_NAME_MAX_SIZE; // length 6 means "event/"
    bmcf->event_name_dst.data = ngx_palloc(cf->pool, bmcf->event_name_dst.len);
    p = ngx_cpymem(bmcf->event_name_dst.data, bmcf->billing_path.data, bmcf->billing_path.len);
    p = ngx_cpymem(p, "event/", ngx_strlen("event/"));

    bmcf->event_name_src.len = bmcf->billing_path.len + 4 + 1 + NGX_RTMP_BILLING_NAME_MAX_SIZE;
    bmcf->event_name_src.data = ngx_palloc(cf->pool, bmcf->event_name_src.len);
    p = ngx_cpymem(bmcf->event_name_src.data, bmcf->billing_path.data, bmcf->billing_path.len);
    p = ngx_cpymem(p, "tmp/", ngx_strlen("tmp/"));

    bmcf->flow_name_dst.len = bmcf->billing_path.len + 5 + 1 + NGX_RTMP_BILLING_NAME_MAX_SIZE;  // length 5 means "flow/"
    bmcf->flow_name_dst.data = ngx_palloc(cf->pool, bmcf->flow_name_dst.len);
    p = ngx_cpymem(bmcf->flow_name_dst.data, bmcf->billing_path.data, bmcf->billing_path.len);
    p = ngx_cpymem(p, "flow/", ngx_strlen("flow/"));

    bmcf->flow_name_src.len = bmcf->billing_path.len + 4 + 1 + NGX_RTMP_BILLING_NAME_MAX_SIZE;  // length 4 means "tmp/"
    bmcf->flow_name_src.data = ngx_palloc(cf->pool, bmcf->flow_name_src.len);
    p = ngx_cpymem(bmcf->flow_name_src.data, bmcf->billing_path.data, bmcf->billing_path.len);
    p = ngx_cpymem(p, "tmp/", ngx_strlen("tmp/"));

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_billing_publish;

	next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_billing_play;

    return NGX_OK;
}

