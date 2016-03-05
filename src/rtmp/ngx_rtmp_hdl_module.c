
/*
 * Copyright (C) Gino Hu
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_rtmp.h>
#include "ngx_rtmp_init.h"
#include "ngx_rtmp_hdl_module.h"


extern ngx_uint_t ngx_rtmp_playing;

typedef struct {
    ngx_flag_t                          hdl;
} ngx_rtmp_http_hdl_loc_conf_t;


static ngx_int_t ngx_rtmp_hdl_send_message(ngx_rtmp_session_t *s, ngx_chain_t *out, ngx_uint_t priority);
static ngx_int_t ngx_rtmp_http_hdl_handler(ngx_http_request_t *r);
static ngx_int_t ngx_rtmp_http_hdl_init(ngx_conf_t *cf);
static void * ngx_rtmp_http_hdl_create_conf(ngx_conf_t *cf);
static char * ngx_rtmp_http_hdl_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_rtmp_hdl_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_hdl_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_hdl_merge_app_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_rtmp_http_hdl_get_info(ngx_str_t *uri, ngx_str_t *app, ngx_str_t *name);
static ngx_int_t ngx_rtmp_http_hdl_close_keepalived(ngx_http_request_t *r);
static void ngx_rtmp_http_hdl_close_connection(ngx_connection_t *c);
static ngx_int_t ngx_rtmp_http_hdl_connect_local(ngx_http_request_t *r, ngx_str_t *app, ngx_str_t *name, ngx_int_t protocol);
static ngx_rtmp_session_t *ngx_rtmp_http_hdl_init_session(ngx_connection_t *c, ngx_rtmp_addr_conf_t *addr_conf);
static ngx_int_t ngx_rtmp_http_hdl_init_connection(ngx_http_request_t *r, ngx_rtmp_conf_port_t *cf_port);
static ngx_int_t ngx_rtmp_hdl_connect_done(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_hdl_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_hdl_play_done(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, ngx_chain_t *in);


static ngx_command_t  ngx_rtmp_http_hdl_commands[] = {

    { ngx_string("hdl"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_rtmp_http_hdl_loc_conf_t, hdl),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_rtmp_http_hdl_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_rtmp_http_hdl_init,        /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_rtmp_http_hdl_create_conf, /* create location configuration */
    ngx_rtmp_http_hdl_merge_conf   /* merge location configuration */
};


ngx_module_t  ngx_rtmp_http_hdl_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_http_hdl_module_ctx, /* module context */
    ngx_rtmp_http_hdl_commands,    /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_command_t ngx_rtmp_hdl_commands[] = {

    { ngx_string("hdl"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hdl_app_conf_t, hdl),
      NULL },

    ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_hdl_module_ctx = {
    NULL,                               /* preconfiguration */
    ngx_rtmp_hdl_postconfiguration,     /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_rtmp_hdl_create_app_conf,       /* create application configuration */
    ngx_rtmp_hdl_merge_app_conf,        /* merge application configuration */
};


ngx_module_t  ngx_rtmp_hdl_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_hdl_module_ctx,           /* module context */
    ngx_rtmp_hdl_commands,              /* module directives */
    NGX_RTMP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_rtmp_hdl_send_message(ngx_rtmp_session_t *s, ngx_chain_t *out,
        ngx_uint_t priority)
{
    ngx_uint_t                      nmsg;

    if (!ngx_hdl_type(s->protocol)) {

        ngx_rtmp_acquire_shared_chain(out);
        return NGX_OK;
    }

    nmsg = (s->out_last - s->out_pos) % s->out_queue + 1;

    if (priority > 3) {
        priority = 3;
    }

    /* drop packet?
     * Note we always leave 1 slot free */
    if (nmsg + priority * s->out_queue / 4 >= s->out_queue) {
    /*
        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "RTMP drop message bufs=%ui, priority=%ui",
                nmsg, priority);
    */
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "RTMP drop message bufs=%ui, priority=%ui, s->out_last=%d, s->out_pos=%d, s->out_queue=%d ",
            nmsg, priority, s->out_last, s->out_pos, s->out_queue);
        return NGX_AGAIN;
    }

    s->out[s->out_last++] = out;
    s->out_last %= s->out_queue;

    ngx_rtmp_acquire_shared_chain(out);

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "RTMP send nmsg=%ui, priority=%ui #%ui",
            nmsg, priority, s->out_last);

    if (priority && s->out_buffer && nmsg < s->out_cork) {
        return NGX_OK;
    }

    if (!s->connection->write->active) {

        ngx_rtmp_send(s->connection->write);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_http_hdl_get_info(ngx_str_t *uri, ngx_str_t *app, ngx_str_t *name)
{
    size_t    len;

    if (uri == NULL || uri->len == 0) {

        return NGX_ERROR;
    }

    len = 0;
    for(; uri->data[len] == '/' || uri->len == len; ++ len); // skip first '/'

    app->data = &uri->data[len];                             // we got app

    for(; uri->data[len] != '/' || uri->len == len; ++ len); // reach next '/'

    app->len  = &uri->data[len ++] - app->data;
    name->data = &uri->data[len];                            // we got name

    for(; uri->data[len] != '.' || uri->len == len; ++ len); // reach '.'

    name->len  = &uri->data[len] - name->data;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_http_hdl_close_keepalived(ngx_http_request_t *r)
{
	ngx_rtmp_session_t          *s;

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "hdl close keepalived");

	s = r->connection->http_data;
	s->r = NULL;

	return NGX_OK;
}


static ngx_int_t
ngx_rtmp_http_hdl_play_local(ngx_http_request_t *r)
{
    static ngx_rtmp_play_t      v;

	ngx_rtmp_session_t         *s;
    ngx_rtmp_hdl_ctx_t         *ctx;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_core_app_conf_t   *cacf;

	s = r->connection->http_data;

	ngx_memzero(&v, sizeof(ngx_rtmp_play_t));

    ngx_memcpy(v.name, s->name.data, s->name.len);
    ngx_memcpy(v.args, s->args.data, s->args.len);

    s->rtmp_stream_status = NGX_RTMP_STREAM_STATUS_PLAY;

    if (!ngx_rtmp_remote_conf()) {

        if (ngx_rtmp_cmd_get_core_srv_conf(s, NGX_RTMP_CMD_HDL_PLAY, &s->host_in, &s->app, &cscf, &cacf) != NGX_OK) {

            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "hdl_play: forbidden");
            return NGX_ERROR;
        }
    } else {

        cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    }

    if (!ngx_rtmp_remote_conf()) {

        s->app_conf = cacf->app_conf;
        s->unique_name = cscf->unique_name;
    } else {

        s->app_conf = cscf->ctx->app_conf;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hdl_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_hdl_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_hdl_module);
    }

	return ngx_rtmp_cmd_start_play(s, &v);
}


static void
ngx_rtmp_http_hdl_close_connection(ngx_connection_t *c)
{
	ngx_rtmp_session_t		   *s;
	ngx_rtmp_core_srv_conf_t   *cscf;
	ngx_rtmp_hdl_ctx_t         *ctx;

	s = c->http_data;
	c = s->connection;

	cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
	ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hdl_module);

    ngx_log_error(NGX_LOG_ERR, c->log, 0, "hdl close connection");

    ngx_rtmp_fire_event(s, NGX_RTMP_DISCONNECT, NULL, NULL);

    if (s->ping_evt.timer_set) {
        ngx_del_timer(&s->ping_evt);
    }

    while (s->out_pos != s->out_last) {
        ngx_rtmp_free_shared_chain(cscf, s->out[s->out_pos++]);
        s->out_pos %= s->out_queue;
    }
}


static ngx_int_t
ngx_rtmp_http_hdl_connect_local(ngx_http_request_t *r, ngx_str_t *app, ngx_str_t *name, ngx_int_t protocol)
{
	static ngx_rtmp_connect_t   v;

	ngx_rtmp_session_t         *s;
    ngx_connection_t           *c;
    ngx_rtmp_hdl_ctx_t         *ctx;

	s = r->connection->http_data;
    c = r->connection;

	ngx_memzero(&v, sizeof(ngx_rtmp_connect_t));

    ngx_memcpy(v.app, app->data, app->len);
    ngx_memcpy(v.args, r->args.data, r->args.len);
    ngx_memcpy(v.flashver, "HDL flashver", ngx_strlen("HDL flashver"));
    ngx_memcpy(v.swf_url, "HDL swf_url", ngx_strlen("HDL swf_url"));
    ngx_memcpy(v.tc_url, "HDL tc_url", ngx_strlen("HDL tc_url"));
    ngx_memcpy(v.page_url, "HDL page_url", ngx_strlen("HDL page_url"));

    ngx_str_set(&s->host_in, "default_host");
    s->port_in = 8080;

    NGX_RTMP_SET_STRPAR(app);
    NGX_RTMP_SET_STRPAR(args);
    NGX_RTMP_SET_STRPAR(flashver);
    NGX_RTMP_SET_STRPAR(swf_url);
    NGX_RTMP_SET_STRPAR(tc_url);
    NGX_RTMP_SET_STRPAR(page_url);

    ngx_rtmp_parse_host(c->pool, r->headers_in.host->value, &s->host_in, &s->port_in);

    ngx_http_arg(r, (u_char*)"vhost", 5, &s->host_in);

    s->name.len = name->len;
    s->name.data = ngx_pstrdup(s->connection->pool, name);

    s->rtmp_stream_status = NGX_RTMP_STREAM_STATUS_CONNECT;
    c->protocol = s->protocol = protocol;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hdl_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_hdl_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_hdl_module);
    }

	return ngx_rtmp_cmd_start_connect(s, &v);
}


static ngx_rtmp_session_t *
ngx_rtmp_http_hdl_init_session(ngx_connection_t *c, ngx_rtmp_addr_conf_t *addr_conf)
{
	ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_core_main_conf_t      *cmcf;
    ngx_rtmp_session_t             *s;

    s = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_session_t) +
            sizeof(ngx_chain_t *) * ((ngx_rtmp_core_srv_conf_t *)
                addr_conf->ctx->srv_conf[ngx_rtmp_core_module
                    .ctx_index])->out_queue);
    if (s == NULL) {
		ngx_rtmp_close_connection(c);
        return NULL;
    }

	s->addr_conf = addr_conf;

	s->main_conf = addr_conf->ctx->main_conf;
    s->srv_conf = addr_conf->ctx->srv_conf;

	s->addr_text = &addr_conf->addr_text;

    c->http_data = s;
	s->connection = c;
	c->rtmp_closer = ngx_rtmp_http_hdl_close_connection;

    s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (s->ctx == NULL) {
        ngx_rtmp_close_connection(c);
        return NULL;
    }

	cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    s->out_queue = cscf->out_queue;
    s->out_cork = cscf->out_cork;
    s->in_streams = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_stream_t)
            * cscf->max_streams);
    if (s->in_streams == NULL) {
        ngx_rtmp_close_connection(c);
        return NULL;
    }

	s->epoch = ngx_current_msec;
	s->timeout = cscf->timeout;
	s->buflen = cscf->buflen;
	ngx_rtmp_set_chunk_size(s, NGX_RTMP_DEFAULT_CHUNK_SIZE);

	if (ngx_rtmp_fire_event(s, NGX_RTMP_CONNECT, NULL, NULL) != NGX_OK) {
        ngx_rtmp_finalize_session(s);
        return NULL;
    }

    /** to init the session event'log **/
	cmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_core_module );
    s->connect_time = ngx_time();  // record the start time
	s->is_drm 		= NGX_RTMP_STREAM_NDRM;
	s->is_public	= NGX_RTMP_STREAM_PRIVATE;

    return s;
}


static ngx_int_t
ngx_rtmp_http_hdl_init_connection(ngx_http_request_t *r, ngx_rtmp_conf_port_t *cf_port)
{
	ngx_uint_t             i;
	ngx_rtmp_port_t       *port;
    ngx_rtmp_session_t    *s;
	ngx_rtmp_addr_conf_t  *addr_conf;
	ngx_connection_t      *c;
	struct sockaddr       *sa;
	struct sockaddr_in    *sin;
    ngx_rtmp_in_addr_t    *addr;
	ngx_int_t              unix_socket;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6   *sin6;
    ngx_rtmp_in6_addr_t   *addr6;
#endif

	c = r->connection;

	++ngx_rtmp_hls_naccepted;

	port = cf_port->ports.elts;
    unix_socket = 0;

    if (port->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() already gave this address.
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_rtmp_close_connection(c);
            return NGX_ERROR;
        }

        sa = c->local_sockaddr;

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sa;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            addr_conf = &addr6[i].conf;

            break;
#endif

        case AF_UNIX:
            unix_socket = 1;

        default: /* AF_INET */
            sin = (struct sockaddr_in *) sa;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            addr_conf = &addr[i].conf;

            break;
        }

    } else {
        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            addr_conf = &addr6[0].conf;
            break;
#endif

        case AF_UNIX:
            unix_socket = 1;

        default: /* AF_INET */
            addr = port->addrs;
            addr_conf = &addr[0].conf;
            break;
        }
    }

	ngx_log_error(NGX_LOG_INFO, c->log, 0, "hdl client connected '%V'", &c->addr_text);

    s = ngx_rtmp_http_hdl_init_session(c, addr_conf);
    if (s == NULL) {
        return NGX_ERROR;
    }

	r->read_event_handler = ngx_http_test_reading;
	r->keepalived_handler = ngx_rtmp_http_hdl_close_keepalived;

    c->write->handler = ngx_rtmp_send;
	c->read->handler = ngx_rtmp_recv;

	s->auto_pushed = unix_socket;

    s = r->connection->http_data;
	s->r = r;

	return NGX_OK;
}


static ngx_int_t
ngx_rtmp_http_hdl_handler(ngx_http_request_t *r)
{
    ngx_rtmp_http_hdl_loc_conf_t        *hlcf;
    ngx_rtmp_core_main_conf_t           *cmcf;
	ngx_rtmp_conf_port_t                *port;
	ngx_rtmp_session_t                  *s;
	ngx_int_t                            protocol, rc = 0;
	ngx_str_t                            app, name;
    ngx_int_t                            nslash;
    size_t                               i;

    cmcf = ngx_rtmp_core_main_conf;
    if (cmcf == NULL || cmcf->ports.nelts == 0) {
        return NGX_ERROR;
    }

	hlcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_http_hdl_module);
	if (hlcf == NULL || !hlcf->hdl) {
		return NGX_DECLINED;
	}

	if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/' &&
		r->uri.len > ngx_strlen(".flv")) {
        return NGX_DECLINED;
    }

    nslash = 0;
    for (i = 0; i < r->uri.len; ++ i) {

        if (r->uri.data[i] == '/') {

            ++ nslash;
        } else if (r->uri.data[i] == '?') {

            break;
        }
    }

    if (nslash != 2) {

        return NGX_DECLINED;
    }

	if (r->uri.data[r->uri.len - 1] == 'v' &&
		r->uri.data[r->uri.len - 2] == 'l' &&
		r->uri.data[r->uri.len - 3] == 'f' &&
		r->uri.data[r->uri.len - 4] == '.') {
		protocol = NGX_RTMP_PULL_TYPE_HDL;
	} else {
		return NGX_DECLINED;
	}

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
              "http_hdl handle uri: '%V' args: '%V'", &r->uri, &r->args);

    if (ngx_rtmp_http_hdl_get_info(&r->uri, &app, &name) != NGX_OK) {

        return NGX_DECLINED;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
              "http_hdl handle app: '%V' name: '%V'", &app, &name);

	s = r->connection->http_data;
	if (s != NULL) {

		r->read_event_handler = ngx_http_test_reading;
		r->keepalived_handler = ngx_rtmp_http_hdl_close_keepalived;
		s->r = r;

		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "http_hdl handle keep-alived request");

        if (ngx_rtmp_http_hdl_play_local(r) != NGX_OK) {

            return NGX_DECLINED;
        }
	} else {

        port = cmcf->ports.elts;

        if (ngx_rtmp_http_hdl_init_connection(r, &port[0]) != NGX_OK) {

            return NGX_DECLINED;
        }

        ngx_rtmp_http_hdl_connect_local(r, &app, &name, protocol);
	}

	return NGX_CUSTOME;
}


static ngx_int_t
ngx_rtmp_http_hdl_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_rtmp_http_hdl_handler;

    return NGX_OK;
}


static void *
ngx_rtmp_http_hdl_create_conf(ngx_conf_t *cf)
{
    ngx_rtmp_http_hdl_loc_conf_t  *hlcf;

    hlcf = ngx_palloc(cf->pool, sizeof(ngx_rtmp_http_hdl_loc_conf_t));
    if (hlcf == NULL) {
        return NULL;
    }

    hlcf->hdl = NGX_CONF_UNSET;

    return hlcf;
}


static char *
ngx_rtmp_http_hdl_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_http_hdl_loc_conf_t *prev = parent;
    ngx_rtmp_http_hdl_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->hdl, prev->hdl, 0);

    return NGX_CONF_OK;
}


static void *
ngx_rtmp_hdl_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_hdl_app_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_hdl_app_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->hdl = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_rtmp_hdl_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_hdl_app_conf_t    *prev = parent;
    ngx_rtmp_hdl_app_conf_t    *conf = child;

    ngx_conf_merge_value(conf->hdl, prev->hdl, 0);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_hdl_connect_done(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
    ngx_http_request_t             *r;

    if (!ngx_hdl_pull_type(s->protocol)) {

        return NGX_OK;
    }

    r = s->r;

    return ngx_rtmp_http_hdl_play_local(r);
}


static ngx_chain_t *
ngx_rtmp_hdl_append_tag_bufs(ngx_rtmp_session_t *s, ngx_chain_t *tag,
    ngx_rtmp_header_t *ch, uint32_t epoch)
{
    ngx_chain_t                    *tail, *head, *taghead, prepkt;
    ngx_buf_t                       prebuf;
    uint32_t                        presize, presizebuf;
    u_char                         *p, *ph;
    uint32_t                        timestamp;
    ngx_rtmp_core_srv_conf_t       *cscf;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ngx_memzero(&prebuf, sizeof(prebuf));
    prebuf.start = prebuf.pos = (u_char*)&presizebuf;
    prebuf.end   = prebuf.last = (u_char*)(((u_char*)&presizebuf) + sizeof(presizebuf));
    prepkt.buf   = &prebuf;
    prepkt.next  = NULL;

    timestamp = ch->timestamp - epoch;
    head = tag;
    tail = tag;   
    taghead = NULL;

    for (presize = 0, tail = tag; tag; tail = tag, tag = tag->next) {
        presize += (tag->buf->last - tag->buf->pos);
    }

    presize += NGX_RTMP_MAX_FLV_TAG_HEADER;

    ph = (u_char*)&presizebuf;
    p  = (u_char*)&presize;

    *ph++ = p[3];
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];

    /* Link chain of PreviousTagSize after the last packet. */
    tail->next = &prepkt;

    taghead = ngx_rtmp_append_shared_bufs(cscf, NULL, head);

    tail->next = NULL;
    presize -= NGX_RTMP_MAX_FLV_TAG_HEADER;

    /* tag header */
    taghead->buf->pos -= NGX_RTMP_MAX_FLV_TAG_HEADER;
    ph = taghead->buf->pos;

    *ph++ = (u_char)ch->type;

    p = (u_char*)&presize;
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

    return taghead;
}


static void
ngx_rtmp_hdl_gop_cache_send(ngx_rtmp_session_t *ss)
{
    ngx_rtmp_session_t             *s;
    ngx_chain_t                    *pkt, *apkt, *mpkt, *meta, *header;
    ngx_rtmp_live_ctx_t            *pctx, *publisher, *player;
    ngx_rtmp_hdl_ctx_t             *hctx;
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

    hctx = ngx_rtmp_get_module_ctx(ss, ngx_rtmp_hdl_module);
    if (hctx == NULL) {
        return;
    }

    if (!ngx_hdl_pull_type(ss->protocol)) {
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
    mpkt = NULL;
    header = NULL;
    meta = NULL;
    meta_version = 0;

    ngx_memzero(&ch, sizeof(ch));

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

        ch.type = NGX_RTMP_MSG_AMF_META;
        ch.timestamp = 0;

        mpkt = ngx_rtmp_hdl_append_tag_bufs(ss, meta, &ch, 0);

        if (ngx_rtmp_hdl_send_message(ss, mpkt, 0) == NGX_OK) {
            player->meta_version = meta_version;
        }

        if (mpkt) {
            ngx_rtmp_free_shared_chain(cscf, mpkt);
        }
    }

    for (cache = publisher->gop_cache; cache; cache = cache->next) {

        csidx = !(lacf->interleave || cache->h.type == NGX_RTMP_MSG_VIDEO);

        cs = &player->cs[csidx];

        lh = ch = cache->h;

        if (cs->active) {

            lh.timestamp = cs->timestamp;
        }

        if (!hctx->initialized) {

            hctx->initialized = 1;
            hctx->epoch = ch.timestamp;
        }

        delta = ch.timestamp - lh.timestamp;

        if (!cs->active) {

            header = cache->h.type == NGX_RTMP_MSG_VIDEO ? codec_ctx->avc_header : codec_ctx->aac_header;
            if (header) {

                apkt = ngx_rtmp_hdl_append_tag_bufs(s, header, &ch, hctx->epoch);
            }

            if (ngx_rtmp_hdl_send_message(ss, apkt, cache->prio) != NGX_OK) {

                return;
            }

            cs->timestamp = lh.timestamp;
            cs->active = 1;
            ss->current_time = cs->timestamp;
        }

        pkt = ngx_rtmp_hdl_append_tag_bufs(s, cache->frame, &ch, hctx->epoch);

        if (ngx_rtmp_hdl_send_message(ss, pkt, 0) != NGX_OK) {
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
ngx_rtmp_hdl_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                 ngx_chain_t *in)
{
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_hdl_app_conf_t        *hacf;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_hdl_ctx_t             *hctx;
    ngx_rtmp_live_ctx_t            *ctx, *pctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx = NULL;
    ngx_rtmp_header_t               ch, lh, hch;
    ngx_rtmp_session_t             *ss;
    ngx_int_t                       rc;
    ngx_uint_t                      csidx;
    ngx_uint_t                      prio;
    ngx_uint_t                      meta_version;
    ngx_chain_t                    *header, *fpkt, *apkt, *mpkt, *meta;
    ngx_rtmp_live_chunk_stream_t   *cs;
    uint32_t                        delta = 0;
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

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hdl_module);
    if (hacf == NULL) {
        return NGX_ERROR;
    }

    if (!ngx_rtmp_get_attr_conf(hacf, hdl)) {
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
                       "live_hdl: %s from non-publisher", type_s);
        return NGX_OK;
    }

    apkt = NULL;
    fpkt = NULL;
    mpkt = NULL;
    header = NULL;
    meta = NULL;
    meta_version = 0;

    prio = (h->type == NGX_RTMP_MSG_VIDEO ?
            ngx_rtmp_get_video_frame_type(in) : 0);

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    csidx = !(lacf->interleave || h->type == NGX_RTMP_MSG_VIDEO);

    cs = &ctx->cs[csidx];

    ngx_memzero(&ch, sizeof(ch));
    ngx_memzero(&hch, sizeof(hch));

    ch.timestamp = h->timestamp;
    ch.msid = NGX_RTMP_MSID;
    ch.csid = cs->csid;
    ch.type = h->type;

    lh = ch;

    if (cs->active) {
        lh.timestamp = cs->timestamp;
    }

    delta = ch.timestamp - lh.timestamp;

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (codec_ctx) {

        if (h->type == NGX_RTMP_MSG_AUDIO) {
            header = codec_ctx->aac_header;

            if (codec_ctx->audio_codec_id == NGX_RTMP_AUDIO_AAC &&
                ngx_rtmp_is_codec_header(in)) // is or not audio header
            {
                prio = 0;
            }

        } else {
            header = codec_ctx->avc_header;

            if (codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H264 &&
                ngx_rtmp_is_codec_header(in)) // is or not video header
            {
                prio = 0;
            }
        }

        if (codec_ctx->meta) {
            meta = codec_ctx->meta;
            meta_version = codec_ctx->meta_version;
        }
    }

    /* broadcast to all subscribers */

    for (pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
        if (pctx == ctx || pctx->paused) {
            continue;
        }

        ss = pctx->session;
        cs = &pctx->cs[csidx];

        hctx = ngx_rtmp_get_module_ctx(ss, ngx_rtmp_hdl_module);
        if (hctx == NULL) {
            continue;
        }

        if (!ngx_hdl_pull_type(ss->protocol)) {
            continue;
        }

        if (!hctx->initialized) {

            hctx->initialized = 1;
            hctx->epoch = ch.timestamp;
        }

        /* send metadata */

        if (meta && meta_version != pctx->meta_version) {
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                           "live_hdl: meta");

            hch.type = NGX_RTMP_MSG_AMF_META;
            hch.timestamp = 0;

            mpkt = ngx_rtmp_hdl_append_tag_bufs(ss, meta, &hch, 0);

            if (ngx_rtmp_hdl_send_message(ss, mpkt, 0) == NGX_OK) {
                pctx->meta_version = meta_version;
            }

            if (mpkt) {
                ngx_rtmp_free_shared_chain(cscf, mpkt);
            }
        }

        /* sync stream */

        if (cs->active && (lacf->sync && cs->dropped > lacf->sync)) {
            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                           "live_hdl: sync %s dropped=%uD", type_s, cs->dropped);

            cs->active = 0;
            cs->dropped = 0;
        }

        /* absolute packet */

        if (!cs->active) {

            if (lacf->wait_video && h->type == NGX_RTMP_MSG_AUDIO &&
				!pctx->cs[0].active)
            {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live_hdl: waiting for video");
                continue;
            }

            if (lacf->wait_key && prio != NGX_RTMP_VIDEO_KEY_FRAME &&
               (lacf->interleave || h->type == NGX_RTMP_MSG_VIDEO))
            {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live_hdl: skip non-key");
                continue;
            }

            if (header) {

                /* send absolute codec header */

                ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live_hdl: abs %s header timestamp=%uD",
                               type_s, lh.timestamp);

                if (header) {
                    if (apkt == NULL) {
                        apkt = ngx_rtmp_hdl_append_tag_bufs(s, header, &ch, hctx->epoch);
                    }

                    rc = ngx_rtmp_hdl_send_message(ss, apkt, 0);
                    if (rc != NGX_OK) {
                        continue;
                    }
                }

                cs->timestamp = lh.timestamp;
                cs->active = 1;
                ss->current_time = cs->timestamp;
            }
        }

        fpkt = ngx_rtmp_hdl_append_tag_bufs(s, in, &ch, hctx->epoch);

        /* send relative packet */

        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                       "live_hdl: rel %s packet delta=%uD",
                       type_s, delta);

        if (ngx_rtmp_hdl_send_message(ss, fpkt, prio) != NGX_OK) {
            ++pctx->ndropped;

            cs->dropped += delta;

            continue;
        }

        cs->timestamp += delta;
        ss->current_time = cs->timestamp;

        if (apkt) {
            ngx_rtmp_free_shared_chain(cscf, apkt);
            apkt = NULL;
        }

        if (fpkt) {
            ngx_rtmp_free_shared_chain(cscf, fpkt);
            fpkt = NULL;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hdl_play_done(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
    static u_char httpheader[] = {
        "HTTP/1.1 200 OK\r\n"
        "Cache-Control: no-cache\r\n"
        "Content-Type: video/x-flv\r\n"
        "Expires: -1\r\n"
        "Pragma: no-cache\r\n"
        "\r\n"
    };

    static u_char flvheader[] = {
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

    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_hdl_app_conf_t        *lacf;
    ngx_chain_t                     c1, c2, *pkt;
    ngx_buf_t                       b1, b2;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hdl_module);
    if (lacf == NULL) {
        return NGX_OK;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (!ngx_rtmp_get_attr_conf(lacf, hdl)) {
        return NGX_OK;
    }

    if (!ngx_hdl_pull_type(s->protocol)) {
        return NGX_OK;
    }

    c1.buf = &b1;
    c2.buf = &b2;
    c1.next = &c2;
    c2.next = NULL;

    b1.start = b1.pos = &httpheader[0];
    b1.end = b1.last = b1.pos + sizeof(httpheader) - 1;

    b2.start = b2.pos = &flvheader[0];
    b2.end = b2.last = b2.pos + sizeof(flvheader);

    pkt = ngx_rtmp_append_shared_bufs(cscf, NULL, &c1);

    ngx_rtmp_hdl_send_message(s, pkt, 0);

    ngx_rtmp_free_shared_chain(cscf, pkt);

    ngx_rtmp_hdl_gop_cache_send(s);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_hdl_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t   *cmcf;
    ngx_rtmp_handler_pt         *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    /* register raw event handlers */

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_hdl_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_hdl_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_CONNECT_DONE]);
    *h = ngx_rtmp_hdl_connect_done;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_PLAY_DONE]);
    *h = ngx_rtmp_hdl_play_done;

    return NGX_OK;
}

