
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t
ngx_rtmp_arg(ngx_str_t args, u_char *name, size_t len, ngx_str_t *value)
{
    u_char  *p, *last;

    if (args.len == 0) {
        return NGX_DECLINED;
    }

    p = args.data;
    last = p + args.len;

    for ( /* void */ ; p < last; p++) {

        /* we need '=' after name, so drop one char from last */

        p = ngx_strlcasestrn(p, last - 1, name, len - 1);

        if (p == NULL) {
            return NGX_DECLINED;
        }

        if ((p == args.data || *(p - 1) == '&') && *(p + len) == '=') {

            value->data = p + len + 1;

            p = ngx_strlchr(p, last, '&');

            if (p == NULL) {
                p = args.data + args.len;
            }

            value->len = p - value->data;

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


ngx_int_t
ngx_rtmp_parse_tcurl(ngx_str_t args, ngx_str_t tcurl, ngx_str_t *host_in, ngx_int_t *port_in)
{
    u_char  *port, *slash, *last;

    if (tcurl.len == 0 || !host_in || !port_in) {
        return NGX_DECLINED;
    }

    if (ngx_strncmp(tcurl.data, "rtmp://", 7) == 0) {
        tcurl.data += 7;
        tcurl.len  -= 7;
    } else {
        return NGX_DECLINED;
    }

    last = tcurl.data + tcurl.len;

    slash = ngx_strlchr(tcurl.data, tcurl.data + tcurl.len, '/');
    if (slash != NULL) {
        last = slash;
    }

    port = ngx_strlchr(tcurl.data, last, ':');
    if (port != NULL) {
        *port_in = ngx_atoi(port + 1, last - port - 1);
    }

    if (ngx_rtmp_arg(args, (u_char *)"vhost", 5, host_in) != NGX_OK) {
        host_in->data = tcurl.data;
        host_in->len  = (port ? port : slash) - tcurl.data;
    }

    return NGX_OK;
}

ngx_int_t
ngx_rtmp_parse_host(ngx_pool_t *pool, ngx_str_t hosts, ngx_str_t *host_in, ngx_int_t *port_in)
{
    u_char  *port, *last;

    if (hosts.len == 0 || !host_in || !port_in) {
        return NGX_DECLINED;
    }

    last = hosts.data + hosts.len;

    port = ngx_strlchr(hosts.data, last, ':');
    if (port != NULL) {

        hosts.len = port - hosts.data;

        *port_in = ngx_atoi(port + 1, last - port - 1);
    }

    host_in->len = hosts.len;
    host_in->data = ngx_pstrdup(pool, &hosts);

    return NGX_OK;
}

