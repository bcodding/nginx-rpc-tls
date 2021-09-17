/**
 * ngx_stream_rpc_tls_module.c:
 * A TLS offload mechanism for RPC
 * Copyright (C) 2022 Benjamin Coddington <bcodding@redhat.com>
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

typedef struct {
	ngx_flag_t rpc_tls_state;
	ngx_flag_t client;
	ngx_flag_t server;
} ngx_stream_rpc_tls_conf_t;

typedef struct {
	uint32_t		xdr_len;
	uint32_t		xid;
	uint32_t		msg_type;
	uint32_t		rpcvers;
	uint32_t		prog;
	uint32_t		vers;
	uint32_t		proc;
	uint32_t		auth_flavor;
	uint32_t		auth_len;
	uint32_t		verf_flavor;
	uint32_t		verf_len;
	u_char			*pos;
    ngx_pool_t		*pool;
    ngx_log_t		*log;
	unsigned int	sent_auth_tls:1;
	unsigned int	skip_auth_tls:1;
} ngx_stream_rpc_tls_ctx_t;

void
ngx_stream_rpc_tls_server_read_handler(ngx_event_t *rev);
static ngx_int_t
ngx_stream_rpc_tls_client_handler(ngx_stream_session_t *s);
static ngx_int_t
ngx_stream_rpc_tls_server_handler(ngx_stream_session_t *s);
static ngx_int_t
ngx_stream_rpc_tls_init(ngx_conf_t *cf);
static void *
ngx_stream_rpc_tls_create_conf(ngx_conf_t *cf);
static char *
ngx_stream_rpc_tls_merge_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_command_t
ngx_stream_rpc_tls_commands[] = {

    { ngx_string("rpc_tls_server"),
      NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
	  ngx_conf_set_flag_slot,  
      NGX_STREAM_SRV_CONF_OFFSET,
	  offsetof(ngx_stream_rpc_tls_conf_t, server),
      NULL },

    { ngx_string("rpc_tls_client"),
      NGX_STREAM_UPS_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
	  offsetof(ngx_stream_rpc_tls_conf_t, client),
      NULL },

    ngx_null_command
};

static ngx_stream_module_t
ngx_stream_rpc_tls_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_stream_rpc_tls_init,               /* postconfiguration */
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */
    ngx_stream_rpc_tls_create_conf,        /* create server configuration */
    ngx_stream_rpc_tls_merge_conf,         /* merge server configuration */
};

/* Module definition. */
ngx_module_t
ngx_stream_rpc_tls_module = {
    NGX_MODULE_V1,
    &ngx_stream_rpc_tls_module_ctx,		/* module context */
    ngx_stream_rpc_tls_commands,		/* module directives */
    NGX_STREAM_MODULE,				/* module type */
    NULL,					/* init master */
    NULL,					/* init module */
    NULL,					/* init process */
    NULL,					/* init thread */
    NULL,					/* exit thread */
    NULL,					/* exit process */
    NULL,					/* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_stream_rpc_tls_create_conf(ngx_conf_t *cf)
{
	ngx_stream_rpc_tls_conf_t *rtcf;

	rtcf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_rpc_tls_conf_t));
	if (rtcf == NULL)
		return NULL;

	rtcf->client = NGX_CONF_UNSET;
	rtcf->server = NGX_CONF_UNSET;

	return rtcf;
}

static char *
ngx_stream_rpc_tls_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_stream_rpc_tls_conf_t *prev = parent;
	ngx_stream_rpc_tls_conf_t *conf = child;
	ngx_conf_merge_value(conf->client, prev->client, 0);
	ngx_conf_merge_value(conf->server, prev->server, 0);
	/* TODO: make client and server mutually exclusive (backchannel?) */
	return NGX_CONF_OK;
}

static ngx_int_t
ngx_stream_rpc_tls_client_handler(ngx_stream_session_t *s)
{
    ngx_connection_t *c = s->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "ngx_stream_rpc_tls_client_handler begin");
	return NGX_DECLINED;
}

static ngx_int_t
ngx_stream_rpc_tls_read(ngx_stream_session_t *s)
{
	size_t						size;
	ssize_t						n;
    ngx_int_t                   rc = NGX_AGAIN;
    ngx_connection_t			*c;

    c = s->connection;

	ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "nsrt_read()");

	while (rc == NGX_AGAIN) {

		if (c->buffer == NULL) {
			ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "nsrt_read: null buffer");

			/* FIXME: buffer size - from config? */
			c->buffer = ngx_create_temp_buf(c->pool, 16384);
			if (c->buffer == NULL)
				return NGX_ERROR;
		}

        size = c->buffer->end - c->buffer->last;

        if (size == 0) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "nsrt_read: rpc_tls buffer full");
            rc = NGX_STREAM_BAD_REQUEST;
            break;
        }

        if (c->read->eof) {
            rc = NGX_STREAM_OK;
            break;
        }

        if (!c->read->ready) {
            break;
        }

        n = c->recv(c, c->buffer->last, size);

        if (n == NGX_ERROR || n == 0) {
            rc = NGX_STREAM_OK;
            break;
        }

        if (n == NGX_AGAIN)
			break;

        c->buffer->last += n;
	}
	
	if (rc == NGX_AGAIN) {
		ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "nsrt_read: schedule read event handler");
		if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
			ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
			return NGX_OK;
		}

		if (!c->read->timer_set) {
			/* FIXME: get timeout from config?? */
			ngx_add_timer(c->read, 30000);
		}

		c->read->handler = ngx_stream_rpc_tls_server_read_handler;
	}

	return rc;
}

static void xdr_set_quad_word(u_char *p, uint32_t val) {
	*(uint32_t *)p = htonl(val);
}

static uint32_t xdr_get_quad_word(u_char *p)
{
	return (uint32_t)((*p << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}

static ngx_int_t
ngx_stream_rpc_tls_server_parse(ngx_stream_session_t *s, ngx_stream_rpc_tls_ctx_t *ctx)
{
	ngx_connection_t		*c = s->connection;
	ngx_buf_t				*b = c->buffer;
	u_char					*p = b->pos;
	ngx_int_t	i = 0, len;
	ngx_int_t  	debug_p = 0;
	u_char		debug_b[40];
	u_char		reply_buf[40];

	ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "nsrt_server_parse()");

	len = b->last - b->pos;

	if (len < 4) {
		ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "nsrt_server_parse: short buffer, declined");
		return NGX_DECLINED;
	}

	while (i < len) {
		ngx_snprintf(&debug_b[debug_p], 6, "%02xD%02xD ", p[i], p[i+1]);
		i += 2;
		debug_p += 5;

		if (i % 16 == 0) {
			ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "nsrt_server_parse: data: %s", debug_b);
			debug_p = 0;
		}
	}
	debug_b[debug_p] = '\0';

	ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "nsrt_server_parse: data: %s", debug_b);

	/* Record Marker: we only support single-record RPCs */
	if (!(p[0] & 0x80)) {
		ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "nsrt_server_parse: not last frag, set skip_auth_tls");
		ctx->skip_auth_tls = 1;
		return NGX_AGAIN;
	}

	ctx->xdr_len = xdr_get_quad_word(p) & ~(1 << 31);
	len -= 4;
	ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "nsrt_server_parse: xdr_len: %d", ctx->xdr_len);

	/* We need at least 40 bytes for a proper tls probe */
	if (len < 40 || len < ctx->xdr_len)
		return NGX_AGAIN;

	ctx->xid = xdr_get_quad_word(p+=4);
	len -= 4;
//	ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "xid: %04xD", ctx->xid);

	ctx->msg_type = xdr_get_quad_word(p+=4);
	len -= 4;
//	ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "msg_type: %04xD", ctx->msg_type);

	ctx->rpcvers = xdr_get_quad_word(p+=4);
	len -= 4;
//	ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "rpcvers: %04xD", ctx->rpcvers);

	ctx->prog = xdr_get_quad_word(p+=4);
	len -= 4;
//	ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "prog: %d", ctx->prog);

	ctx->vers = xdr_get_quad_word(p+=4);
	len -= 4;
//	ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "vers: %04xD", ctx->vers);

	ctx->proc = xdr_get_quad_word(p+=4);
	len -= 4;
//	ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "proc: %04xD", ctx->proc);

	ctx->auth_flavor = xdr_get_quad_word(p+=4);
	len -= 4;
//	ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "auth_flavor: %04xD", ctx->auth_flavor);

	ctx->auth_len = xdr_get_quad_word(p+=4);
	len -= 4;
//	ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "auth_len: %04xD", ctx->auth_len);

	ctx->verf_flavor = xdr_get_quad_word(p+=4);
	len -= 4;
//	ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "verf_flavor: %04xD", ctx->verf_flavor);

	ctx->verf_len = xdr_get_quad_word(p+=4);
	len -= 4;
//	ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "verf_len: %04xD", ctx->verf_len);

	if (ctx->auth_flavor == 7 && ctx->auth_len == 0 &&
		ctx->verf_flavor == 0 && ctx->verf_len == 0 &&
		len == 0) {
		ctx->sent_auth_tls = 1;
		// this is where you want to do auth_tls
		ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "nsrt_server_parse: set sent_auth_tls muthafucka");

		// we want to reply with reply_stat MSG_ACCEPTED and AUTH_NONE
		// verifier containing STARTTLS:
		p = reply_buf;
		i = 0;

		xdr_set_quad_word(p, 0x80000020);
		p += 4;
		// xid:
		xdr_set_quad_word(p, ctx->xid);
		p += 4;
		// msg_type REPLY:
		xdr_set_quad_word(p, 1);
		p += 4;
		// reply_stat MSG_ACCEPTED:
		xdr_set_quad_word(p, 0);
		p += 4;
		// verfier, flavor AUTH_NONE:
		xdr_set_quad_word(p, 0);
		p += 4;
		// verf_len: 8
		xdr_set_quad_word(p, 0x8);
		p += 4;
		// verf_body:
		ngx_memcpy(p, "STARTTLS", 8);
		p += 8;
		// accept_stat: SUCCESS
		xdr_set_quad_word(p, 0);
		p += 4;

		c->send(c, reply_buf, 36);

		ctx->sent_auth_tls = 1;
	} else
		ctx->skip_auth_tls = 1;

	return NGX_AGAIN;
}

void
ngx_stream_rpc_tls_server_read_handler(ngx_event_t *rev)
{
	ngx_int_t				rc;
	ngx_connection_t		*c;
	ngx_stream_session_t	*s;
	ngx_stream_rpc_tls_ctx_t	*ctx;

	c = rev->data;
	s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "nsrt_server_read_handler()");

	ctx = ngx_stream_get_module_ctx(s, ngx_stream_rpc_tls_module);

	rc = ngx_stream_rpc_tls_read(s);

	size_t 		size = c->buffer->last - c->buffer->pos;
	ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "nsrt_server_read_handler: read returns %d", rc);
	ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0, "nsrt_server_read_handler: buffer pos %p last %p, size %d",
		c->buffer->pos, c->buffer->last, c->buffer->last - c->buffer->pos);

	if (size > 32)
		ctx->skip_auth_tls = 1;

	rc = ngx_stream_rpc_tls_server_parse(s, ctx);

	ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "nsrt_server_read_handler: parse returns %d", rc);

	/* reset things back to the session: */
	c->read->handler = ngx_stream_session_handler;

	ngx_stream_core_run_phases(s);
}

static ngx_int_t
ngx_stream_rpc_tls_server_handler(ngx_stream_session_t *s)
{
    ngx_connection_t *c = s->connection;
	ngx_int_t	rc;
	ngx_stream_rpc_tls_ctx_t	*ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "nsrt_server_handler() v.03");

	/* set up our context */
	ctx = ngx_stream_get_module_ctx(s, ngx_stream_rpc_tls_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_rpc_tls_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_stream_set_ctx(s, ctx, ngx_stream_rpc_tls_module);

        ctx->pool = c->pool;
        ctx->log = c->log;
    }

	/* then we should pass this onto the SSL module */
	if (ctx->sent_auth_tls) {
		// there's gotta be a better way to do this:
		ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "nsrt_server_handler: sent_auth_tls, NGX_DECLINED");
		return NGX_DECLINED;
	}

	/* then we should skip ssl and proxy-only */
	if (ctx->skip_auth_tls) {
		ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "nsrt_server_handler: skip_auth_tls, NGX_OK");
		return NGX_OK;
	}

	rc = ngx_stream_rpc_tls_read(s);

	ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "nsrt_server_handler: read returns %d", rc);
	if (rc == NGX_AGAIN || rc == NGX_OK)
		return rc;

	return NGX_DECLINED;
}

static ngx_int_t
ngx_stream_rpc_tls_init(ngx_conf_t *cf)
{
    /* ngx_stream_srv_conf_t *scf = conf; */
    ngx_stream_handler_pt       *h;
    ngx_stream_core_main_conf_t	*cmcf;
	ngx_stream_rpc_tls_conf_t	*rtcf;

    ngx_log_error(NGX_LOG_DEBUG, cf->log, 0, "ngx_stream_rpc_tls_init push handler");

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    rtcf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_rpc_tls_module);

	if (rtcf->client) {
		ngx_log_debug0(NGX_LOG_DEBUG_STREAM, cf->log, 0, "ngx_stream_rpc_tls setup client handling");
		h = ngx_array_push(&cmcf->phases[NGX_STREAM_SSL_PHASE].handlers);
		if (h == NULL) {
			return NGX_ERROR;
		}

		*h = ngx_stream_rpc_tls_client_handler;
	}

	if (rtcf->server) {
		ngx_log_debug0(NGX_LOG_DEBUG_STREAM, cf->log, 0, "ngx_stream_rpc_tls setup server handling");
		h = ngx_array_push(&cmcf->phases[NGX_STREAM_SSL_PHASE].handlers);
		if (h == NULL) {
			return NGX_ERROR;
		}

		*h = ngx_stream_rpc_tls_server_handler;
	}

    return NGX_OK;
} /* ngx_stream_rpc_tls_init */
