#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_LAST_LEVEL_500  508
#define NGX_HTTP_STATUS_CODES_NUM (NGX_HTTP_LAST_LEVEL_500 - NGX_HTTP_OK)

typedef struct {
	ngx_int_t request_cnt;
	ngx_int_t send_bytes;
	ngx_int_t recv_bytes;
	ngx_uint_t status_codes_cnt[NGX_HTTP_STATUS_CODES_NUM];
} ngx_http_traffic_status_rule_t;

typedef struct
{
	ngx_int_t req_flag;     /* request times: 1-enable; 0-disabled  */
	ngx_int_t pkt_flag;     /* packet bytes: 1-enable; 0-disabled  */
	ngx_int_t status_flag;  /*status codes counter: 1-enable; 0-disabled  */	
} ngx_http_traffic_status_local_conf_t;

typedef struct {
    ngx_array_t      *rules;     /* array of ngx_http_traffic_status_rule_t */
} ngx_http_traffic_status_loc_conf_t;

static ngx_int_t ngx_http_traffic_status_init(ngx_conf_t *cf);
static void *ngx_http_traffic_status_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_traffic_status_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static void *ngx_http_traffic_status_create_local_conf(ngx_conf_t *cf);
static char *ngx_http_traffic_status_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t ngx_http_traffic_status_commands[] = {
   {
        ngx_string("traffic_statistics"),
        NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
        ngx_http_traffic_status_set,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    ngx_null_command
};


static ngx_http_module_t ngx_http_traffic_status_module_ctx = {
    NULL,                                      /* preconfiguration */
    ngx_http_traffic_status_init,              /* postconfiguration */
    NULL,                                      /* create main configuration */
    NULL,                                      /* init main configuration */
    ngx_http_traffic_status_create_srv_conf,   /* create server configuration */
    ngx_http_traffic_status_merge_srv_conf,    /* merge server configuration */
    ngx_http_traffic_status_create_local_conf, /* create location configuration */
    NULL                                       /* merge location configuration */
};


ngx_module_t ngx_http_traffic_status_module = {
    NGX_MODULE_V1,
    &ngx_http_traffic_status_module_ctx,    /* module context */
    ngx_http_traffic_status_commands,       /* module directives */
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


static ngx_int_t
ngx_http_traffic_status_handler(ngx_http_request_t *r)
{
    ngx_int_t    rc;
    ngx_buf_t   *b;
    ngx_chain_t  out;
    u_char ngx_traffic_status_string[1024] = {0};
	ngx_uint_t               i;
	ngx_http_traffic_status_rule_t	    *rucf = NULL;
	ngx_http_traffic_status_local_conf_t *local_conf = NULL;
	ngx_int_t offset = 0;

	ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "ngx_http_traffic_status_handler is called!");

    /* we response to 'GET' and 'HEAD' requests only */
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rucf = ngx_http_get_module_srv_conf(r, ngx_http_traffic_status_module);
	if (NULL == rucf) {
		return NGX_ERROR;
	}

	local_conf = ngx_http_get_module_loc_conf(r, ngx_http_traffic_status_module);
	/* not enable */
	if (!(local_conf->req_flag | local_conf->pkt_flag | local_conf->status_flag)) {
		return NGX_HTTP_NOT_ALLOWED;
	}
	
    /* request times calculate */
	if (local_conf->req_flag) {
		ngx_sprintf(ngx_traffic_status_string + offset, "http request times: %d\n",
			rucf->request_cnt);
		offset += ngx_strlen(ngx_traffic_status_string);  
	}

    if (local_conf->pkt_flag) {
	    /* recevie bytes */
		ngx_sprintf(ngx_traffic_status_string + offset, "recevie packet bytes: %d\n",
			rucf->recv_bytes);
		offset += ngx_strlen(ngx_traffic_status_string);  		

	    /* send bytes */
		ngx_sprintf(ngx_traffic_status_string + offset, "send packet bytes: %d\n",
			rucf->send_bytes);
		offset += ngx_strlen(ngx_traffic_status_string);  
    }

	if (local_conf->status_flag) {
		ngx_sprintf(ngx_traffic_status_string + offset, "---- http status ----\n");
		offset += ngx_strlen(ngx_traffic_status_string);  
		
		ngx_sprintf(ngx_traffic_status_string + offset, "---------------------\n");
		offset += ngx_strlen(ngx_traffic_status_string);  			
	    for (i = 0; i < NGX_HTTP_STATUS_CODES_NUM; i++) {
			if (rucf->status_codes_cnt[i] > 0) {
				ngx_sprintf(ngx_traffic_status_string + offset, "%d: %d\n", 
					i + NGX_HTTP_OK, rucf->status_codes_cnt[i]);
				offset += ngx_strlen(ngx_traffic_status_string);  
			}
	    }
		ngx_sprintf(ngx_traffic_status_string + offset, "---------------------\n");
		offset += ngx_strlen(ngx_traffic_status_string);  
	}

    /* discard request body, since we don't need it here */
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    /* set the 'Content-type' header */
    ngx_str_set(&r->headers_out.content_type, "text/html");

    /* send the header only, if the request type is http 'HEAD' */
    if (r->method == NGX_HTTP_HEAD) {
            r->headers_out.status = NGX_HTTP_OK;
            r->headers_out.content_length_n = offset;

            return ngx_http_send_header(r);
    }

    /* allocate a buffer for your response body */
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* attach this buffer to the buffer chain */
    out.buf = b;
    out.next = NULL;

    /* adjust the pointers of the buffer */
    b->pos = ngx_traffic_status_string;
    b->last = ngx_traffic_status_string + offset;
    b->memory = 1;    /* this buffer is in memory */
    b->last_buf = 1;  /* this is the last buffer in the buffer chain */

    /* set the status line */
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = offset;

    /* send the headers of your response */
    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
    }

    /* send the buffer chain of your response */
    return ngx_http_output_filter(r, &out);
}


static void *
ngx_http_traffic_status_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_traffic_status_rule_t *conf = NULL;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_traffic_status_rule_t));

    if (NULL == conf) {
        return NULL;
    }
    return  conf;
}

static char *
ngx_http_traffic_status_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_traffic_status_rule_t	*conf = child;
	ngx_memset(conf, 0, sizeof(ngx_http_traffic_status_rule_t));
	
    return NGX_CONF_OK;
}


static void *
ngx_http_traffic_status_create_local_conf(ngx_conf_t *cf)
{
    ngx_http_traffic_status_local_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_traffic_status_local_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->req_flag = 0;
    conf->pkt_flag = 0;
	conf->status_flag = 0;

    return conf;
}


static char *
ngx_http_traffic_status_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_uint_t    i;
	ngx_str_t    *value;
	ngx_http_core_loc_conf_t  *clcf = NULL;
	ngx_http_traffic_status_local_conf_t *tslc = conf;

	value = cf->args->elts;
	for (i = 1; i < cf->args->nelts; i++)
	{
	    if (ngx_strcasecmp(value[i].data, (u_char *) "request_times") == 0) 
		{
	        tslc->req_flag = 1;
			continue;
	    } 
		else if (ngx_strcasecmp(value[i].data, (u_char *) "packet_bytes") == 0) 
		{
			tslc->pkt_flag = 1;
			continue;
	    } 
		else if (ngx_strcasecmp(value[i].data, (u_char *) "status_codes") == 0) 
		{
			tslc->status_flag = 1;
			continue;
	    } 
		else
		{
	        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				"invalid value \"%s\" in \"%s\" directive",
				value[i].data, cmd->name.data);
        	return NGX_CONF_ERROR;
		}
	}

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_traffic_status_handler;

	return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_status_codes_statistics(ngx_http_request_t *r)
{
	ngx_http_traffic_status_rule_t	    *rucf = NULL;
	rucf = ngx_http_get_module_srv_conf(r, ngx_http_traffic_status_module);

	if (NULL == rucf)
	{
		return NGX_ERROR;
	}
	
	ngx_int_t index = r->headers_out.status;
	if (index >= NGX_HTTP_OK && index < NGX_HTTP_LAST_LEVEL_500)
	{
		++rucf->status_codes_cnt[index - NGX_HTTP_OK];
	}
	/* request times */
	++rucf->request_cnt;

    /* recevie packet bytes */
	rucf->recv_bytes += r->request_length;
	/* send packet bytes */
	rucf->send_bytes += r->connection->sent;
	
	return NGX_HTTP_OK;
}


static ngx_int_t
ngx_http_traffic_status_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) 
	{
    	return NGX_ERROR;
    }

    *h = ngx_http_status_codes_statistics;
	
    return NGX_OK;
}

