#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    in_addr_t         mask;
    in_addr_t         addr;
    ngx_uint_t        deny;      /* unsigned  deny:1; */
	ngx_table_elt_t   *user_agent;    
	ngx_str_t         brower_string; /* browser key-value */
} ngx_http_access_browser_rule_t;

typedef struct {
    ngx_array_t      *rules;     /* array of ngx_http_access_browser_rule_t */
} ngx_http_access_browser_loc_conf_t;


static ngx_int_t ngx_http_access_browser_init(ngx_conf_t *cf);
static void *ngx_http_access_browser_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_access_browser_rule(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);


static ngx_command_t ngx_http_access_browser_commands[] = {
    { ngx_string("browser_deny"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_access_browser_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

/*
static u_char ngx_access_browser_default_string[] = "Default String: Hello, world!";
*/

static ngx_http_module_t ngx_http_access_browser_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_access_browser_init,           /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_access_browser_create_loc_conf, /* create location configuration */
    NULL                            /* merge location configuration */
};


ngx_module_t ngx_http_access_browser_module = {
    NGX_MODULE_V1,
    &ngx_http_access_browser_module_ctx,    /* module context */
    ngx_http_access_browser_commands,       /* module directives */
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
ngx_http_access_browser_handler(ngx_http_request_t *r)
{
	ngx_uint_t               i;

	ngx_http_access_browser_loc_conf_t	*alcf;
	ngx_http_access_browser_rule_t	    *rule;
	
	alcf = ngx_http_get_module_loc_conf(r, ngx_http_access_browser_module);

	if (!alcf->rules)
	{
		return NGX_DECLINED;
	}
	
    rule = alcf->rules->elts;
	
    for (i = 0; i < alcf->rules->nelts; i++) 
	{
        if (ngx_strstr(r->headers_in.user_agent->value.data, rule[i].brower_string.data)) 
		{
            if (rule[i].deny)
            {
				return NGX_HTTP_FORBIDDEN;
            }
        }
		
		//return NGX_OK; //此阶段OK，进入下一个阶段
    }

    return NGX_DECLINED;  //继续执行此阶段	
}


static void *ngx_http_access_browser_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_access_browser_loc_conf_t* local_conf = NULL;
    local_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_access_browser_loc_conf_t));
    if (local_conf == NULL) 
	{
        return NULL;
    }

    return local_conf;
}


static char *
ngx_http_access_browser_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{

    ngx_http_access_browser_loc_conf_t *alcf = conf;

    ngx_str_t                  *value;
    ngx_http_access_browser_rule_t   *rule;

    value = cf->args->elts;

    if (alcf->rules == NULL) {
        alcf->rules = ngx_array_create(cf->pool, 4,
                                       sizeof(ngx_http_access_browser_rule_t));
        if (alcf->rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(alcf->rules);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

	rule->deny = (0 == ngx_strcmp(value[0].data, "browser_deny")) ? 1 : 0;
	
	//rule->brower_string = value[1]; /* "Trident", "curl" */
	ngx_str_set(&(rule->brower_string), value[1].data);
	
    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_access_browser_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
            return NGX_ERROR;
    }

    *h = ngx_http_access_browser_handler;
	
    return NGX_OK;
}

