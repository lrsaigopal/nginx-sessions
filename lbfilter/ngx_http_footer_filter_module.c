
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_thread.h>
#include <ngx_regex.h>

#include "uthash.h" //hashmap


static ngx_int_t ngx_http_footer_filter_init(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_footer_filter_module_ctx = {
    NULL,                               /* proconfiguration */
    ngx_http_footer_filter_init,        /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    NULL,    /* create location configuration */
    NULL      /* merge location configuration */
};


ngx_module_t  ngx_http_footer_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_footer_filter_module_ctx, /* module context */
    NULL,                               /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


/* session mapping hash struct */
typedef struct {
    u_char* id;                    /* key */
    int selected_peer;
    time_t reg_time;
    UT_hash_handle hh;         /* makes this structure hashable */
} session_map;

typedef struct {
    ngx_str_t                     *domain;
    ngx_str_t                     *name;
    session_map                   **map;
    ngx_uint_t                    selected_peer;
    time_t                        expiry_limit;
    time_t                       *last_cleaned;

} ngx_http_sticky_ctx;


ngx_module_t ngx_http_sticky_module;

static ngx_http_output_body_filter_pt   ngx_http_next_body_filter;




void add_mapping(u_char *tmp_id, size_t len, int selected_peer, time_t reg_time, session_map** map_ptr)
{
    session_map *s, *map = *map_ptr;
    u_char* mapping_id = (u_char*)malloc(sizeof(u_char) * len + 1);
    *(ngx_copy(mapping_id, tmp_id, len)) = 0;
    HASH_FIND(hh, map, mapping_id, len, s);  // dont add again
    if (s==NULL) {
        s = (session_map*)malloc(sizeof(session_map));
        s->id = mapping_id;
        s->selected_peer =  selected_peer;
        s->reg_time = reg_time;
        HASH_ADD_KEYPTR(hh, map, mapping_id, len, s);  /* id: name of key field */
        *map_ptr = map;
    }
}




static ngx_int_t
ngx_http_footer_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{

    if(ngx_http_sticky_module.ctx == NULL) { //sticky no defined
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Sticky module not there");
        return ngx_http_next_body_filter(r, in);
    }

    ngx_http_sticky_ctx *ctx = ngx_http_get_module_ctx(r, ngx_http_sticky_module);
    if(ctx==NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"null sticky_ctx");
        return ngx_http_next_body_filter(r, in);
    }
    session_map *map = *(ctx->map);

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"ctx_domain_name : %V", ctx->domain);

    //do clean up if necc
    time_t now = ngx_time();
    time_t expiry_limit = ctx->expiry_limit;
    if((now - *(ctx->last_cleaned)) > expiry_limit) { //do clean up
        session_map *mapping = NULL;
        session_map *temp_mapping = NULL;
        for(mapping = map; mapping != NULL; ) {
            temp_mapping = (session_map*)(mapping->hh.next);
            if((now - mapping->reg_time) > expiry_limit) {
                HASH_DELETE( hh, map, mapping);
                free(mapping->id);
                free(mapping);
            }
            mapping = temp_mapping;
        }
        *(ctx->last_cleaned) = now;
    }

    //do parsing here. in->buf->pos to in->buf->last is the resp. #####check if buf can hav max. its 4096 nw##############

    ngx_str_t s  = { (ngx_uint_t)(in->buf->last - in->buf->pos), in->buf->pos};

    ngx_regex_compile_t   rc;
    u_char                errstr[NGX_MAX_CONF_ERRSTR];
    char *name = "jsessionid=";
    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pool = r->pool;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;
    ngx_str_set(&(rc.pattern), "<\\s*form[^>]*\\s+action\\s*=\\s*[\"'](.+?)[\"'][^>]*(>)");
    rc.options = NGX_REGEX_CASELESS;
    int n = 6;
    int capture_array[6]= {0};
    //ngx_regex_t* re;

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "regex compiling failed");
        return ngx_http_next_body_filter(r, in);
    }

    ngx_int_t res = ngx_regex_exec(rc.regex, &s, capture_array, n);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"regex stuff : %d : %d : %d : %d", res, capture_array[0], capture_array[1], capture_array[2]);
    if(res == 0) { //form action is there
        int i=0;
        for(i=0; i<n; ++i) {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"%d elem : %d",i, capture_array[i]);
        }
        ngx_str_t url = {capture_array[3] - capture_array[2] + 1,  in->buf->pos + capture_array[2]};//including one extra char to incl the quote fr nxt reg ex match
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"regex stuff : ##%V##", &url );
        ngx_str_set(&(rc.pattern), "[^?;]+[?;](.*)([\"'])");//';' could serve as a delimiter as well as indicates the beginning of query param.
        if (ngx_regex_compile(&rc) != NGX_OK) {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "regex compiling failed");
            return ngx_http_next_body_filter(r, in);
        }
        res = ngx_regex_exec(rc.regex, &url, capture_array, n);
        ngx_str_t param = {capture_array[3] - capture_array[2],  url.data + capture_array[2]};
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"param_regex : ##%V##", &param );
        char* param_alloc = (char*)ngx_palloc(r->pool, param.len + 2);
        *(ngx_copy(param_alloc, param.data, param.len + 1)) = 0;
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"param_tmp : ##%s##", param_alloc );

        char *session_id = ngx_strstr(param_alloc, name);
        if(session_id == NULL) {
            return ngx_http_next_body_filter(r, in);
        }
        char *val_beg = session_id + strlen(name);
        char *val_end = ngx_strchr(val_beg, ';');
        if(val_end == NULL) {
            val_end = ngx_strchr(val_beg, '&');
        }
        if(val_end == NULL) {
            val_end = ngx_strchr(val_beg, '"');
        }
        if(val_end == NULL) {
            val_end = ngx_strchr(val_beg, '\'');
        }
        if(val_end != NULL) {
            ngx_str_t val = {val_end - val_beg, (u_char*) val_beg};
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"\n[filter/regex]jsession val : ##%s##", val.data );
            add_mapping(val.data, val.len, ctx->selected_peer, time((time_t*)0), &map);
        } else {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"\n[filter/regex]Regex Error");
        }

    } else {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"[filter/regex]regex stuff : Did not match" );
    }

    //end parsing

    *(ctx->map) = map;
    session_map *mapping;
    /* Debug Only
    for(mapping=map; mapping != NULL; mapping=(session_map*)(mapping->hh.next))
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "\n[map_filter]mapping id: %s selected_peer :%d\n", mapping->id, mapping->selected_peer);
    */
    return ngx_http_next_body_filter(r, in);
}


static ngx_int_t
ngx_http_footer_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_footer_body_filter;
    return NGX_OK;
}
