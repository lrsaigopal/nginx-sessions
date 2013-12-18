#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "uthash.h" //hash map

#define MAX_PTR_STR 50

/* session mapping hash struct */
typedef struct {
    u_char* id;                    /* key */
    int selected_peer;
    time_t reg_time;
    UT_hash_handle hh;         /* makes this structure hashable */
} session_map;


/* the configuration structure */
typedef struct {
    ngx_str_t                     domain;
    ngx_str_t                     name;
    time_t                        expiry_limit;
    ngx_uint_t                    no_fallback;
    session_map                   *map;
    time_t                        last_cleaned;
} ngx_http_sticky_srv_conf_t;


/* the custom sticky struct used on each request */
typedef struct {
    /* the round robin data must be first */
    ngx_http_upstream_rr_peer_data_t   rrp;
    ngx_event_get_peer_pt              get_rr_peer;
    int                                selected_peer;
    int                                no_fallback;
    ngx_http_sticky_srv_conf_t        *sticky_conf;
    ngx_http_request_t                *request;
} ngx_http_sticky_peer_data_t;



static ngx_int_t ngx_http_init_sticky_peer(ngx_http_request_t *r,	ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_get_sticky_peer(ngx_peer_connection_t *pc, void *data);
static char *ngx_http_sticky_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_sticky_create_conf(ngx_conf_t *cf);


static ngx_command_t  ngx_http_sticky_commands[] = {

    {
        ngx_string("session_sticky"),
        NGX_HTTP_UPS_CONF|NGX_CONF_ANY,
        ngx_http_sticky_set,
        0,
        0,
        NULL
    },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_sticky_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_sticky_create_conf,           /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_sticky_module = {
    NGX_MODULE_V1,
    &ngx_http_sticky_module_ctx, /* module context */
    ngx_http_sticky_commands,    /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


typedef struct {
    ngx_str_t                     *domain;
    ngx_str_t                     *name;
    session_map                   **map;
    ngx_uint_t                    selected_peer;
    time_t                        expiry_limit;
    time_t                       *last_cleaned;

} ngx_http_sticky_ctx;



/*
 * function called by the upstream module to init itself
 * it's called once per instance
 */
ngx_int_t ngx_http_init_upstream_sticky(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us) {
    ngx_http_upstream_rr_peers_t *rr_peers;

    /* call the rr module on wich the sticky module is based on */
    if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    /* calculate each peer digest once and save */
    rr_peers = us->peer.data;

    /* do nothing there's only one peer */
    if (rr_peers->number <= 1 || rr_peers->single) {
        return NGX_OK;
    }

    /* tell the upstream module to call ngx_http_init_sticky_peer when it inits peer */
    us->peer.init = ngx_http_init_sticky_peer;

    return NGX_OK;
}

/*
 * function called by the upstream module when it inits each peer
 * it's called once per request
 */
static ngx_int_t ngx_http_init_sticky_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us) {
    ngx_http_sticky_peer_data_t  *iphp;

    /* alloc custom sticky struct */
    iphp = ngx_palloc(r->pool, sizeof(ngx_http_sticky_peer_data_t));
    if (iphp == NULL) {
        return NGX_ERROR;
    }

    /* attach it to the request upstream data */
    r->upstream->peer.data = &iphp->rrp;




    /* call the rr module on which the sticky is based on */
    if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    /* set the callback to select the next peer to use */
    r->upstream->peer.get = ngx_http_get_sticky_peer;

    /* init the custom sticky struct */
    iphp->get_rr_peer = ngx_http_upstream_get_round_robin_peer;
    iphp->selected_peer = -1;
    iphp->no_fallback = 0;
    iphp->sticky_conf = ngx_http_conf_upstream_srv_conf(us, ngx_http_sticky_module);
    iphp->request = r;

    //parsing url
    u_char* id = NULL;
    u_int len = 0;
    u_char* uri_str = (u_char*)ngx_palloc(r->pool, (r->uri).len + 2);//one fr " and \0 char
    u_char* tmp = ngx_copy(uri_str, (r->uri).data, (r->uri).len);
    *(tmp++) = '"';
    *tmp = 0;
    ngx_regex_compile_t   rc;
    u_char                errstr[NGX_MAX_CONF_ERRSTR];
    u_char *name = (iphp->sticky_conf->name).data;
    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
    rc.pool = r->pool;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;
    rc.options = NGX_REGEX_CASELESS;
    int n = 6;
    int capture_array[6]= {0};
    ngx_str_set(&(rc.pattern), "[^?;]+[?;](.*)([\"'])");//';' could serve as a delimiter as well as indicates the beginning of query param.
    ngx_str_t tmp_url = {(r->uri).len + 1, uri_str};
    ngx_regex_compile(&rc);
    ngx_int_t res = ngx_regex_exec(rc.regex, &tmp_url, capture_array, n);
    if(res == 0) {
        ngx_str_t param = {capture_array[3] - capture_array[2],  uri_str + capture_array[2]};


        char *session_id = ngx_strstr(param.data, name);
        if(session_id != NULL) {
            char *val_beg = session_id + strlen((char*)name);
            char *val_end = ngx_strchr(val_beg, ';');
            if(val_end == NULL) {
                val_end = ngx_strchr(val_beg, '&');
            }
            if(val_end == NULL) {
                val_end = ngx_strchr(val_beg, '"');
            }
            if(val_end != NULL) {
                ngx_str_t val = {val_end - val_beg, (u_char*) val_beg};
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"[sticky/init_sticky_peer]sessionid val : ##%V##", &val );
                id = val.data;
                id[val.len] = 0;
                len = val.len;
            } else {
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"[sticky/init_sticky_peer]Regex error");
            }
        }
    } else {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"[sticky/init_sticky_peer]no query param");
        return NGX_OK;
    }
    //end of parsing url

    //1st see if session id is there in url. if yes loop up in hahs table. if found set selec peer and return ngxok. else return ngxok bt log it

    session_map *mapping = NULL;

    HASH_FIND(hh, iphp->sticky_conf->map, id, len, mapping);
    if(mapping != NULL) { //found a session mapping
        iphp->selected_peer = mapping->selected_peer;
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[sticky/init_sticky_peer] selecting peer %d\n", mapping->selected_peer);
    } else {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[sticky/init_sticky_peer] no mapping for this session\n");
        /* Debug Purpose
            for(mapping=iphp->sticky_conf->map; mapping != NULL; mapping=(session_map*)(mapping->hh.next))
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "\n[map_lb]mapping id: %s selected_peer :%d\n", mapping->id, mapping->selected_peer);
        */
    }
    return NGX_OK;
    //end of session based code

}

/*
 * function called by the upstream module to choose the next peer to use
 * called at least one time per request
 */
static ngx_int_t ngx_http_get_sticky_peer(ngx_peer_connection_t *pc, void *data) {
    ngx_http_sticky_peer_data_t  *iphp = data;
    ngx_http_sticky_srv_conf_t   *conf = iphp->sticky_conf;
    ngx_int_t                     selected_peer = -1;
    time_t                        now = ngx_time();
    uintptr_t                     m =0;
    ngx_uint_t                    n = 0, i;
    ngx_http_upstream_rr_peer_t  *peer = NULL;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0, "[sticky/get_sticky_peer] get sticky peer, try: %ui, n_peers: %ui, no_fallback: %ui/%ui", pc->tries, iphp->rrp.peers->number, conf->no_fallback, iphp->no_fallback);


    /* has the sticky module already choosen a peer to connect to and is it a valid peer */
    /* is there more than one peer (otherwise, no choices to make) */
    if (iphp->selected_peer >= 0 && iphp->selected_peer < (ngx_int_t)iphp->rrp.peers->number && !iphp->rrp.peers->single) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0, "[sticky/get_sticky_peer] let's try the selected peer (%i)", iphp->selected_peer);

        n = iphp->selected_peer / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << iphp->selected_peer % (8 * sizeof(uintptr_t));

        /* has the peer not already been tried ? */
        if (!(iphp->rrp.tried[n] & m)) {
            peer = &iphp->rrp.peers->peer[iphp->selected_peer];

            /* if the no_fallback flag is set */
            if (conf->no_fallback) {

                iphp->no_fallback = 1;

                /* if peer is down */
                if (peer->down) {
                    ngx_log_error(NGX_LOG_NOTICE, pc->log, 0, "[sticky/get_sticky_peer] the selected peer is down and no_fallback is flagged");
                    return NGX_BUSY;
                }

                /* if it's been ignored for long enought (fail_timeout), reset timeout */
                /* do this check before testing peer->fails ! :) */
                if (now - peer->accessed > peer->fail_timeout) {
                    peer->fails = 0;
                }

                /* if peer is failed */
                if (peer->max_fails > 0 && peer->fails >= peer->max_fails) {
                    ngx_log_error(NGX_LOG_NOTICE, pc->log, 0, "[sticky/get_sticky_peer] the selected peer is maked as failed and no_fallback is flagged");
                    return NGX_BUSY;
                }
            }

            /* ensure the peer is not marked as down */
            if (!peer->down) {

                /* if it's not failedi, use it */
                if (peer->max_fails == 0 || peer->fails < peer->max_fails) {
                    selected_peer = (ngx_int_t)n;

                    /* if it's been ignored for long enought (fail_timeout), reset timeout and use it */
                } else if (now - peer->accessed > peer->fail_timeout) {
                    peer->fails = 0;
                    selected_peer = (ngx_int_t)n;

                    /* it's failed or timeout did not expire yet */
                } else {
                    /* mark the peer as tried */
                    iphp->rrp.tried[n] |= m;
                }
            }
        }
    }



    //setting up per request ctx going to be used by filter
    ngx_http_sticky_ctx *ctx = ngx_pcalloc(iphp->request->pool, sizeof(ngx_http_sticky_ctx));
    ngx_http_set_ctx(iphp->request, ctx, ngx_http_sticky_module);
    ctx->domain = &(conf->domain);
    ctx->name = &(conf->name);
    ctx->map = &(conf->map);
    ctx->expiry_limit = conf->expiry_limit;
    ctx->last_cleaned = &(conf->last_cleaned);


    /* we have a valid peer, tell the upstream module to use it */
    if (peer && selected_peer >= 0) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0, "[sticky/get_sticky_peer] peer found at index %i", selected_peer);

        iphp->rrp.current = iphp->selected_peer;
        pc->cached = 0;
        pc->connection = NULL;
        pc->sockaddr = peer->sockaddr;
        pc->socklen = peer->socklen;
        pc->name = &peer->name;

        iphp->rrp.tried[n] |= m;

        ctx->selected_peer = iphp->selected_peer;

    } else {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0, "[sticky/get_sticky_peer] no sticky peer selected, switch back to classic rr");

        if (iphp->no_fallback) {
            ngx_log_error(NGX_LOG_NOTICE, pc->log, 0, "[sticky/get_sticky_peer] No fallback in action !");
            return NGX_BUSY;
        }

        ngx_int_t ret = iphp->get_rr_peer(pc, &iphp->rrp);
        if (ret != NGX_OK) {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0, "[sticky/get_sticky_peer] ngx_http_upstream_get_round_robin_peer returned %i", ret);
            return ret;
        }

        /* search for the choosen peer in order to set the cookie */
        for (i = 0; i < iphp->rrp.peers->number; i++) {

            if (iphp->rrp.peers->peer[i].sockaddr == pc->sockaddr && iphp->rrp.peers->peer[i].socklen == pc->socklen) {
                ctx->selected_peer = i;
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0, "[sticky/get_sticky_peer] selected rr peer : %d", i);
                break;
            }
        }
    }

    /* reset the selection in order to bypass the sticky module when the upstream module will try another peers if necessary */
    iphp->selected_peer = -1;

    return NGX_OK;
}

/*
 * Function called when the sticky command is parsed on the conf file
 */
static char *ngx_http_sticky_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_upstream_srv_conf_t  *upstream_conf;
    ngx_http_sticky_srv_conf_t    *sticky_conf;
    ngx_uint_t i;
    ngx_str_t tmp;
    ngx_str_t domain = ngx_string("");
    ngx_str_t name = ngx_string("jsessionid=\0");
    time_t expires = 60000;
    ngx_uint_t no_fallback = 0;

    /* parse all elements */
    for (i = 1; i < cf->args->nelts; i++) {
        ngx_str_t *value = cf->args->elts;

        /* is "name=" is starting the argument ? */
        if ((u_char *)ngx_strstr(value[i].data, "name=") == value[i].data) {

            /* do we have at least on char after "name=" ? */
            if (value[i].len <= sizeof("name=") - 1) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "a value must be provided to \"name=\"");
                return NGX_CONF_ERROR;
            }

            /* save what's after "name=" */
            u_char* temp;
            name.len = value[i].len - ngx_strlen("name=") + 2;//for = and null char
            temp = (u_char *)(value[i].data + sizeof("name=") - 1);
            name.data = ngx_pcalloc(cf->pool, name.len);
            temp = ngx_copy(name.data, temp, name.len - 2);
            *(temp++) = '=';
            *temp = 0;
            continue;
        }

        /* is "domain=" is starting the argument ? */
        if ((u_char *)ngx_strstr(value[i].data, "domain=") == value[i].data) {

            /* do we have at least on char after "domain=" ? */
            if (value[i].len <= ngx_strlen("domain=")) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "a value must be provided to \"domain=\"");
                return NGX_CONF_ERROR;
            }

            /* save what's after "domain=" */
            domain.len = value[i].len - ngx_strlen("domain=");
            domain.data = (u_char *)(value[i].data + sizeof("domain=") - 1);
            continue;
        }

        /* is "expires=" is starting the argument ? */
        if ((u_char *)ngx_strstr(value[i].data, "expires=") == value[i].data) {

            /* do we have at least on char after "expires=" ? */
            if (value[i].len <= sizeof("expires=") - 1) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "a value must be provided to \"expires=\"");
                return NGX_CONF_ERROR;
            }

            /* extract value */
            tmp.len =  value[i].len - ngx_strlen("expires=");
            tmp.data = (u_char *)(value[i].data + sizeof("expires=") - 1);

            /* convert to time, save and validate */
            expires = ngx_parse_time(&tmp, 1);
            if (expires == NGX_ERROR || expires < 1) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid value for \"expires=\"");
                return NGX_CONF_ERROR;
            }
            continue;
        }


        /* is "no_fallback" flag present ? */
        if (ngx_strncmp(value[i].data, "no_fallback", sizeof("no_fallback") - 1) == 0 ) {
            no_fallback = 1;
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid arguement (%V)", &value[i]);
        return NGX_CONF_ERROR;
    }


    /* save the sticky parameters */
    sticky_conf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_sticky_module);
    sticky_conf->domain = domain;
    sticky_conf->name = name;//store it with = and end it with 0. so 2 more bytes
    sticky_conf->expiry_limit = expires;
    sticky_conf->no_fallback = no_fallback;
    sticky_conf->map = NULL;
    sticky_conf->last_cleaned = ngx_time();

    upstream_conf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    /*
     * ensure another upstream module has not been already loaded
     * peer.init_upstream is set to null and the upstream module use RR if not set
     * But this check only works when the other module is declared before sticky
     */
    if (upstream_conf->peer.init_upstream) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "You can't use session_sticky with another upstream module");
        return NGX_CONF_ERROR;
    }

    /* configure the upstream to get back to this module */
    upstream_conf->peer.init_upstream = ngx_http_init_upstream_sticky;

    upstream_conf->flags = NGX_HTTP_UPSTREAM_CREATE
                           | NGX_HTTP_UPSTREAM_MAX_FAILS
                           | NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
                           | NGX_HTTP_UPSTREAM_DOWN
                           | NGX_HTTP_UPSTREAM_WEIGHT;

    return NGX_CONF_OK;
}

/*
 * alloc stick configuration
 */
static void *ngx_http_sticky_create_conf(ngx_conf_t *cf) {
    ngx_http_sticky_srv_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sticky_srv_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
}
