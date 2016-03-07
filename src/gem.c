#include <rtosc/rtosc.h>
#include "gem.h"
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <ctype.h>

//Testing Hooks
int  (*osc_socket_hook)(void) = NULL;
int  (*osc_request_hook)(int, const char *) = NULL;

#define END     "\xc0"
#define ESC     "\xdb"
#define ESC_END "\xdc"
#define ESC_ESC "\xdd"
void send_slip(const char *data, unsigned size)
{
    char *tmp_buf = malloc(size*2);
}

//Database
void db_insert_int(void);
void db_insert_float(void);

static int match_path(const char *uri, const char *pattern)
{
    if(!pattern)
        return 0;

    //uri_i = pattern_j when uri_i !\in range
    //range = atoi(pattern_j) when \in  range

    int match = 1;
    while(*uri && *pattern)
    {
        if(*pattern != '[') {
            if(*uri != *pattern)
                return 0;
            uri++;
            pattern++;
        } else {
            pattern++;
            assert(isdigit(*pattern));
            int low = atoi(pattern);
            while(*pattern && isdigit(*pattern))
                pattern++;
            //printf("pattern = %s\n", pattern);
            assert(*pattern == ',');
            pattern++;
            int high = atoi(pattern);
            while(*pattern && isdigit(*pattern))
                pattern++;
            assert(*pattern == ']');
            pattern++;

            int real = atoi(uri);
            while(*uri && isdigit(*uri))
                uri++;

            if(real < low || real > high)
                return 0;
        }

    }


    return 1;
}

//Schema
schema_handle_t sm_get(schema_t sch, uri_t u)
{
    schema_handle_t invalid;
    printf("Getting a handle...\n");
    for(int i=0; i<sch.elements; ++i)
        if(match_path(u, sch.handles[i].pattern))
            return sch.handles[i];
    return invalid;
}
opt_t sm_get_opts(schema_handle_t);
str_t sm_get_name(schema_handle_t h)
{
    return h.name ? h.name : "";
}

str_t sm_get_short(schema_handle_t h)
{
    return h.short_name ? h.short_name : "";
}

str_t sm_get_tooltip(schema_handle_t h)
{
    return h.documentation ? h.documentation : "";
}

str_t sm_get_units(schema_handle_t h)
{
    return "";
}

int sm_valid(schema_handle_t h)
{
    return 1;
}

//Bridge
bridge_t br_create(uri_t uri)
{
    bridge_t br;
    memset(&br, 0, sizeof(br));
    int ret;
    struct sockaddr_in addr;
    br.sock = socket(PF_INET, SOCK_DGRAM, 0);
    printf("[debug] socket = %d\n", br.sock);

    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(0);
    ret = bind(br.sock, (struct sockaddr*)&addr, sizeof(addr));
    printf("[debug] bind   = %d\n", ret);

    return br;
}

void parse_schema(const char *json, schema_t *sch);
schema_t br_get_schema(bridge_t br, uri_t uri)
{
    schema_t sch;
    int ret;
    //struct addrinfo *ai;

    //ret = getaddrinfo("localhost", "1337", NULL, &ai);
    //printf("[debug] getaddrinfo = %d\n", ret);

    //ret = connect(br.sock, ai->ai_addr, ai->ai_addrlen);
    //printf("[debug] connect = %d\n", ret);

    //ret = send(br.sock, "/sch" "ema\0" ",\0\0\0", 12, 0);
    //printf("[debug] send = %d\n", ret);

    printf("[debug] loading json file\n");
    //FILE *f = fopen("../test-schema.json", "r");
    FILE *f = fopen("test.json", "r");
    assert(f && "opening json file");
    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    rewind(f);
    char *json = malloc(len);
    fread(json, 1, len, f);
    fclose(f);

    printf("[debug] parsing json file\n");
    parse_schema(json, &sch);


	return sch;
}

//typedef struct {
//    char *path;
//    char  valid;
//    char  type;
//    rtosc_arg_t val;
//} param_cache_t;
static int cache_has(param_cache_t *c, size_t len, uri_t uri)
{
    for(int i=0; i<len; ++i)
        if(!strcmp(c->path, uri))
            return 1;
    return 0;
}

static void cache_push(bridge_t *br, uri_t uri)
{
    br->cache_len += 1;
    br->cache = realloc(br->cache, br->cache_len*sizeof(param_cache_t));
    param_cache_t *ch = br->cache + (br->cache_len - 1);
    ch->path    = strdup(uri);
    ch->valid   = 0;
    ch->pending = 1;

    char buffer[128];
    rtosc_message(buffer, 128, uri, "");
    if(osc_request_hook)
    	osc_request_hook(0, buffer);
}

static void callback_push(bridge_t *br, uri_t uri, bridge_cb_t cb)
{
    br->callback_len += 1;
    br->callback = realloc(br->callback, br->callback_len*sizeof(bridge_callback_t));
    bridge_callback_t *ch = br->callback + (br->callback_len - 1);
    ch->path    = strdup(uri);
    ch->cb      = cb;
}

static param_cache_t *cache_get(bridge_t *br, uri_t uri)
{
    for(int i=0; i<br->cache_len; ++i)
        if(!strcmp(br->cache[i].path, uri))
	    return br->cache + i;
    cache_push(br, uri);
    return cache_get(br, uri);
}

static void cache_set(bridge_t *br, uri_t uri, char type, rtosc_arg_t val)
{
    param_cache_t *line = cache_get(br, uri);
    assert(line);
    line->pending = false;
    if(!line->valid || line->type != type || memcmp(&line->val, &val, sizeof(val)))
    {
        line->valid = true;
        line->type  = type;
        line->val   = val;

        //run callbacks
        for(int i=0; i<br->callback_len; ++i)
            if(!strcmp(br->callback[i].path, uri))
                br->callback[i].cb(uri, 0);
    }
}

void br_request_value(bridge_t *br, uri_t uri, schema_handle_t handle)
{
    char buffer[128];
    rtosc_message(buffer, 128, uri, "");
    if(osc_request_hook)
    	osc_request_hook(0, buffer);
}

void br_add_callback(bridge_t *br, uri_t uri, bridge_cb_t callback, void *data)
{
    if(!cache_has(br->cache, br->cache_len, uri))
        cache_push(br, uri);
    callback_push(br, uri, callback);
}

void br_recv(bridge_t *br)
{
    char buffer[128];
    rtosc_message(buffer, 128, "/part0/Pvolume", "i", 74);

    cache_set(br, buffer, rtosc_type(buffer, 0), rtosc_argument(buffer, 0));

}

//Views
void vw_add_float(void);
void vw_add_enum(void);


//Statistics
void print_stats(bridge_t br, schema_t sch)
{
    printf("Bridge Statistics:\n");
    printf("    Total cache lines:          %d\n", br.cache_len);
    printf("    Total callbacks:            %d\n", br.callback_len);
    printf("Schema Statistics:\n");
    printf("    Known Parameters Patterns:  %d\n", sch.elements);
}
