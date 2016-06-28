#include <rtosc/rtosc.h>
#include "gem.h"
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <ctype.h>

//Testing Hooks
int  (*osc_socket_hook)(void) = NULL;
int  (*osc_request_hook)(bridge_t *, const char *) = NULL;

#define END     '\xc0'
#define ESC     '\xdb'
#define ESC_END '\xdc'
#define ESC_ESC '\xdd'
char *send_slip(const char *data, unsigned size, unsigned *nsize)
{
    char *tmp_buf = malloc(size*2);
    unsigned i;
    unsigned j;
    //Escape sequence
    for(i=0,j=0; i<size; ++i) {
        if(data[i] == ESC) {
            tmp_buf[j++] = ESC;
            tmp_buf[j++] = ESC_ESC;
        } else if(data[i] == END) {
            tmp_buf[j++] = ESC;
            tmp_buf[j++] = ESC_ESC;
        } else
            tmp_buf[j++] = data[i];
    }
    tmp_buf[j++] = END;
    tmp_buf[j]   = 0;
    *nsize       = j-1;
    return tmp_buf;
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

    //partial match, but not a complete one
    if(!*pattern && *uri)
        return 0;

    return 1;
}

void br_destroy_schema(schema_t sch)
{
    free(sch.json);
    for(int i=0; i<sch.elements; ++i) {
        if(sch.handles[i].opts) {
            free(sch.handles[i].opts->ids);
            for(int j=0; j<sch.handles[i].opts->num_opts; ++j)
                free((void*)sch.handles[i].opts->labels[j]);
            free(sch.handles[i].opts->labels);
        }
        free((void*)sch.handles[i].documentation);
        free((void*)sch.handles[i].name);
        free((void*)sch.handles[i].short_name);
        free((void*)sch.handles[i].pattern);
        free(sch.handles[i].opts);
    }
    free(sch.handles);
}

//Schema
schema_handle_t sm_get(schema_t sch, uri_t u)
{
    schema_handle_t invalid;
    memset(&invalid, 0, sizeof(invalid));
    invalid.flag = 0xdeadbeef;
    //printf("Getting a handle(%s)...\n", u);
    for(int i=0; i<sch.elements; ++i)
        if(match_path(u, sch.handles[i].pattern))
            return sch.handles[i];
    printf("invalid handle(%s)...\n", u);
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
    return h.flag != 0xdeadbeef;
}

static void alloc_buffer(uv_handle_t *handle, size_t suggested_size,
        uv_buf_t *buf) {
    *buf = uv_buf_init((char*) malloc(suggested_size), suggested_size);
}

static void hexdump(const char *data, const char *mask, size_t len)
{
    const char *bold_gray = "\x1b[30;1m";
    const char *reset      = "\x1b[0m";
    int offset = 0;
    while(1)
    {
        //print line
        printf("#%07x: ", offset);

        int char_covered = 0;

        //print hex groups (8)
        for(int i=0; i<8; ++i) {

            //print doublet
            for(int j=0; j<2; ++j) {
                int loffset = offset + 2*i + j;
                if(loffset >= (int)len)
                    goto escape;

                //print hex
                {
                    //start highlight
                    if(mask && mask[loffset]){printf("%s", bold_gray);}

                    //print chars
                    printf("%02x", 0xff&data[loffset]);

                    //end highlight
                    if(mask && mask[loffset]){printf("%s", reset);}
                    char_covered += 2;
                }
            }
            printf(" ");
            char_covered += 1;
        }
escape:

        //print filler if needed
        for(int i=char_covered; i<41; ++i)
            printf(" ");

        //print ascii (16)
        for(int i=0; i<16; ++i) {
            if(isprint(data[offset+i]))
                printf("%c", data[offset+i]);
            else
                printf(".");
        }
        printf("\n");
        offset += 16;
        if(offset >= (int)len)
            return;
    }
}

void on_read(uv_udp_t *req, ssize_t nread, const uv_buf_t *buf,
             const struct sockaddr *addr, unsigned flags) {
    if(nread > 0) {

        const struct sockaddr_in *addr_in = (const struct sockaddr_in *)addr;
        if(addr) {
            char sender[17] = { 0 };
            uv_ip4_name(addr_in, sender, 16);
            //printf("Recv from %s\n", sender);
            //printf("port = %d\n", addr_in->sin_port);
        }
        //printf("buffer[%d] = %s\n", nread, buf->base);
        //hexdump(buf->base, 0, nread);
        bridge_t *br = (bridge_t*)req->data;
        br_recv(br, buf->base);
    }
    free(buf->base);
    //free(req);
}

static void send_cb(uv_udp_send_t* req, int status)
{
    free(req);
}

void osc_request(bridge_t *br, const char *path)
{
    uv_udp_send_t *send_req = malloc(sizeof(uv_udp_send_t));
    char *buffer      = malloc(4096);
    size_t len_org    = rtosc_message(buffer, 4096, path, "");
    //unsigned len_slip = 0;
    //char *slip = send_slip(buffer, len_org, &len_slip);
    uv_buf_t buf = uv_buf_init((char*)buffer, len_org);
    struct sockaddr_in send_addr;
    uv_ip4_addr("127.0.0.1", 1337, &send_addr);
    uv_udp_send(send_req, &br->socket, &buf, 1, (const struct sockaddr *)&send_addr, send_cb);
    //printf("osc request done<%s>?\n", path);
}

void osc_send(bridge_t *br, const char *message)
{
    uv_udp_send_t *send_req = malloc(sizeof(uv_udp_send_t));
    size_t   len_org  = rtosc_message_length(message, -1);
    unsigned len_slip = 0;
    char *slip = send_slip(message, len_org, &len_slip);
    uv_buf_t buf = uv_buf_init((char*)slip, len_slip);
    struct sockaddr_in send_addr;
    uv_ip4_addr("127.0.0.1", 1337, &send_addr);
    uv_udp_send(send_req, &br->socket, &buf, 1, (const struct sockaddr *)&send_addr, send_cb);
    //printf("osc sent...<%s>?\n", message);
}

//Bridge
bridge_t *br_create(uri_t uri)
{
    bridge_t *br = calloc(1,sizeof(bridge_t));

    br->loop = uv_default_loop();

    uv_udp_init(br->loop, &br->socket);
    for(int offset=0; offset < 1000; ++offset) {
        struct sockaddr_in recv_addr;
        uv_ip4_addr("127.0.0.1", 1338+offset, &recv_addr);
        if(!uv_udp_bind(&br->socket, (const struct sockaddr *)&recv_addr, 0))
            break;
    }
    br->socket.data = br;

    uv_udp_recv_start(&br->socket, alloc_buffer, on_read);

    return br;
}

void br_destroy(bridge_t *br)
{
    for(int i=0; i<br->cache_len; ++i) {
        free((void*)br->cache[i].path);
        if(br->cache[i].type == 'v') {
            free((void*)br->cache[i].vec_type);
            free((void*)br->cache[i].vec_value);
        }
    }
    free(br->cache);
    free(br->bounce);
    for(int i=0; i<br->callback_len; ++i) {
        free((void*)br->callback[i].data);
        free((void*)br->callback[i].path);
    }
    free(br->callback);
    free(br);
}

void parse_schema(const char *json, schema_t *sch);
schema_t br_get_schema(bridge_t *br, uri_t uri)
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
    FILE *f = fopen("schema/test.json", "r");
    if(!f)
        f = fopen("src/osc-bridge/schema/test.json", "r");
    assert(f && "opening json file");
    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    rewind(f);
    char *json = malloc(len);
    fread(json, 1, len, f);
    fclose(f);

    printf("[debug] parsing json file\n");
    parse_schema(json, &sch);
    sch.json = json;


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
        if(!strcmp(c[i].path, uri))
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
    ch->type    = 0;
    ch->pending = 1;
    ch->request_time = 0;
    memset(&ch->val, 0, sizeof(ch->val));

    char buffer[128];
    rtosc_message(buffer, 128, uri, "");
    if(osc_request_hook)
    	osc_request_hook(br, buffer);
    else
        osc_request(br, uri);
}

static void debounce_push(bridge_t *br, param_cache_t *line, double obs)
{
    br->debounce_len += 1;
    br->bounce        = realloc(br->bounce, br->debounce_len*sizeof(debounce_t));
    debounce_t *bo = br->bounce + (br->debounce_len - 1);
    bo->path = line->path;
    bo->last_set = obs;
}

static void debounce_update(bridge_t *br, param_cache_t *line)
{
    struct timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    double obs = time.tv_sec + 1e-9*time.tv_nsec;
    for(int i=0; i<br->debounce_len; ++i) {
        if(!strcmp(line->path, br->bounce[i].path)) {
            br->bounce[i].last_set = obs;
            return;
        }
    }
    debounce_push(br, line, obs);
}

static void debounce_pop(bridge_t *br, int idx)
{
    assert(idx < br->debounce_len);
    for(int i=idx; i<br->debounce_len-1; ++i)
        br->bounce[i] = br->bounce[i+1];
    br->debounce_len -= 1;
}


static void callback_push(bridge_t *br, uri_t uri, bridge_cb_t cb, void *data)
{
    br->callback_len += 1;
    br->callback = realloc(br->callback, br->callback_len*sizeof(bridge_callback_t));
    bridge_callback_t *ch = br->callback + (br->callback_len - 1);
    ch->path    = strdup(uri);
    ch->cb      = cb;
    ch->data    = data;
}

static void callback_pop(bridge_t *br, uri_t uri, bridge_cb_t cb, void *data)
{
    int len = br->callback_len;

    int idx = 0;
    while(idx < len) {
        bridge_callback_t item = br->callback[idx];
        if(!strcmp(item.path, uri) && item.cb == cb && item.data == data) {
            //We should remove this element
            //printf("Deleting callback...\n");

            //Deallocate resources
            free((void*)item.path);

            //Move all other items
            for(int i=idx; i<len-1; ++i)
                br->callback[i] = br->callback[i+1];

            //Shrink list
            len--;
        } else {
            //move on to the next element of the list
            idx++;
        }
    }

    br->callback_len = len;
}

static param_cache_t *cache_get(bridge_t *br, uri_t uri)
{
    for(int i=0; i<br->cache_len; ++i)
        if(!strcmp(br->cache[i].path, uri))
	    return br->cache + i;
    cache_push(br, uri);
    return cache_get(br, uri);
}

static int valid_type(char ch)
{
    switch(ch)
    {
        case 'i'://official types
        case 's':
        case 'b':
        case 'f':

        case 'h'://unofficial
        case 't':
        case 'd':
        case 'S':
        case 'r':
        case 'm':
        case 'c':
        case 'T':
        case 'F':
        case 'N':
        case 'I':
            return 1;
        default:
            return 0;
    }
}

static void run_callbacks(bridge_t *br, param_cache_t *line)
{
    char buffer[1024*8];
    if(line->type != 'v') {
        char args[2] = {line->type, 0};
        assert(valid_type(line->type));
        rtosc_amessage(buffer, sizeof(buffer), line->path, args, &line->val);
    } else {
        rtosc_amessage(buffer, sizeof(buffer), line->path, line->vec_type,
                line->vec_value);
    }

    //run callbacks
    for(int i=0; i<br->callback_len; ++i)
        if(!strcmp(br->callback[i].path, line->path))
            br->callback[i].cb(buffer, br->callback[i].data);
}

static rtosc_arg_t
clone_value(char type, rtosc_arg_t val)
{
    if(type == 'b') {
        char *data = (char*)val.b.data;
        val.b.data = malloc(val.b.len);
        memcpy(val.b.data, data, val.b.len);
    } else if(type == 's') {
        val.s = strdup(val.s);
    }
    return val;
}

static rtosc_arg_t *
clone_vec_value(char *type, rtosc_arg_t *val)
{
    int n = strlen(type);
    rtosc_arg_t *nargs = calloc(sizeof(rtosc_arg_t), n);
    for(int i=0; i<n; ++i) {
        nargs[i] = clone_value(type[i], val[i]);
    }
    return nargs;
}

//returns true when the cache has changed values
static int cache_set(bridge_t *br, uri_t uri, char type, rtosc_arg_t val, int skip_debounce)
{
    param_cache_t *line = cache_get(br, uri);
    assert(line);
    line->pending = false;
    if(!line->valid || line->type != type || memcmp(&line->val, &val, sizeof(val)))
    {
        line->valid = true;
        line->type  = type;
        line->val   = clone_value(type, val);

        //check if cache line is currently debounced...
        int debounced = false;
        for(int i=0; i<br->debounce_len; ++i)
            if(!strcmp(br->bounce[i].path, line->path))
                debounced = true;

        if(!debounced || skip_debounce)
            run_callbacks(br, line);

        return true;
    }
    return false;
}

static int cache_set_vector(bridge_t *br, uri_t uri, char *types, rtosc_arg_t *args)
{
    param_cache_t *line = cache_get(br, uri);
    assert(line);
    line->pending = false;

    int ins_size  = strlen(types);
    int line_size = line->type == 'v' ? strlen(line->vec_type) : 0;

    //If the line is invalid OR
    //the cache isn't a vector field OR
    //the vector fields differ in type OR
    //the vector fields differ in value
    if(!line->valid || line->type != 'v' || strcmp(line->vec_type, types) ||
            memcmp(&line->vec_value, &args, sizeof(args[0])*line_size))
    {
        line->valid     = true;
        line->type      = 'v';
        //TODO fix memory leak
        line->vec_type  = strdup(types);
        line->vec_value = clone_vec_value(types, args);

        //check if cache line is currently debounced...
        int debounced = false;
        for(int i=0; i<br->debounce_len; ++i)
            if(!strcmp(br->bounce[i].path, line->path))
                debounced = true;

        if(!debounced)
            run_callbacks(br, line);

        return true;
    }
    return false;
}

void br_request_value(bridge_t *br, uri_t uri, schema_handle_t handle)
{
    char buffer[128];
    rtosc_message(buffer, 128, uri, "");
    if(osc_request_hook)
    	osc_request_hook(0, buffer);
}

void br_randomize(bridge_t *br, uri_t uri)
{
    schema_handle_t handle;
    //TODO
}

void br_set_value_int(bridge_t *br, uri_t uri, int value)
{
    rtosc_arg_t arg = {.i = value};
    if(cache_set(br, uri, 'i', arg, 1)) {
        char buffer[1024];
        rtosc_message(buffer, 1024, uri, "i", value);
        osc_send(br, buffer);
        debounce_update(br, cache_get(br, uri));
    }
}

void br_set_value_float(bridge_t *br, uri_t uri, float value)
{
    rtosc_arg_t arg = {.f = value};
    if(cache_set(br, uri, 'f', arg, 1)) {
        char buffer[1024];
        rtosc_message(buffer, 1024, uri, "f", value);
        osc_send(br, buffer);
        debounce_update(br, cache_get(br, uri));
    }
}

void br_add_callback(bridge_t *br, uri_t uri, bridge_cb_t callback, void *data)
{
    assert(br);
    callback_push(br, uri, callback, data);
    if(!cache_has(br->cache, br->cache_len, uri)) {
        cache_push(br, uri);
    } else {
        //instantly respond when possible
        param_cache_t *ch = cache_get(br, uri);
        if(!ch->valid)
            return;
        char buffer[1024*8];

        if(ch->type != 'v') {
            char typestr[2] = {ch->type,0};
            rtosc_amessage(buffer, sizeof(buffer), ch->path,
                    typestr, &ch->val);
        } else {
            rtosc_amessage(buffer, sizeof(buffer), ch->path, ch->vec_type,
                    ch->vec_value);
        }
        callback(buffer, data);
    }
}

void br_del_callback(bridge_t *br, uri_t uri, bridge_cb_t callback, void *data)
{
    callback_pop(br, uri, callback, data);
}

void br_refresh(bridge_t *br, uri_t uri)
{
    param_cache_t *cline = cache_get(br, uri);
    
    struct timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    double now = time.tv_sec + 1e-9*time.tv_nsec;

    if(cline->request_time < now - 30e-3) {
        cline->request_time = now;
        osc_request(br, uri);
    }
}

void br_watch(bridge_t *br, const char *uri)
{
    uv_udp_send_t *send_req = malloc(sizeof(uv_udp_send_t));
    char *buffer = malloc(4096);
    size_t len_org = rtosc_message(buffer, 4096, "/watch/add", "s", uri);
    unsigned len_slip = 0;
    char *slip = send_slip(buffer, len_org, &len_slip);
    uv_buf_t buf = uv_buf_init((char*)slip, len_slip);
    struct sockaddr_in send_addr;
    uv_ip4_addr("127.0.0.1", 1337, &send_addr);
    uv_udp_send(send_req, &br->socket, &buf, 1, (const struct sockaddr *)&send_addr, send_cb);

}

void br_action(bridge_t *br, const char *uri, const char *argt,
        const rtosc_arg_t *args)
{
    uv_udp_send_t *send_req = malloc(sizeof(uv_udp_send_t));
    char *buffer = malloc(4096);
    size_t len_org = rtosc_amessage(buffer, 4096, uri, argt, args);
    unsigned len_slip = 0;
    char *slip = send_slip(buffer, len_org, &len_slip);
    uv_buf_t buf = uv_buf_init((char*)slip, len_slip);
    struct sockaddr_in send_addr;
    uv_ip4_addr("127.0.0.1", 1337, &send_addr);
    uv_udp_send(send_req, &br->socket, &buf, 1, (const struct sockaddr *)&send_addr, send_cb);

}

void br_recv(bridge_t *br, const char *msg)
{
    //char buffer[128];
    //rtosc_message(buffer, 128, "/part0/Pvolume", "i", 74);
    if(!msg)
        return;

    //printf("BR RECEIVE %s:%s\n", msg, rtosc_argument_string(msg));
    //printf("MESSAGE IS %d bytes\n", rtosc_message_length(msg, -1));
    
    if(!strcmp("/damage", msg) && !strcmp("s", rtosc_argument_string(msg))) {
        const char *dmg = rtosc_argument(msg, 0).s;
        printf("Damage of parameters...\n");
        printf("path is %s\n", dmg);
        for(int i=0; i<br->cache_len; ++i) {
            if(strstr(br->cache[i].path, dmg)) {
                osc_request(br, br->cache[i].path);
            }
        }
        return;
    }

    const int nargs = rtosc_narguments(msg);
    if(nargs == 1)
        cache_set(br, msg, rtosc_type(msg, 0), rtosc_argument(msg, 0), 0);
    else {
        //Try to handle the vector message cases
        //printf("BRIDGE RECEIVE A VECTOR MESSAGE\n");
        //TODO verify that we've got some sort of uniformity?
        rtosc_arg_itr_t  itr   = rtosc_itr_begin(msg);
        rtosc_arg_t     *args  = calloc(nargs, sizeof(rtosc_arg_t));
        char            *types = strdup(rtosc_argument_string(msg));

        int offset = 0;
        while(!rtosc_itr_end(itr))
            args[offset++] = rtosc_itr_next(&itr).val;

        cache_set_vector(br, msg, types, args);
    }
    //for(int i=0; i<br->callback_len; ++i) {
    //    printf("cb name = %s\n", br->callback[i].path);
    //    bridge_callback_t cb = br->callback[i];
    //    if(!strcmp(cb.path, msg))
    //        cb.cb(msg, cb.data);
    //}
}

int br_pending(bridge_t *br)
{
    int pending = 0;
    for(int i=0; i<br->cache_len; ++i)
        pending += !!(br->cache[i].pending);
    return pending;
}

void br_tick(bridge_t *br)
{
    //Run all network events
    while(uv_run(br->loop, UV_RUN_NOWAIT) > 1);

    //Attempt to disable debouncing
    if(br->debounce_len == 0)
        return;
    struct timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    double delta  = 300e-3;
    double thresh = time.tv_sec + 1e-9*time.tv_nsec - delta;
    for(int i=br->debounce_len-1; i >= 0; --i) {
        if(br->bounce[i].last_set < thresh) {
            run_callbacks(br, cache_get(br, br->bounce[i].path));
            debounce_pop(br, i);
        }
    }
}

//Views
void vw_add_float(void);
void vw_add_enum(void);


//Statistics
void print_stats(bridge_t *br, schema_t sch)
{
    printf("Bridge Statistics:\n");
    printf("    Total cache lines:          %d\n", br->cache_len);
    printf("    Total callbacks:            %d\n", br->callback_len);
    printf("Schema Statistics:\n");
    printf("    Known Parameters Patterns:  %d\n", sch.elements);
}
