#include <stdint.h>
#include <uv.h>
//A means of staying synchonized with respect to a collection of parameters
//presented over OSC in a REST like fashion

//Database
typedef struct db_t_ db_t;
void db_insert_int(void);
void db_insert_float(void);

//Schema
typedef struct {
    int         *ids;
    const char **labels;
    unsigned     num_opts;
} opt_t;
typedef struct {
    //all dynamic here
    int   flag;
    opt_t *opts;
    const char *pattern;
    const char *name;
    const char *short_name;
    const char *units;
    const char *documentation;
    float value_min;
    float value_max;
} schema_handle_t;
typedef struct {
    char            *json;
    schema_handle_t *handles;
    int              elements;
} schema_t;
typedef const char *uri_t;
typedef const char *str_t;

schema_handle_t sm_get(schema_t, uri_t u);
opt_t sm_get_opts(schema_handle_t);
str_t sm_get_name(schema_handle_t);
str_t sm_get_short(schema_handle_t);
str_t sm_get_tooltip(schema_handle_t);
str_t sm_get_units(schema_handle_t);
float sm_get_min_flt(schema_handle_t);
float sm_get_max_flt(schema_handle_t);

int sm_valid(schema_handle_t);

#ifndef RTOSC_H
typedef struct {
    int32_t len;
    uint8_t *data;
} rtosc_blob_t;

typedef union {
    int32_t       i;   //i,c,r
    char          T;   //I,T,F,N
    float         f;   //f
    double        d;   //d
    int64_t       h;   //h
    uint64_t      t;   //t
    uint8_t       m[4];//m
    const char   *s;   //s,S
    rtosc_blob_t  b;   //b
} rtosc_arg_t;
#endif

typedef struct {
    char *path;
    char  valid;
    char  pending;
    char  type;
    double request_time;
    union {
        rtosc_arg_t val;
        struct {
            const char  *vec_type;
            rtosc_arg_t *vec_value;
        };
    };
} param_cache_t;

typedef struct {
    const char *path;
    double last_set;
} debounce_t;

typedef void (*bridge_cb_t)(const char *, void*);
typedef struct {
    const char *path;
    bridge_cb_t cb;
    void *data;
} bridge_callback_t;

//Bridge
typedef struct {
    uv_loop_t *loop;
    uv_udp_t socket;
    void *pending_requests;

    char *address;
    int port;
    int frame_messages;

    param_cache_t     *cache;
    debounce_t        *bounce;
    bridge_callback_t *callback;
    char             **rlimit;
    int cache_len;
    int debounce_len;
    int callback_len;
    int rlimit_len;
    uint64_t last_update;
} bridge_t;

#define BR_RATE_LIMIT 50

bridge_t *br_create(uri_t);
void      br_destroy(bridge_t *br);
schema_t br_get_schema(bridge_t*, uri_t);
void br_destroy_schema(schema_t);
void br_request_value(bridge_t *, uri_t, schema_handle_t);
void br_randomize(bridge_t *, uri_t);
void br_set_array(bridge_t *, uri_t, char*, rtosc_arg_t*);
void br_set_value_bool(bridge_t *, uri_t, int);
void br_set_value_int(bridge_t *, uri_t, int);
void br_set_value_float(bridge_t *, uri_t, float);
void br_set_value_string(bridge_t *, uri_t, const char *);
int  br_has_callback(bridge_t *, uri_t);
void br_add_callback(bridge_t *, uri_t, bridge_cb_t, void*);
void br_add_action_callback(bridge_t *, uri_t, bridge_cb_t, void*);
void br_del_callback(bridge_t *, uri_t, bridge_cb_t, void*);
void br_damage(bridge_t *, uri_t);
void br_refresh(bridge_t *, uri_t);
void br_watch(bridge_t *, uri_t);
void br_action(bridge_t *, uri_t, const char *argt, const rtosc_arg_t *args);
void br_recv(bridge_t *, const char *);
int br_pending(bridge_t *);
void br_tick(bridge_t *);
int  br_last_update(bridge_t *);//returns delta time in seconds

//Views
void vw_add_float(void);
void vw_add_enum(void);

void print_stats(bridge_t *br, schema_t sch);


//Testing Hooks
extern int  (*osc_socket_hook)(void);
extern int  (*osc_request_hook)(bridge_t *, const char *);
