#include <stdint.h>
//A means of staying synchonized with respect to a collection of parameters
//presented over OSC in a REST like fashion

//Database
typedef struct db_t_ db_t;
void db_insert_int(void);
void db_insert_float(void);

//Schema
typedef struct {
    //all dynamic here
    const char *pattern;
    const char *name;
    const char *short_name;
    const char *units;
    const char *documentation;
} schema_handle_t;
typedef struct {
    schema_handle_t *handles;
    int              elements;
} schema_t;
typedef const char *uri_t;
typedef struct opt_t_ opt_t;
typedef const char *str_t;

schema_handle_t sm_get(schema_t, uri_t u);
opt_t sm_get_opts(schema_handle_t);
str_t sm_get_name(schema_handle_t);
str_t sm_get_short(schema_handle_t);
str_t sm_get_tooltip(schema_handle_t);
str_t sm_get_units(schema_handle_t);

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
    rtosc_arg_t val;
} param_cache_t;

typedef void (*bridge_cb_t)(const char *,void*);
typedef struct {
    const char *path;
    bridge_cb_t cb;
} bridge_callback_t;

//Bridge
typedef struct {
    int sock;
    void *pending_requests;

    param_cache_t     *cache;
    bridge_callback_t *callback;
    int cache_len;
    int callback_len;
} bridge_t;

bridge_t br_create(uri_t);
schema_t br_get_schema(bridge_t, uri_t);
void br_request_value(bridge_t *, uri_t, schema_handle_t);
void br_add_callback(bridge_t *, uri_t, bridge_cb_t, void*);
void br_recv(bridge_t *);

//Views
void vw_add_float(void);
void vw_add_enum(void);

void print_stats(bridge_t br, schema_t sch);


//Testing Hooks
extern int  (*osc_socket_hook)(void);
extern int  (*osc_request_hook)(int, const char *);
