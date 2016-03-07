#include <rtosc/rtosc.h>
#include "gem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int osc_socket_hook_fn(void)
{
    return 0;
}

int osc_request_hook_fn(int sock, const char *msg)
{
    // /schema        - return the schema file
    // /part0/Pvolume - return the volume
    char *buffer = NULL;

    const char *args = rtosc_argument_string(msg);
    printf("osc_request_hook_fn(%d,%s,%s)\n", sock, msg,args);
    if(!strcmp(msg, "/schema") && !strcmp(args, "")) {
        size_t buf_size = rtosc_message(NULL, 0, "/schema", "s", "");
        buffer = malloc(buf_size);
        rtosc_message(buffer, buf_size, "/schema", "s", "");
    } else if(!strcmp(msg, "/part0/Pvolume") && !strcmp(args, "")) {
        size_t buf_size = rtosc_message(NULL, 0, "/part0/Pvolume", "i", 32);
        buffer = malloc(buf_size);
        rtosc_message(buffer, 128, "/part0/Pvolume", "i", 32);
    } else {
        printf("unexpected message...\n");
        assert(false);
        return 0;
    }

    //TODO send the message

    free(buffer);

    return 0;
}



void print_response(const char *osc, void *v)
{
    printf("#####################################\n");
    printf("got a message '%s'...\n", osc);
    printf("#####################################\n");
}

int main()
{
    //Apply Debug Hooks
    osc_request_hook = osc_request_hook_fn;
    osc_socket_hook  = osc_socket_hook_fn;


    //Define that there is a bridge on localhost:1337
    printf("Creating Bridge To Remote...\n");
    bridge_t bridge = br_create("localhost:1337");

    //Get the bridge to obtain the schema
    printf("Creating Schema For Remote...\n");
    schema_t schema = br_get_schema(bridge, "/schema");

    {
        //Add a view to /part0/Pvolume
        printf("Grabing a Handle On Schema...\n");
        uri_t uri = "/part0/Pvolume";
        schema_handle_t handle = sm_get(schema, uri);

        assert(sm_valid(handle));

        printf("Obtained Handle for <%s>...\n", uri);
        printf("name:       \"%s\"\n", sm_get_name(handle));
        printf("short name: \"%s\"\n", sm_get_short(handle));
        printf("tooltip:    \"%s\"\n", sm_get_tooltip(handle));
        printf("units:      \"%s\"\n", sm_get_units(handle));

        br_add_callback(&bridge, uri, print_response, NULL);
        br_add_callback(&bridge, uri, print_response, (void*)0xbeef);
        br_request_value(&bridge, uri, handle);
    }

    {
        uri_t uri = "/part0/Penabled";
        schema_handle_t handle = sm_get(schema, uri);

        assert(sm_valid(handle));

        printf("Obtained Handle for <%s>...\n", uri);
        printf("name:       \"%s\"\n", sm_get_name(handle));
        printf("short name: \"%s\"\n", sm_get_short(handle));
        printf("tooltip:    \"%s\"\n", sm_get_tooltip(handle));
        printf("units:      \"%s\"\n", sm_get_units(handle));
    }

    br_recv(&bridge);

    print_stats(bridge, schema);

    return 0;
}
