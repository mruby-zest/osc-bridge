#include <rtosc/rtosc.h>
#include "../src/gem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int osc_socket_hook_fn(void)
{
    return 0;
}

int osc_request_hook_fn(bridge_t *br, const char *msg)
{
    // /schema        - return the schema file
    // /part0/Pvolume - return the volume
    char *buffer = NULL;

    const char *args = rtosc_argument_string(msg);
    printf("[REQUEST] osc_request_hook_fn(%p,%s,%s)\n", br, msg,args);
    if(!strcmp(msg, "/schema") && !strcmp(args, "")) {
        size_t buf_size = rtosc_message(NULL, 0, "/schema", "s", "");
        buffer = malloc(buf_size);
        rtosc_message(buffer, buf_size, "/schema", "s", "");
        br_recv(br, buffer);
    } else if(!strcmp(msg, "/part0/Pvolume") && !strcmp(args, "")) {
        size_t buf_size = rtosc_message(NULL, 0, "/part0/Pvolume", "i", 32);
        buffer = malloc(buf_size);
        rtosc_message(buffer, 128, "/part0/Pvolume", "i", 32);
        br_recv(br, buffer);
    } else {
        printf("[ERROR] unexpected message...\n");
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
    printf("got a message '%s':%c data=%p...\n", osc, rtosc_type(osc, 0), v);
    printf("#####################################\n");
}

void test_pvolume(schema_t schema, bridge_t *bridge)
{
    //Add a view to /part0/Pvolume
    printf("Grabing a Handle On Schema...\n");
    uri_t uri = "/part0/Pvolume";
    schema_handle_t handle = sm_get(schema, uri);

    assert(sm_valid(handle));

    //printf("Obtained Handle for <%s>...\n", uri);
    //printf("name:       \"%s\"\n", sm_get_name(handle));
    //printf("short name: \"%s\"\n", sm_get_short(handle));
    //printf("tooltip:    \"%s\"\n", sm_get_tooltip(handle));
    //printf("units:      \"%s\"\n", sm_get_units(handle));

    printf("Callback #1\n");
    br_add_callback(bridge, uri, print_response, NULL);
    printf("Callback #2\n");
    br_add_callback(bridge, uri, print_response, (void*)0xbeef);
}

void test_enable(schema_t schema)
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

void test_part_level(schema_t schema, bridge_t *bridge)
{
    test_pvolume(schema, bridge);
    test_enable(schema);
}


//Paths to check for a minimal(ish) example subwindow
const char *paths[] = {
"/part0/kit0/adpars/VoicePar0/FreqLfo/Pfreq",
"/part0/kit0/adpars/VoicePar0/FreqLfo/Pintensity",
"/part0/kit0/adpars/VoicePar0/FreqLfo/Pstartphase",
"/part0/kit0/adpars/VoicePar0/FreqLfo/PLFOtype",
"/part0/kit0/adpars/VoicePar0/FreqLfo/Prandomness",
"/part0/kit0/adpars/VoicePar0/FreqLfo/Pfreqrand",
"/part0/kit0/adpars/VoicePar0/FreqLfo/Pdelay",
"/part0/kit0/adpars/VoicePar0/FreqLfo/Pcontinous",
"/part0/kit0/adpars/VoicePar0/FreqLfo/Pstretch",
};
void test_lfo(schema_t schema)
{
    for(int i=0; i<sizeof(paths)/sizeof(paths[0]); ++i) {
        uri_t uri = paths[i];
        printf("\nTesting address '%s'\n", uri);
        schema_handle_t handle = sm_get(schema, uri);

        assert(sm_valid(handle));

        printf("(1#{%s} 2#{%s} 3#{%s} 4#{%s}\n",
        sm_get_name(handle),    sm_get_short(handle),
        sm_get_tooltip(handle), sm_get_units(handle));
    }
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

    test_part_level(schema, &bridge);
    //test_lfo(schema);

    printf("bridge receive...\n");
    br_recv(&bridge, 0);

    print_stats(bridge, schema);

    return 0;
}
