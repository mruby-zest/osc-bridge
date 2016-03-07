#include "gem.h"
#define MM_JSON_IMPLEMENTATION
#include "mm_json.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

void print_string(const char *str, unsigned len)
{
    for(int i=0; i<len; ++i)
        putchar(str[i]);
}

void parse_schema(const char *json, schema_t *sch)
{
    sch->elements = 0;
    sch->handles  = 0;

    /* Lexer example */
    mm_json_size len = strlen(json);

    /* create iterator  */
    struct mm_json_iter iter;
    iter = mm_json_begin(json, len);

    //Read in parameters
    struct mm_json_pair pair;
    iter = mm_json_parse(&pair, &iter);
    assert(!mm_json_cmp(&pair.name, "parameters"));
    assert(pair.value.type == MM_JSON_ARRAY);

    //Read in parameter objects
    struct mm_json_iter array = mm_json_begin(pair.value.str, pair.value.len);
    struct mm_json_token tok;
    array = mm_json_read(&tok, &array);
    while (array.src) {
        /* read single token */
        printf("new schema handle...\n");
        sch->elements += 1;
        sch->handles   = realloc(sch->handles, sch->elements*sizeof(schema_handle_t));

        schema_handle_t *handle = sch->handles+(sch->elements-1);
        memset(handle, 0, sizeof(schema_handle_t));

        struct mm_json_iter array2 = mm_json_begin(tok.str, tok.len);
        struct mm_json_pair pair2;
        array2 = mm_json_parse(&pair2, &array2);
        while (!array2.err) {
            assert(pair2.name.type == MM_JSON_STRING);
            printf("  ");
            print_string(pair2.name.str, pair2.name.len);
            unsigned pad = pair2.name.len < 10 ? 10-pair2.name.len : 0;
            for(int i=0; i<pad; ++i)
                putchar(' ');

            if(pair2.value.type == MM_JSON_STRING) {
                printf(" = \"");
                print_string(pair2.value.str, pair2.value.len);
                printf("\"\n");

                struct mm_json_token v = pair2.value;
                if(mm_json_cmp(&pair2.name, "path") == 0)
                    handle->pattern = strndup(v.str, v.len);
                else if(mm_json_cmp(&pair2.name, "name") == 0)
                    handle->name = strndup(v.str, v.len);
                else if(mm_json_cmp(&pair2.name, "shortname") == 0)
                    handle->short_name = strndup(v.str, v.len);
                else if(mm_json_cmp(&pair2.name, "tooltip") == 0)
                    handle->documentation = strndup(v.str, v.len);
            } else
                printf(" = ????\n");
            array2 = mm_json_parse(&pair2, &array2);
        }

        //MM_JSON_OBJECT
        array = mm_json_read(&tok, &array);
    }

    {
        printf("ACTIONS...\n\n");
        iter = mm_json_parse(&pair, &iter);
        assert(!mm_json_cmp(&pair.name, "actions"));
        assert(pair.value.type == MM_JSON_ARRAY);

        //Read in parameter objects
        struct mm_json_iter array = mm_json_begin(pair.value.str, pair.value.len);
        struct mm_json_token tok;
        iter = mm_json_read(&tok, &array);
        while (array.src) {
            /* read single token */
            printf("field.type = %d\n", tok.type);
            struct mm_json_iter array2 = mm_json_begin(tok.str, tok.len);
            struct mm_json_pair pair2;
            array2 = mm_json_parse(&pair2, &array2);
            while (!array2.err) {
                assert(pair2.name.type == MM_JSON_STRING);
                printf("  field.name[");
                print_string(pair2.name.str, pair2.name.len);
                if(pair2.value.type == MM_JSON_STRING) {
                    printf("] = \"");
                    print_string(pair2.value.str, pair2.value.len);
                    printf("\"\n");
                } else
                    printf("] = ????\n");
                array2 = mm_json_parse(&pair2, &array2);
            }

            //MM_JSON_OBJECT
            array = mm_json_read(&tok, &array);
        }
    }

    return;

    /* read subobject (array/objects) */
    iter = mm_json_parse(&pair, &iter);
    printf("pair.name = %s\n", pair.name.str);
    printf("pair.value.type = %d\n", pair.value.type);
    assert(pair.value.type == MM_JSON_ARRAY);

}
