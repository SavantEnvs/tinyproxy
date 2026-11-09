/*
 * tinyproxy.conf parser: directive lookup, the per-directive regular
 * expressions and handlers (Allow/Deny, Upstream, ReversePath, BasicAuth,
 * ErrorFile, AddHeader, Listen/Bind, LogLevel, ...) and the teardown of
 * everything they build.
 *
 * Input: the config file text, delivered through fmemopen() the way fopen()
 * of the config file would deliver it.
 */
#include "harness_common.h"
#include "conf.c"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
        harness_init();
        return config_init() == 0 ? 0 : 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
        if (size < 1 || size > HARNESS_MAX_INPUT)
                return -1;

        uint8_t *copy = malloc(size);
        if (!copy)
                return 0;
        memcpy(copy, data, size);
        FILE *f = fmemopen(copy, size, "r");
        if (f) {
                struct config_s conf;
                initialize_config_defaults(&conf);
                config_parse(&conf, f);
                free_config(&conf);
                fclose(f);
        }
        free(copy);
        return 0;
}
