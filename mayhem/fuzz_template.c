/*
 * HTML error/stats page templates: send_html_file() substitutes {variable}
 * references in a template (found with a POSIX regex) from the connection's
 * error variables and writes the result to the client.
 *
 * Input: the template text, delivered through fmemopen() the way fopen() of
 * an ErrorFile would deliver it.
 */
#include "harness_common.h"
#include "html-error.h"
#include "conns.h"

#define TEMPLATE_MAX_INPUT (8 * 1024)

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
        harness_init();
        return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
        if (size < 1 || size > TEMPLATE_MAX_INPUT)
                return -1;

        int cfd[2];
        if (harness_feed(cfd, NULL, 0) != 0)
                return 0;

        uint8_t *copy = malloc(size);
        if (!copy) {
                close(cfd[0]);
                close(cfd[1]);
                return 0;
        }
        memcpy(copy, data, size);
        FILE *tmpl = fmemopen(copy, size, "r");

        struct conn_s conn;
        memset(&conn, 0, sizeof conn);
        conn_struct_init(&conn);
        conn.client_fd = cfd[1];
        struct harness_drain drain;
        harness_drain_start(&drain, cfd[0]);
        conn.protocol.major = 1;
        conn.protocol.minor = 1;
        conn_init_contents(&conn, "192.0.2.7", NULL);
        conn.request_line = safestrdup("GET http://example.com/ HTTP/1.1");
        indicate_http_error(&conn, 404, "Not Found", "detail",
                            "The page was not found", "url",
                            "http://example.com/", NULL);

        if (tmpl) {
                send_html_file(tmpl, &conn);
                fclose(tmpl);
        }

        conn_destroy_contents(&conn);
        harness_drain_join(&drain);
        free(copy);
        return 0;
}
