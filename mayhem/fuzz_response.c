/*
 * Server side of a proxied connection: the status line and header block
 * returned by an origin server, as parsed, filtered and rewritten by
 * process_server_headers() before it is forwarded to the client (Via,
 * Connection-listed headers, reverse-proxy Location rewriting and cookie).
 *
 * Input: one option byte (bit 0 HTTP/1.1 client, bit 1 no Via, bit 2 reverse
 * proxy with magic cookie and base URL), then the raw bytes the server sends.
 */
#include "harness_common.h"
#include "reqs.c"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
        harness_init();
        return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
        if (size < 1 || size > HARNESS_MAX_INPUT)
                return -1;
        uint8_t opt = data[0];

        int cfd[2], sfd[2];
        if (harness_feed(sfd, data + 1, size - 1) != 0)
                return 0;
        if (harness_feed(cfd, NULL, 0) != 0) {
                close(sfd[0]);
                close(sfd[1]);
                return 0;
        }

        struct config_s *c = &harness_config;
        c->basicauth_realm = safestrdup("tinyproxy");
        c->stathost = safestrdup(TINYPROXY_STATHOST);
        c->via_proxy_name = safestrdup("fuzz-proxy");
        c->disable_viaheader = (opt >> 1) & 1;
        if (opt & 4) {
                reversepath_add("/app/", "http://backend.example:8080/",
                                &c->reversepath_list);
                reversepath_add("/", "https://other.example/",
                                &c->reversepath_list);
                c->reversemagic = 1;
                c->reversebaseurl = safestrdup("http://proxy.example/");
        }

        struct conn_s conn;
        memset(&conn, 0, sizeof conn);
        conn_struct_init(&conn);
        conn.client_fd = cfd[1];
        conn.server_fd = sfd[1];
        struct harness_drain drain;
        harness_drain_start(&drain, cfd[0]);
        conn.protocol.major = 1;
        conn.protocol.minor = opt & 1;
        conn_init_contents(&conn, "127.0.0.1", NULL);
        if (opt & 4)
                conn.reversepath = safestrdup("/app/");

        if (process_server_headers(&conn) < 0 && conn.error_variables)
                send_http_error_message(&conn);

        conn_destroy_contents(&conn);
        harness_drain_join(&drain);
        close(sfd[0]);
        free_config(c);
        return 0;
}
