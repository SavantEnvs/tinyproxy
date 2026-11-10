/*
 * Client side of a proxied connection: the request line, the header block,
 * URL extraction, the CONNECT/stat-host/reverse-proxy/transparent-proxy
 * decisions, header rewriting and request-body relaying, followed by the
 * error page or stats page that would be sent back.
 *
 * This replays handle_connection() in reqs.c up to the point where it would
 * open a TCP connection, with a socketpair standing in for the remote server.
 *
 * Input: one option byte that picks the proxy configuration (bit 0 no Via,
 * bit 1 anonymous mode, bit 2 reverse path, bit 3 reverse-only, bit 4 HTTP
 * upstream, bit 5 basic auth, bit 6 X-Tinyproxy header), then the raw bytes the client sends.
 */
#include "harness_common.h"
#include "reqs.c"

static void setup_config(struct config_s *c, uint8_t opt)
{
        c->basicauth_realm = safestrdup("tinyproxy");
        c->stathost = safestrdup(TINYPROXY_STATHOST);
        c->idletimeout = MAX_IDLE_TIME;
        c->maxclients = 100;
        c->via_proxy_name = safestrdup("fuzz-proxy");
        c->disable_viaheader = opt & 1;
        add_connect_port_allowed(443, &c->connect_ports);
        add_connect_port_allowed(563, &c->connect_ports);

        http_header_t extra = { safestrdup("X-Fuzz"), safestrdup("1") };
        c->add_headers = sblist_new(sizeof extra, 4);
        sblist_add(c->add_headers, &extra);

        if (opt & 2) {
                anonymous_insert(c, safestrdup("user-agent"));
                anonymous_insert(c, safestrdup("content-type"));
                anonymous_insert(c, safestrdup("x-fuzz"));
        }
        if (opt & 4)
                reversepath_add("/app/", "http://backend.example:8080/",
                                &c->reversepath_list);
        if (opt & 8)
                c->reverseonly = 1;
        if (opt & 16)
                upstream_add("up.example", 3128, NULL, "u", "p", PT_HTTP,
                             &c->upstream_list);
        if (opt & 32) {
                c->basicauth_list = sblist_new(sizeof(char *), 4);
                basicauth_add(c->basicauth_list, "user", "pass");
        }
        c->add_xtinyproxy = (opt >> 6) & 1;
}

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
        if (harness_feed(cfd, data + 1, size - 1) != 0)
                return 0;
        if (harness_feed(sfd, NULL, 0) != 0) {
                close(cfd[0]);
                close(cfd[1]);
                return 0;
        }

        setup_config(&harness_config, opt);

        struct conn_s conn;
        memset(&conn, 0, sizeof conn);
        conn_struct_init(&conn);
        conn.client_fd = cfd[1];
        struct harness_drain cdrain, sdrain;
        harness_drain_start(&cdrain, cfd[0]);
        harness_drain_start(&sdrain, sfd[0]);
        conn_init_contents(&conn, "127.0.0.1", NULL);

        struct request_s *request = NULL;
        pseudomap *headers = NULL;
        int got_headers = 0;

        if (read_request_line(&conn) < 0)
                goto done;

        headers = pseudomap_create();
        if (!headers)
                goto done;

        if (get_all_headers(conn.client_fd, headers) < 0) {
                indicate_http_error(&conn, 400, "Bad Request", "detail",
                                    "Could not retrieve all the headers from "
                                    "the client.", NULL);
                goto fail;
        }
        got_headers = 1;

        if (config->basicauth_list != NULL) {
                char *auth = pseudomap_find(headers, "proxy-authorization");
                if (!auth || strncasecmp(auth, "Basic ", 6) != 0 ||
                    basicauth_check(config->basicauth_list, auth + 6) != 1) {
                        auth_error(&conn, 407);
                        goto fail;
                }
                pseudomap_remove(headers, "proxy-authorization");
        }

        for (size_t i = 0; i < sblist_getsize(config->add_headers); i++) {
                http_header_t *h = sblist_get(config->add_headers, i);
                pseudomap_append(headers, h->name, h->value);
        }

        request = process_request(&conn, headers);
        if (!request)
                goto fail;

        conn.server_fd = sfd[1];
        conn.upstream_proxy = UPSTREAM_HOST(request->host);
        if (conn.upstream_proxy) {
                size_t len = strlen(request->host) + strlen(request->path) + 14;
                char *combined = safemalloc(len);
                if (!combined)
                        goto done;
                if (conn.connect_method)
                        snprintf(combined, len, "%s:%d", request->host,
                                 request->port);
                else
                        snprintf(combined, len, "http://%s:%d%s", request->host,
                                 request->port, request->path);
                safefree(request->path);
                request->path = combined;
                establish_http_connection(&conn, request);
        } else if (!conn.connect_method) {
                establish_http_connection(&conn, request);
        }

        if (process_client_headers(&conn, headers) < 0)
                goto fail;

        if (conn.connect_method)
                send_connect_method_response(&conn);
        goto done;

fail:
        handle_connection_failure(&conn, got_headers);

done:
        free_request_struct(request);
        if (conn.server_fd == -1)
                close(sfd[1]);
        if (headers)
                pseudomap_destroy(headers);
        conn_destroy_contents(&conn);
        harness_drain_join(&cdrain);
        harness_drain_join(&sdrain);
        free_config(&harness_config);
        return 0;
}
