/*
 * Host/network specifications used by Allow/Deny, Upstream and NoUpstream:
 * hostspec_parse() turns "ip", "ip/mask", "ip/dotted-mask" or a domain into a
 * struct hostspec, hostspec_match() compares it with an address or hostname,
 * and numeric specs are also run through the ACL list (insert_acl/check_acl).
 *
 * Input: "<spec>\n<address>", split at the first newline.
 */
#include "harness_common.h"
#include "acl.h"
#include "hostspec.h"
#include "heap.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
        harness_init();
        return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
        if (size > HARNESS_MAX_INPUT)
                return -1;
        const uint8_t *nl = memchr(data, '\n', size);
        if (!nl)
                return -1;
        size_t spec_len = nl - data, addr_len = size - spec_len - 1;
        if (spec_len == 0 || addr_len == 0)
                return -1;

        char *spec = malloc(spec_len + 1);
        char *spec2 = malloc(spec_len + 1);
        char *addr = malloc(addr_len + 1);
        memcpy(spec, data, spec_len);
        spec[spec_len] = 0;
        memcpy(spec2, spec, spec_len + 1);
        memcpy(addr, nl + 1, addr_len);
        addr[addr_len] = 0;

        struct hostspec hs;
        if (hostspec_parse(spec, &hs) == 0) {
                hostspec_match(addr, &hs);

                if (hs.type == HST_NUMERIC) {
                        /* Only numeric entries: a string entry would make
                         * check_acl() resolve names through the network. */
                        acl_list_t list = NULL;
                        if (insert_acl(spec2, ACL_ALLOW, &list) == 0) {
                                union sockaddr_union peer;
                                memset(&peer, 0, sizeof peer);
                                if (addr[0] != '\0')
                                        check_acl(addr, &peer, list);
                        }
                        flush_access_list(list);
                } else if (hs.type == HST_STRING) {
                        safefree(hs.address.string);
                }
        }

        free(spec);
        free(spec2);
        free(addr);
        return 0;
}
