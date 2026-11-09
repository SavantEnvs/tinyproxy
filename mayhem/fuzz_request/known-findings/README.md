# `is_stathost()` reads past the end of the Host header value

`src/reqs.c:is_stathost()` compares the client's `Host` header with the configured `StatHost`:

```c
while (*p && *(p++) == *(q++));
return *p == 0 && (*q == 0 || *q == ':');
```

When `Host` is a proper prefix of the stat host (default `tinyproxy.stats`; e.g. `Host: tinyproxy.stat`) the
loop advances `q` past the terminating NUL on the mismatching step, and `p` past the last character of the stat
host, so `*p == 0` holds and `*q` is read one byte beyond the header value: a heap-buffer-overflow read of 1 byte
(ASan: `READ of size 1 ... is_stathost reqs.c:330`). Any client can trigger it with one request.

Reproduce: `/mayhem/fuzz_request-standalone mayhem/fuzz_request/known-findings/is_stathost-oob-read.bin`

Fix: stop advancing on the mismatching character, e.g. compare with `strncmp`/`strlen` of the stat host
instead of the post-increment loop.
