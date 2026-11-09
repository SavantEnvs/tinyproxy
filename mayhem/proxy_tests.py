#!/usr/bin/env python3
"""Black-box behavioural tests for the tinyproxy binary built by mayhem/build.sh.

Starts the real proxy on loopback next to a small origin server and a raw TCP
echo server, sends it hand-written requests, and checks the exact status
lines, headers and bodies it produces. Prints one `ok:`/`FAIL:` line per check
and `RESULT <passed> <failed>` at the end.
"""
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TINYPROXY = sys.argv[1]
passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("ok:", name)
    else:
        failed += 1
        print("FAIL:", name, detail[:300])


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def body_in(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            out = b""
            while True:
                n = int(self.rfile.readline().split(b";")[0], 16)
                if n == 0:
                    self.rfile.readline()
                    return out
                out += self.rfile.read(n)
                self.rfile.readline()
        n = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(n) if n else b""

    def reply(self, code, body, extra=()):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "text/plain")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/hello":
            self.reply(200, b"hello from origin",
                       [("X-Origin", "yes"), ("Keep-Alive", "timeout=5"),
                        ("Proxy-Connection", "keep-alive")])
        elif self.path == "/headers":
            hs = "".join("%s: %s\n" % (k.lower(), v) for k, v in self.headers.items())
            self.reply(200, ("path=%s\n%s" % (self.path, hs)).encode())
        elif self.path == "/redirect":
            self.reply(302, b"", [("Location", "/hello")])
        else:
            self.reply(404, b"nothing here")

    def do_POST(self):
        data = self.body_in()
        hs = "".join("%s: %s\n" % (k.lower(), v) for k, v in self.headers.items())
        self.reply(200, b"len=%d\n" % len(data) + data + b"\n--\n" + hs.encode())


def serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()


def echo_server():
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", 0))
    ls.listen(8)

    def run():
        while True:
            c, _ = ls.accept()

            def one(c=c):
                while True:
                    d = c.recv(4096)
                    if not d:
                        break
                    c.sendall(d.upper())
                c.close()
            threading.Thread(target=one, daemon=True).start()
    threading.Thread(target=run, daemon=True).start()
    return ls.getsockname()[1]


def exchange(port, raw, timeout=10):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.sendall(raw)
    buf = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            buf += d
    except socket.timeout:
        pass
    s.close()
    head, _, body = buf.partition(b"\r\n\r\n")
    lines = head.decode("latin1").split("\r\n")
    hdrs = {}
    for l in lines[1:]:
        k, _, v = l.partition(":")
        hdrs.setdefault(k.strip().lower(), []).append(v.strip())
    return lines[0], hdrs, body


def start_proxy(tmp, name, extra, port):
    conf = os.path.join(tmp, name + ".conf")
    with open(conf, "w") as f:
        f.write("Port %d\nListen 127.0.0.1\nTimeout 30\n" % port)
        f.write('LogFile "%s/%s.log"\nPidFile "%s/%s.pid"\n' % (tmp, name, tmp, name))
        f.write('ViaProxyName "mayhemproxy"\nStatHost "tinyproxy.stats"\n')
        f.write(extra)
    p = subprocess.Popen([TINYPROXY, "-d", "-c", conf], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return p
        except OSError:
            time.sleep(0.1)
    p.kill()
    raise SystemExit("tinyproxy did not start: " + name)


def main():
    tmp = tempfile.mkdtemp(prefix="tinyproxy-test-")
    origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    serve(origin)
    oport = origin.server_address[1]
    eport = echo_server()
    filt = os.path.join(tmp, "filter")
    with open(filt, "w") as f:
        f.write("blocked\\.example\n")

    pa, pb, pc = free_port(), free_port(), free_port()
    procs = [
        start_proxy(tmp, "a", 'AddHeader "X-Added" "yes"\nAllow 127.0.0.1\n'
                    'ConnectPort %d\nFilter "%s"\nFilterURLs On\nFilterExtended Off\n' % (eport, filt), pa),
        start_proxy(tmp, "b", 'Allow 127.0.0.1\nBasicAuth alice secret\nBasicAuthRealm "mayhem realm"\n'
                    'ReversePath "/app/" "http://127.0.0.1:%d/"\n' % oport, pb),
        start_proxy(tmp, "c", 'Allow 10.9.9.9\nDisableViaHeader Yes\n', pc),
    ]
    try:
        base = "http://127.0.0.1:%d" % oport

        # plain GET through the proxy
        st, h, b = exchange(pa, ("GET %s/hello HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                                 "Proxy-Connection: keep-alive\r\nConnection: close\r\n\r\n" % (base, oport)).encode())
        check("GET status", st.endswith("200 OK"), st)
        check("GET body relayed", b == b"hello from origin", repr(b))
        check("GET origin header kept", h.get("x-origin") == ["yes"], str(h))
        check("response Via added", any("mayhemproxy" in v for v in h.get("via", [])), str(h))
        check("response Keep-Alive stripped", "keep-alive" not in h, str(h))
        check("response Proxy-Connection stripped", "proxy-connection" not in h, str(h))

        # what the origin saw
        st, h, b = exchange(pa, ("GET %s/headers HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nUser-Agent: t/1\r\n"
                                 "Proxy-Connection: keep-alive\r\nKeep-Alive: 300\r\nX-Custom: abc\r\n\r\n" % (base, oport)).encode())
        t = b.decode()
        check("origin gets origin-form path", "path=/headers\n" in t, t)
        check("origin gets AddHeader", "x-added: yes\n" in t, t)
        check("origin gets Via", re.search(r"via: 1\.1 mayhemproxy", t) is not None, t)
        check("origin gets custom header", "x-custom: abc\n" in t and "user-agent: t/1\n" in t, t)
        check("origin never sees Proxy-Connection", "proxy-connection" not in t, t)
        check("origin sees Connection: close", "connection: close\n" in t, t)

        # request bodies
        body = b"a=1&b=hello+world"
        st, h, b = exchange(pa, ("POST %s/post HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Length: %d\r\n"
                                 "Content-Type: application/x-www-form-urlencoded\r\n\r\n" % (base, oport, len(body))).encode() + body)
        check("POST body relayed", st.endswith("200 OK") and b.startswith(b"len=%d\n" % len(body) + body), repr(b[:80]))
        chunked = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        st, h, b = exchange(pa, ("POST %s/post HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nTransfer-Encoding: chunked\r\n\r\n"
                                 % (base, oport)).encode() + chunked)
        check("chunked POST relayed", st.endswith("200 OK") and b.startswith(b"len=11\nhello world\n"), repr(b[:80]))

        # origin errors and redirects pass through unchanged
        st, h, b = exchange(pa, ("GET %s/missing HTTP/1.1\r\nHost: x\r\n\r\n" % base).encode())
        check("origin 404 passed through", st.endswith("404 Not Found") and b == b"nothing here", st + repr(b))
        st, h, b = exchange(pa, ("GET %s/redirect HTTP/1.1\r\nHost: x\r\n\r\n" % base).encode())
        check("origin redirect passed through", " 302 " in st and h.get("location") == ["/hello"], st + str(h))

        # HTTP/1.0 client
        st, h, b = exchange(pa, ("GET %s/hello HTTP/1.0\r\n\r\n" % base).encode())
        check("HTTP/1.0 client served", " 200 " in st and b == b"hello from origin", st)

        # malformed / unsupported requests
        st, h, b = exchange(pa, b"this is not http\r\n\r\n")
        check("garbage request line gets 400", " 400 " in st, st)
        st, h, b = exchange(pa, ("GET %s/hello HTTP/1.1\r\n\r\n" % base).replace("http://", "ftp://").encode())
        check("non-http scheme refused", re.search(r" (400|501) ", st) is not None, st)
        st, h, b = exchange(pa, b"GET http://127.0.0.1:%d/hello HTTP/1.1\r\nHost: x\r\nBadHeaderWithoutColon\r\n\r\n" % oport)
        check("malformed header handled", st.startswith("HTTP/1."), st)

        # error pages
        st, h, b = exchange(pa, ("GET http://127.0.0.1:%d/ HTTP/1.1\r\nHost: x\r\n\r\n" % free_port()).encode())
        check("unreachable origin gives 500", " 500 " in st and b"Unable to connect" in b, st + repr(b[:200]))
        st, h, b = exchange(pa, b"GET http://blocked.example/ HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
        check("filtered URL gets 403", " 403 " in st and b"filtered" in b.lower(), st + repr(b[:200]))
        check("error page is html", h.get("content-type", [""])[0].startswith("text/html"), str(h))

        # stats page
        st, h, b = exchange(pa, b"GET http://tinyproxy.stats/ HTTP/1.1\r\nHost: tinyproxy.stats\r\n\r\n")
        check("stathost page", st.endswith("200 OK") and b"Number of open connections" in b, st + repr(b[:200]))

        # CONNECT
        st, h, b = exchange(pa, b"CONNECT 127.0.0.1:25 HTTP/1.1\r\nHost: 127.0.0.1:25\r\n\r\n")
        check("CONNECT to a denied port gets 403", " 403 " in st, st)
        s = socket.create_connection(("127.0.0.1", pa), timeout=10)
        s.sendall(("CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n" % (eport, eport)).encode())
        got = b""
        while b"\r\n\r\n" not in got:
            got += s.recv(4096)
        check("CONNECT allowed port established", got.startswith(b"HTTP/1.1 200 Connection established"), repr(got))
        s.sendall(b"ping through tunnel")
        data = b""
        while len(data) < 19:
            d = s.recv(4096)
            if not d:
                break
            data += d
        s.close()
        check("CONNECT tunnel carries data both ways", data == b"PING THROUGH TUNNEL", repr(data))

        # basic auth
        req = "GET %s/hello HTTP/1.1\r\nHost: x\r\n%s\r\n"
        st, h, b = exchange(pb, (req % (base, "")).encode())
        check("auth: no credentials gets 407", " 407 " in st, st)
        check("auth: realm advertised", h.get("proxy-authenticate") == ['Basic realm="mayhem realm"'], str(h))
        st, h, b = exchange(pb, (req % (base, "Proxy-Authorization: Basic YWxpY2U6d3Jvbmc=\r\n")).encode())
        check("auth: wrong password gets 407", " 407 " in st, st)
        st, h, b = exchange(pb, (req % (base, "Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n")).encode())
        check("auth: correct credentials served", st.endswith("200 OK") and b == b"hello from origin", st + repr(b))
        st, h, b = exchange(pb, ("GET %s/headers HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n" % base).encode())
        check("auth: credentials not leaked to origin", b"proxy-authorization" not in b.lower(), repr(b))

        # reverse proxy
        st, h, b = exchange(pb, b"GET /app/hello HTTP/1.1\r\nHost: proxy.local\r\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n")
        check("reverse path maps to origin", st.endswith("200 OK") and b == b"hello from origin", st + repr(b))

        # access control and Via suppression
        st, h, b = exchange(pc, (req % (base, "")).encode())
        check("ACL: unlisted client gets 403", " 403 " in st, st)
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
    print("RESULT %d %d" % (passed, failed))


main()
