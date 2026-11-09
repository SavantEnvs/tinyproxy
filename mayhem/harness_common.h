/*
 * Shared plumbing for the tinyproxy harnesses.
 *
 * The request/response code in reqs.c talks to its peers through plain file
 * descriptors (recv/send), so each harness hands it one end of an AF_UNIX
 * socketpair that already holds the whole fuzz input and is shut down for
 * writing: every read either returns data or EOF and never blocks.
 *
 * The harnesses #include the .c file under test, which is the only way to
 * reach tinyproxy's static parsing functions without editing upstream.
 */
#ifndef MAYHEM_HARNESS_COMMON_H
#define MAYHEM_HARNESS_COMMON_H

#include "common.h"
#include "main.h"
#include "conf.h"
#include "log.h"
#include "stats.h"
#include "heap.h"

#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

/* Normally defined in main.c, which is not linked into the harnesses. */
struct config_s *config;
unsigned int received_sighup;

/* Larger inputs would not fit in a socketpair buffer without blocking. */
#define HARNESS_MAX_INPUT (48 * 1024)

/* log.c's descriptor for the log file; not declared in log.h. */
extern int log_file_fd;

static struct config_s harness_config;

/*
 * Log to /dev/null once, so log_message() neither buffers every message for
 * the lifetime of the process nor writes to the terminal, while still
 * formatting every message.
 */
static void harness_init(void)
{
        config = &harness_config;
        memset(&harness_config, 0, sizeof harness_config);
        setup_logging();
        log_file_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
        init_stats();
}

/* Queue `data` on a fresh socketpair, closed for writing. Returns 0 on success. */
static int harness_feed(int fds[2], const uint8_t *data, size_t size)
{
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) != 0)
                return -1;
        size_t off = 0;
        while (off < size) {
                ssize_t n = send(fds[0], data + off, size - off, MSG_NOSIGNAL);
                if (n <= 0) {
                        close(fds[0]);
                        close(fds[1]);
                        return -1;
                }
                off += (size_t) n;
        }
        shutdown(fds[0], SHUT_WR);
        return 0;
}

/*
 * tinyproxy sends output in many small writes, and every one of them costs a
 * socket buffer slot, so an unread socketpair fills up after a few hundred
 * writes and blocks. A reader thread empties the peer until the other end is
 * closed.
 */
struct harness_drain {
        pthread_t thread;
        int fd;
};

static void *harness_drain_main(void *arg)
{
        int fd = *(int *) arg;
        char buf[4096];
        while (recv(fd, buf, sizeof buf, 0) > 0)
                ;
        return NULL;
}

static void harness_drain_start(struct harness_drain *d, int fd)
{
        d->fd = fd;
        pthread_create(&d->thread, NULL, harness_drain_main, &d->fd);
}

/* Call after the writing end has been closed. */
static void harness_drain_join(struct harness_drain *d)
{
        pthread_join(d->thread, NULL);
        close(d->fd);
}

#endif
