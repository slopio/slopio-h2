/*
 * Reference server on libh2o, for `bench/vs-h2o.sh`: the routes of
 * `examples/bench_server.rs`, byte for byte, h2c, one event loop per thread.
 *
 *   /        200, `read <n> bytes\n`, n being the request body's length
 *   /<n>     200, n bytes of 'x', capped at 64 KiB
 *
 * No `server`, no `content-length`, no `content-type`: `:status` and nothing
 * else, which is what the other side sends — a header one side adds is bytes
 * on the wire that show up as a throughput difference. Bodies are served from
 * memory, never from a file handler, so the run compares h2o's HTTP/2 core to
 * ours and nothing else. See build.sh.
 */
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "h2o.h"
#include "h2o/http2.h"

#define FILLER_LEN (64 * 1024)
#define MAX_THREADS 64

static char filler[FILLER_LEN];
static uint16_t port = 8081;
static h2o_globalconf_t config;

/* One per thread, like h2o's own `num-threads`: a loop, a context, a listener. */
struct worker_t {
    int id;
    h2o_context_t ctx;
    h2o_accept_ctx_t accept_ctx;
};

/* How many bytes `/<n>` asks for; 0 when the path is not a number, which is
 * the echo. The same reading as `requested_size` on the other side. */
static size_t requested_size(h2o_iovec_t path)
{
    size_t n = 0;
    if (path.len < 2 || path.base[0] != '/')
        return 0;
    for (size_t i = 1; i < path.len; ++i) {
        if (path.base[i] < '0' || path.base[i] > '9')
            return 0;
        n = n * 10 + (size_t)(path.base[i] - '0');
        if (n > FILLER_LEN)
            n = FILLER_LEN;
    }
    return n;
}

static int on_req(h2o_handler_t *self, h2o_req_t *req)
{
    static h2o_generator_t generator = {NULL, NULL};
    h2o_iovec_t body;
    size_t n = requested_size(req->path_normalized);

    if (n != 0) {
        /* Static, and outlives the request: `h2o_send` takes it as is. */
        body = h2o_iovec_init(filler, n);
    } else {
        /* The other side pays a `format!` here; this pays a pool allocation. */
        char *buf = h2o_mem_alloc_pool(&req->pool, char, 48);
        int len = snprintf(buf, 48, "read %zu bytes\n", req->entity.len);
        body = h2o_iovec_init(buf, (size_t)len);
    }

    req->res.status = 200;
    req->res.reason = "OK";
    /* SIZE_MAX is h2o's "unset", which is what suppresses the header. */
    req->res.content_length = SIZE_MAX;
    h2o_start_response(req, &generator);
    h2o_send(req, &body, 1, H2O_SEND_STATE_FINAL);
    return 0;
}

static void on_accept(h2o_socket_t *listener, const char *err)
{
    struct worker_t *worker = listener->data;
    h2o_socket_t *sock;
    if (err != NULL || (sock = h2o_evloop_socket_accept(listener)) == NULL)
        return;
    h2o_accept(&worker->accept_ctx, sock);
}

/* `SO_REUSEPORT` and a listener per worker, as `MultiAccept` does: one shared
 * listener would be compared on accept capacity as much as on serving. */
static int create_listener(struct worker_t *worker)
{
    struct sockaddr_in addr;
    int fd, on = 1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1 || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) != 0 ||
        bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, 4096) != 0)
        return -1;
    h2o_socket_t *sock = h2o_evloop_socket_create(worker->ctx.loop, fd, H2O_SOCKET_FLAG_DONT_READ);
    sock->data = worker;
    h2o_socket_read_start(sock, on_accept);
    return 0;
}

static void *run_worker(void *arg)
{
    struct worker_t *worker = arg;

    h2o_context_init(&worker->ctx, h2o_evloop_create(), &config);
    worker->accept_ctx.ctx = &worker->ctx;
    worker->accept_ctx.hosts = config.hosts;
    if (create_listener(worker) != 0) {
        perror("listen");
        exit(1);
    }
    while (h2o_evloop_run(worker->ctx.loop, INT32_MAX) == 0)
        ;
    return NULL;
}

int main(int argc, char **argv)
{
    const char *v;

    signal(SIGPIPE, SIG_IGN);
    memset(filler, 'x', sizeof(filler));
    if ((v = getenv("PORT")) != NULL)
        port = (uint16_t)atoi(v);

    h2o_config_init(&config);
    /* h2o stamps `server: h2o/...` unless the name is empty. */
    config.server_name = h2o_iovec_init(H2O_STRLIT(""));
    /* `MAX_CONCURRENT_STREAMS` on the other side; h2o's default is 100. */
    config.http2.max_streams = 64;
    config.http2.max_concurrent_requests_per_connection = 64;
    h2o_hostconf_t *hostconf = h2o_config_register_host(&config, h2o_iovec_init(H2O_STRLIT("default")), 65535);
    h2o_pathconf_t *pathconf = h2o_config_register_path(hostconf, "/", 0);
    h2o_handler_t *handler = h2o_create_handler(pathconf, sizeof(*handler));
    handler->on_req = on_req;

    /* `THREADS=n`: n workers, placed by the caller's `taskset`. */
    int nthreads = (v = getenv("THREADS")) != NULL ? atoi(v) : 1;
    if (nthreads < 1 || nthreads > MAX_THREADS)
        nthreads = 1;
    static struct worker_t workers[MAX_THREADS];
    pthread_t tids[MAX_THREADS];
    for (int i = 0; i < nthreads; ++i) {
        workers[i].id = i;
        pthread_create(&tids[i], NULL, run_worker, &workers[i]);
    }
    printf("h2o reference on :%u (h2c), %d thread(s)\n", port, nthreads);
    fflush(stdout);
    for (int i = 0; i < nthreads; ++i)
        pthread_join(tids[i], NULL);
    return 1;
}
