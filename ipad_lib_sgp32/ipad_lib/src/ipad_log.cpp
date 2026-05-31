/**
 * @file ipad_log.cpp
 * @brief IPAd configurable log sink — serial and TCP implementations.
 */

#include "ipad/ipad_log.h"

#include <cstdio>
#include <cstring>
#include <ctime>
#include <cerrno>

/* POSIX */
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <termios.h>

/* ──────────────────────────────────────────────────────────────────────────────
 * Internal helpers
 * ────────────────────────────────────────────────────────────────────────── */

/* Map internal 5-level enum → library level for ipad_log_set_level() */
static ipad_loglevel_t user_to_internal(ipad_user_loglvl_t ul) {
    switch (ul) {
        case IPAD_LOGLVL_SIMPLE: return IPAD_LOG_INFO;
        case IPAD_LOGLVL_DETAIL: return IPAD_LOG_DEBUG;
        default:                 return IPAD_LOG_NONE;
    }
}

/* Level tag string */
static const char *level_tag(ipad_loglevel_t level) {
    switch (level) {
        case IPAD_LOG_ERROR: return "ERROR";
        case IPAD_LOG_WARN:  return "WARN ";
        case IPAD_LOG_INFO:  return "INFO ";
        case IPAD_LOG_DEBUG: return "DEBUG";
        default:             return "?    ";
    }
}

/*
 * Build a timestamped log line.
 *
 * SIMPLE format : [YYYY-MM-DD HH:MM:SS] [LEVEL] [module] message\n
 * DETAIL format : [YYYY-MM-DD HH:MM:SS.mmm] [LEVEL] [module] message\n
 *
 * Returns number of bytes written into buf (not including NUL).
 */
static int build_line(char *buf, size_t cap,
                       ipad_loglevel_t level, const char *module,
                       const char *message, ipad_user_loglvl_t user_lvl) {
    /* Timestamp */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm_info;
    localtime_r(&ts.tv_sec, &tm_info);

    char ts_buf[32];
    if (user_lvl >= IPAD_LOGLVL_DETAIL) {
        /* Sub-millisecond timestamp for detail level */
        strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S", &tm_info);
        int ms = (int)(ts.tv_nsec / 1000000);
        char tmp[40];
        snprintf(tmp, sizeof(tmp), "%s.%03d", ts_buf, ms);
        strncpy(ts_buf, tmp, sizeof(ts_buf) - 1);
    } else {
        strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S", &tm_info);
    }

    return snprintf(buf, cap, "[%s] [%s] [%s] %s\n",
                    ts_buf, level_tag(level), module, message);
}

/* Write fully to fd, ignore EINTR */
static void write_all(int fd, const char *buf, int len) {
    if (fd < 0 || len <= 0) return;
    while (len > 0) {
        int n = (int)write(fd, buf, (size_t)len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return;  /* drop on error (connection lost, etc.) */
        }
        buf += n;
        len -= n;
    }
}

/* ──────────────────────────────────────────────────────────────────────────────
 * Callback installed via ipad_log_set_handler()
 * ────────────────────────────────────────────────────────────────────────── */
struct SinkCtx {
    ipad_log_sink_t    *sink;
    ipad_user_loglvl_t  user_lvl;
};

static void sink_callback(ipad_loglevel_t level, const char *module,
                           const char *message, void *user_ctx) {
    auto *ctx = static_cast<SinkCtx *>(user_ctx);
    char line[1024];
    int  len = build_line(line, sizeof(line), level, module, message,
                           ctx->user_lvl);
    write_all(ctx->sink->fd, line, len);
}

/* One SinkCtx per active sink (small allocation, lives until detach) */
static SinkCtx *g_ctx = nullptr;

/* ──────────────────────────────────────────────────────────────────────────────
 * Serial sink
 * ────────────────────────────────────────────────────────────────────────── */
static speed_t baud_to_speed(uint32_t baud) {
    switch (baud) {
        case    9600: return B9600;
        case   19200: return B19200;
        case   38400: return B38400;
        case   57600: return B57600;
        case  115200: return B115200;
        case  230400: return B230400;
        case  460800: return B460800;
        case  921600: return B921600;
        default:      return B115200;
    }
}

ipad_status_t ipad_log_sink_serial(ipad_log_sink_t *sink,
                                    const char      *device,
                                    uint32_t         baudrate) {
    if (!sink || !device) return IPAD_ERR_INVALID_PARAM;
    memset(sink, 0, sizeof(*sink));
    sink->type     = IPAD_SINK_SERIAL;
    sink->baudrate = baudrate;
    strncpy(sink->device, device, sizeof(sink->device) - 1);

    int fd = open(device, O_WRONLY | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) return IPAD_ERR_HAL_FAILURE;

    /* Switch back to blocking after open */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);

    struct termios tio;
    memset(&tio, 0, sizeof(tio));
    cfsetospeed(&tio, baud_to_speed(baudrate));
    cfsetispeed(&tio, baud_to_speed(baudrate));
    /* 8N1, raw mode, no flow control */
    tio.c_cflag = CS8 | CLOCAL | CREAD;
    tio.c_iflag = IGNPAR;
    tio.c_oflag = 0;
    tio.c_lflag = 0;
    tio.c_cc[VMIN]  = 1;
    tio.c_cc[VTIME] = 0;
    tcflush(fd, TCOFLUSH);
    tcsetattr(fd, TCSANOW, &tio);

    sink->fd = fd;
    return IPAD_OK;
}

/* ──────────────────────────────────────────────────────────────────────────────
 * TCP sink
 * ────────────────────────────────────────────────────────────────────────── */
ipad_status_t ipad_log_sink_tcp(ipad_log_sink_t *sink,
                                 const char      *host,
                                 uint16_t         port) {
    if (!sink || !host || port == 0) return IPAD_ERR_INVALID_PARAM;
    memset(sink, 0, sizeof(*sink));
    sink->type = IPAD_SINK_TCP;
    sink->port = port;
    strncpy(sink->host, host, sizeof(sink->host) - 1);

    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res)
        return IPAD_ERR_TRANSPORT;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return IPAD_ERR_TRANSPORT; }

    /* Disable Nagle — we want each log line delivered immediately */
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        return IPAD_ERR_TRANSPORT;
    }
    freeaddrinfo(res);

    sink->fd = fd;
    return IPAD_OK;
}

/* ──────────────────────────────────────────────────────────────────────────────
 * Close
 * ────────────────────────────────────────────────────────────────────────── */
void ipad_log_sink_close(ipad_log_sink_t *sink) {
    if (!sink || sink->fd <= 0) return;
    close(sink->fd);
    sink->fd = -1;
}

/* ──────────────────────────────────────────────────────────────────────────────
 * Attach / detach
 * ────────────────────────────────────────────────────────────────────────── */
ipad_status_t ipad_log_attach(ipad_handle_t       hdl,
                               ipad_log_sink_t    *sink,
                               ipad_user_loglvl_t  level) {
    if (!hdl || !sink) return IPAD_ERR_INVALID_PARAM;

    if (level == IPAD_LOGLVL_NONE) {
        ipad_log_set_level(hdl, IPAD_LOG_NONE);
        ipad_log_set_handler(hdl, nullptr, nullptr);
        return IPAD_OK;
    }

    /* Replace previous context if any */
    delete g_ctx;
    g_ctx           = new SinkCtx{sink, level};
    ipad_log_set_level(hdl, user_to_internal(level));
    return ipad_log_set_handler(hdl, sink_callback, g_ctx);
}

ipad_status_t ipad_log_detach(ipad_handle_t hdl, ipad_log_sink_t * /*sink*/) {
    if (!hdl) return IPAD_ERR_INVALID_PARAM;
    ipad_log_set_handler(hdl, nullptr, nullptr);
    ipad_log_set_level(hdl, IPAD_LOG_NONE);
    delete g_ctx;
    g_ctx = nullptr;
    return IPAD_OK;
}
