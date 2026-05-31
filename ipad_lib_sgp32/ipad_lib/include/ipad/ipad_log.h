/**
 * @file ipad_log.h
 * @brief IPAd — Configurable log sink (serial / TCP)
 *
 * Provides three user-facing log levels with automatic timestamping and two
 * transport back-ends:
 *
 *   IPAD_LOGLVL_NONE  (0) — no output
 *   IPAD_LOGLVL_SIMPLE (1) — one line per event with ISO-8601 timestamp
 *   IPAD_LOGLVL_DETAIL (3) — full parameter dump, sub-millisecond timestamp
 *
 * Transports:
 *   IPAD_SINK_SERIAL  — POSIX serial port (e.g. /dev/ttyUSB0, /dev/ttyAMA0)
 *   IPAD_SINK_TCP     — TCP client; connect to a listener such as
 *                       `nc -l <port>`, PuTTY, or any custom application.
 *
 * Typical usage
 * -------------
 *   // After ipad_init():
 *
 *   ipad_log_sink_t sink;
 *
 *   // --- Serial ---
 *   ipad_log_sink_serial(&sink, "/dev/ttyUSB0", 115200);
 *   ipad_log_attach(hdl, &sink, IPAD_LOGLVL_DETAIL);
 *
 *   // --- TCP (connect to `nc -l 9000` running on the host) ---
 *   ipad_log_sink_tcp(&sink, "192.168.1.10", 9000);
 *   ipad_log_attach(hdl, &sink, IPAD_LOGLVL_SIMPLE);
 *
 *   // --- Detach ---
 *   ipad_log_detach(hdl, &sink);
 *   ipad_log_sink_close(&sink);
 */

#pragma once

#include "ipad.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ──────────────────────────────────────────────────────────────────────────────
 * User-facing log levels
 * ────────────────────────────────────────────────────────────────────────── */
typedef enum {
    IPAD_LOGLVL_NONE   = 0,   /**< No log output                            */
    IPAD_LOGLVL_SIMPLE = 1,   /**< Timestamp + module + short message        */
    IPAD_LOGLVL_DETAIL = 3,   /**< All above + full parameter detail (DEBUG) */
} ipad_user_loglvl_t;

/* ──────────────────────────────────────────────────────────────────────────────
 * Sink type
 * ────────────────────────────────────────────────────────────────────────── */
typedef enum {
    IPAD_SINK_SERIAL = 1,
    IPAD_SINK_TCP    = 2,
} ipad_sink_type_t;

/* ──────────────────────────────────────────────────────────────────────────────
 * Sink descriptor (opaque to the caller)
 * ────────────────────────────────────────────────────────────────────────── */
typedef struct {
    ipad_sink_type_t type;
    int              fd;          /**< file descriptor (serial tty or TCP socket) */
    char             host[64];    /**< TCP: remote host                           */
    uint16_t         port;        /**< TCP: remote port                           */
    char             device[64];  /**< Serial: device path                        */
    uint32_t         baudrate;    /**< Serial: baud rate (e.g. 115200)            */
} ipad_log_sink_t;

/* ──────────────────────────────────────────────────────────────────────────────
 * Sink constructors
 * ────────────────────────────────────────────────────────────────────────── */

/**
 * @brief Configure a serial-port sink.
 * @param sink      Sink to initialise.
 * @param device    Path to tty device, e.g. "/dev/ttyUSB0".
 * @param baudrate  Baud rate (9600, 115200, 921600 …).
 * @return IPAD_OK or IPAD_ERR_HAL_FAILURE.
 */
ipad_status_t ipad_log_sink_serial(ipad_log_sink_t *sink,
                                    const char      *device,
                                    uint32_t         baudrate);

/**
 * @brief Configure a TCP client sink.
 *
 * Connects immediately to host:port.  Use `nc -l <port>` or any TCP server
 * on the receiving side.  If the connection is lost, subsequent writes are
 * silently dropped until ipad_log_sink_tcp() is called again.
 *
 * @param sink  Sink to initialise.
 * @param host  Remote host (IPv4 dotted-decimal or hostname).
 * @param port  Remote TCP port.
 * @return IPAD_OK or IPAD_ERR_TRANSPORT.
 */
ipad_status_t ipad_log_sink_tcp(ipad_log_sink_t *sink,
                                 const char      *host,
                                 uint16_t         port);

/**
 * @brief Close the underlying transport (tty or socket).
 */
void ipad_log_sink_close(ipad_log_sink_t *sink);

/* ──────────────────────────────────────────────────────────────────────────────
 * Attach / detach to a library handle
 * ────────────────────────────────────────────────────────────────────────── */

/**
 * @brief Attach a sink to an IPAd handle and set the user log level.
 *
 * Internally calls ipad_log_set_handler() and ipad_log_set_level().
 * Only one sink can be attached per handle at a time; calling attach again
 * replaces the previous one.
 *
 * @param hdl    IPAd handle obtained from ipad_init().
 * @param sink   Configured sink (must outlive the handle or detach first).
 * @param level  One of IPAD_LOGLVL_NONE / SIMPLE / DETAIL.
 */
ipad_status_t ipad_log_attach(ipad_handle_t       hdl,
                               ipad_log_sink_t    *sink,
                               ipad_user_loglvl_t  level);

/**
 * @brief Detach the current log sink and restore silent mode.
 */
ipad_status_t ipad_log_detach(ipad_handle_t hdl, ipad_log_sink_t *sink);

#ifdef __cplusplus
}
#endif
