/*
 * Quic protocol
 * Copyright (c) 2020 lz 
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include "avformat.h"
#include "libavutil/avassert.h"
#include "libavutil/parseutils.h"
#include "libavutil/opt.h"
#include "libavutil/time.h"

#include "internal.h"
#include "network.h"
#include "os_support.h"
#include "url.h"
#include "raw_quic_api.h"
#if HAVE_POLL_H
#include <poll.h>
#endif

typedef struct QuicContext {
    const AVClass *class;
    RawQuicHandle handle;
    int fd;
    int listen;
    int open_timeout;
    int rw_timeout;
    int listen_timeout;
    int recv_buffer_size;
    int send_buffer_size;
    int quic_nodelay;
#if !HAVE_WINSOCK2_H
    int quic_mss;
#endif /* !HAVE_WINSOCK2_H */
} QuicContext;

#define OFFSET(x) offsetof(QuicContext, x)
#define D AV_OPT_FLAG_DECODING_PARAM
#define E AV_OPT_FLAG_ENCODING_PARAM
static const AVOption options[] = {
    { "listen",          "Listen for incoming connections",  OFFSET(listen),         AV_OPT_TYPE_INT, { .i64 = 0 },     0,       2,       .flags = D|E },
    { "timeout",     "set timeout (in microseconds) of socket I/O operations", OFFSET(rw_timeout),     AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "listen_timeout",  "Connection awaiting timeout (in milliseconds)",      OFFSET(listen_timeout), AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "send_buffer_size", "Socket send buffer size (in bytes)",                OFFSET(send_buffer_size), AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "recv_buffer_size", "Socket receive buffer size (in bytes)",             OFFSET(recv_buffer_size), AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "quic_nodelay", "Use TCP_NODELAY to disable nagle's algorithm",           OFFSET(quic_nodelay), AV_OPT_TYPE_BOOL, { .i64 = 0 },             0, 1, .flags = D|E },
#if !HAVE_WINSOCK2_H
    { "quic_mss",     "Maximum segment size for outgoing TCP packets",          OFFSET(quic_mss),     AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
#endif /* !HAVE_WINSOCK2_H */
    { NULL }
};

static const AVClass quic_class = {
    .class_name = "quic",
    .item_name  = av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};

static void customize_fd(void *ctx, int fd)
{
    QuicContext *s = ctx;
    /* Set the socket's send or receive buffer sizes, if specified.
       If unspecified or setting fails, system default is used. */
    if (s->recv_buffer_size > 0) {
        if (setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &s->recv_buffer_size, sizeof (s->recv_buffer_size))) {
            ff_log_net_error(ctx, AV_LOG_WARNING, "setsockopt(SO_RCVBUF)");
        }
    }
    if (s->send_buffer_size > 0) {
        if (setsockopt (fd, SOL_SOCKET, SO_SNDBUF, &s->send_buffer_size, sizeof (s->send_buffer_size))) {
            ff_log_net_error(ctx, AV_LOG_WARNING, "setsockopt(SO_SNDBUF)");
        }
    }
    if (s->quic_nodelay > 0) {
        if (setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &s->quic_nodelay, sizeof (s->quic_nodelay))) {
            ff_log_net_error(ctx, AV_LOG_WARNING, "setsockopt(TCP_NODELAY)");
        }
    }
#if !HAVE_WINSOCK2_H
    if (s->quic_mss > 0) {
        if (setsockopt (fd, IPPROTO_TCP, TCP_MAXSEG, &s->quic_mss, sizeof (s->quic_mss))) {
            ff_log_net_error(ctx, AV_LOG_WARNING, "setsockopt(TCP_MAXSEG)");
        }
    }
#endif /* !HAVE_WINSOCK2_H */
}

static void TestConnectCallback(RawQuicHandle handle,
                         RawQuicError* error,
                         void* opaque) {
  av_log(NULL, AV_LOG_INFO, "ConnectCallback %d %d %d\n", error->error, error->net_error,
         error->quic_error);
}

static void TestErrorCallback(RawQuicHandle handle,
                       RawQuicError* error,
                       void* opaque) {
  av_log(NULL, AV_LOG_INFO, "ErrorCallback %d %d %d\n", error->error, error->net_error,
         error->quic_error);
}

static void TestCanReadCallback(RawQuicHandle handle, uint32_t size, void* opaque) {
  av_log(NULL, AV_LOG_INFO, "TestCanReadCallback %u\n", size);
}

/* return non zero if error */
static int quic_open(URLContext *h, const char *uri, int flags)
{  
    av_log(h, AV_LOG_ERROR, "uri:%s\n", uri);
    QuicContext *s = h->priv_data;
    RawQuicHandle handle = NULL;
    int ret;
    int port;
    char hostname[1024],proto[1024],path[1024];
    char portstr[10];
    
    av_url_split(proto, sizeof(proto), NULL, 0, hostname, sizeof(hostname),
        &port, path, sizeof(path), uri);
    
    RawQuicCallbacks callbacks;
    callbacks.connect_callback = TestConnectCallback;
    callbacks.error_callback = TestErrorCallback;
    callbacks.can_read_callback = NULL;
    do {
        handle = RawQuicOpen(callbacks, NULL, true);
        if (handle == 0) {
            av_log(h, AV_LOG_ERROR,
                   "Failed to open %s", uri);
            ret = -1;
            break;
        }
 
        av_log(h, AV_LOG_ERROR, "hostname:%s, port:%d", hostname, port);
        ret = RawQuicConnect(handle, hostname, port, "echo", 1000);
        if (ret != RAW_QUIC_ERROR_CODE_SUCCESS) {
            break;
        }
        
        s->handle = handle;
        ret = 0;

    } while(0);

    return ret;
}

static int quic_accept(URLContext *s, URLContext **c)
{
    return 0;
}

static int quic_read(URLContext *h, uint8_t *buf, int size)
{
    QuicContext *s = h->priv_data;
    int ret;

    ret = RawQuicRecv(s->handle, buf, size, 0);
    av_log(h, AV_LOG_ERROR, "read ret:%d, AVERROR(eagain):%d\n", ret, AVERROR(EAGAIN));
    if (ret == 0)
        return AVERROR_EOF;
    //return ret < 0 ? ff_neterrno() : ret;
    if (ret == RAW_QUIC_ERROR_CODE_EAGAIN)
        return AVERROR(EAGAIN);
    return ret;
}

static int quic_write(URLContext *h, const uint8_t *buf, int size)
{
    QuicContext *s = h->priv_data;
    int ret;

    ret = RawQuicSend(s->handle, buf, size);
    av_log(h, AV_LOG_ERROR, "quic wirte %d, %d\n", size, ret);
    //return ret < 0 ? ff_neterrno() : ret;
    return ret;
}

static int quic_shutdown(URLContext *h, int flags)
{
    return 0;
}

static int quic_close(URLContext *h)
{
    QuicContext *s = h->priv_data;
    RawQuicClose(s->handle);
    return 0;
}

static int quic_get_file_handle(URLContext *h)
{
    QuicContext *s = h->priv_data;
    return s->fd;
}

static int quic_get_window_size(URLContext *h)
{
    QuicContext *s = h->priv_data;
    int avail;
    socklen_t avail_len = sizeof(avail);

#if HAVE_WINSOCK2_H
    /* SO_RCVBUF with winsock only reports the actual TCP window size when
    auto-tuning has been disabled via setting SO_RCVBUF */
    if (s->recv_buffer_size < 0) {
        return AVERROR(ENOSYS);
    }
#endif

    if (getsockopt(s->fd, SOL_SOCKET, SO_RCVBUF, &avail, &avail_len)) {
        return ff_neterrno();
    }
    return avail;
}

const URLProtocol ff_quic_protocol = {
    .name                = "quic",
    .url_open            = quic_open,
    .url_accept          = quic_accept,
    .url_read            = quic_read,
    .url_write           = quic_write,
    .url_close           = quic_close,
    .url_get_file_handle = quic_get_file_handle,
    .url_get_short_seek  = quic_get_window_size,
    .url_shutdown        = quic_shutdown,
    .priv_data_size      = sizeof(QuicContext),
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
    .priv_data_class     = &quic_class,
};
