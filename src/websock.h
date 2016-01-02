/*
  websock.h

    Jonathan D. Hall - jhall@futuresouth.us
    Copyright 2015 Future South Technologies

    This file is part of libwebsock.

    libwebsock is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    libwebsock is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with libwebsock.  If not, see <http://www.gnu.org/licenses/>.

*/

#ifndef _websocket_h
#define _websocket_h

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/thread.h>

#define LISTEN_BACKLOG 10

#define MASK_LENGTH 4
#define FRAME_CHUNK_LENGTH 1024

#define WS_OPCODE_CONTINUE 0x0
#define WS_OPCODE_TEXT 0x1
#define WS_OPCODE_BINARY 0x2
#define WS_OPCODE_CLOSE 0x8
#define WS_OPCODE_PING 0x9
#define WS_OPCODE_PONG 0xa

#define WS_CLOSE_NORMAL 1000
#define WS_CLOSE_GOING_AWAY 1001
#define WS_CLOSE_PROTOCOL_ERROR 1002
#define WS_CLOSE_NOT_ALLOWED 1003
#define WS_CLOSE_RESERVED 1004
#define WS_CLOSE_NO_CODE 1005
#define WS_CLOSE_DIRTY 1006
#define WS_CLOSE_WRONG_TYPE 1007
#define WS_CLOSE_POLICY_VIOLATION 1008
#define WS_CLOSE_MESSAGE_TOO_BIG 1009
#define WS_CLOSE_UNEXPECTED_ERROR 1011


#define STATE_SHOULD_CLOSE (1 << 0)
#define STATE_SENT_CLOSE_FRAME (1 << 1)
#define STATE_CONNECTING (1 << 2)
#define STATE_IS_SSL (1 << 3)
#define STATE_CONNECTED (1 << 4)
#define STATE_SENDING_FRAGMENT (1 << 5)
#define STATE_RECEIVING_FRAGMENT (1 << 6)
#define STATE_RECEIVED_CLOSE_FRAME (1 << 7)
#define STATE_FAILING_CONNECTION (1 << 8)


enum WS_FRAME_STATE {
    sw_start = 0,
    sw_got_two,
    sw_got_short_len,
    sw_got_full_len,
    sw_loaded_mask
};

typedef evutil_socket_t lws_sockfd;

typedef struct _libwebsock_listenserver_context {
    unsigned int port;
    lws_sockfd sockfd;
} libwebsock_listenserver_context;


typedef struct _libwebsock_frame {
    unsigned int fin;
    unsigned int opcode;
    unsigned int mask_offset;
    unsigned int payload_offset;
    unsigned int rawdata_idx;
    unsigned int rawdata_sz;
    unsigned int size;
    unsigned int payload_len_short;
    unsigned int payload_len;
    pthread_mutex_t thread_lock;
    char *rawdata;
    struct _libwebsock_frame *next_frame;
    struct _libwebsock_frame *prev_frame;
    unsigned char mask[4];
    enum WS_FRAME_STATE state;
} libwebsock_frame;

typedef struct _libwebsock_message {
    unsigned int opcode;
    unsigned long long payload_len;
    char *payload;
} libwebsock_message;

typedef struct _libwebsock_client_state {
    lws_sockfd sockfd;
    void *data;
    int flags;
    unsigned int handshake_status;
    void *client_tag; // Will be used to send by tag
    char ipaddr[INET_ADDRSTRLEN];
    struct sockaddr_storage *sa;
    char *headers;
    libwebsock_frame *current_frame;
    struct _libwebsock_context *ctx;
    struct event_base *base;
    struct bufferevent *buf_ev;
    struct evbuffer *output_buffer;
#ifdef WEBSOCK_HAVE_SSL
    SSL *ssl;
#endif
    pthread_mutex_t thread_lock;
    pthread_mutex_t frame_lock;
    struct _libwebsock_client_state *prev;
    struct _libwebsock_client_state *next;
} libwebsock_client_state;

typedef struct _libwebsock_context {
    unsigned short running;
    unsigned short ssl_init;
    unsigned int client_count;
    unsigned int connection_workers;
    unsigned int dispatch_workers;
    unsigned int controlframe_workers;
    unsigned int evbase_count;
    unsigned int checkorigin;
    char *origin;
    struct event_base *base;
    void *scheduler;
    pthread_mutex_t thread_lock;
    libwebsock_client_state *clients;
    libwebsock_listenserver_context *lsctx;
    int (*onmessage)(libwebsock_client_state *, libwebsock_message *);
    int (*oncontrolframe)(libwebsock_client_state *, libwebsock_frame *);
    int (*onopen)(libwebsock_client_state *);
    int (*onclose)(libwebsock_client_state *);
    int (*onpong)(libwebsock_client_state *);
    int (*onping)(libwebsock_client_state *);
} libwebsock_context;

/* API Function Definitions */

char *libwebsock_version(void);
libwebsock_context *libwebsock_init_context(void);
void libwebsock_listen(libwebsock_context *);
libwebsock_listenserver_context *libwebsock_listenserver(char *, char *);
void libwebsock_listenserver_stop(libwebsock_listenserver_context *ctx);
void libwebsock_start(libwebsock_context *, libwebsock_listenserver_context *, unsigned int);
void libwebsock_shutdown(libwebsock_context *ctx);

#endif /* websocket_h */
