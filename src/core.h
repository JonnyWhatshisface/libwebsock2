/*
  core.h

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

#ifndef _core_h
#define _core_h

#include <assert.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/thread.h>
#include <pthread.h>
#include <wchar.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#ifdef WEBSOCK_HAVE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <event2/bufferevent_ssl.h>
#endif

#if defined(__linux__)
#  include <endian.h>
#elif defined(__FreeBSD__) || defined(__NetBSD__)
#  include <sys/endian.h>
#elif defined(__OpenBSD__)
#  include <sys/types.h>
#  define be16toh(x) betoh16(x)
#  define be64toh(x) betoh64(x)
#endif

#include "callbacks.h"
#include "utilities.h"
#include "websock.h"

#include "libwebsock_config.h"

#define LIBWEBSOCK_DEBUG

#define LWS_SCHEDULER_JOB_WRAPPERS 50               // Amount of job wrappers to pre-allocate
#define LWS_SCHEDULER_JOB_WRAPPERS_GC 100           // Amount of job wrappers to be allocated before GC'ing them

#define VM_MAX_STACK_SIZE 256

extern pthread_mutex_t gc_lock;

/* LWS_GC
 * Not implemented yet. Will be
 * used for garbage collection.
 */

typedef enum {
    OBJ_LWS_CONTEXT,
    OBJ_LWS_CLIENT,
    OBJ_LWS_MESSAGE,
    OBJ_LWS_FRAME
} gcObjectType;

typedef struct _gcObject {
    gcObjectType type;
    unsigned char marked;
    struct gcObject *next;
    union {
        /* OBJ_LWS_CONTEXT */
        libwebsock_context *ctx;
        /* OBJ_LWS_CLIENT */
        libwebsock_client_state *state;
        /* OBJ_LWS_MESSAGE */
        libwebsock_message *msg;
        /* OBJ_LWS_FRAME */
        libwebsock_frame *frame;
    };
} gcObject;

typedef struct {
    gcObject* stack[VM_MAX_STACK_SIZE];
    int stackSize;
    gcObject* firstObject;
    int numObjects;
    int maxObjects;
} LWS_VM;

/* Scheduler / Worker Begin */

typedef enum {
    LWS_CONNECTION_WORKER,
    LWS_CONTROLFRAME_WORKER,
    LWS_DISPATCH_WORKER,
    LWS_EVBASE_WORKER
} lws_worker_type;

typedef enum {
    LWS_CONNECTION,
    LWS_DISPATCH,
    LWS_CONTROLFRAME,
    LWS_FRAME,
    LWS_EVBASE,
    LWS_CONNECTION_CLOSE
} lws_job_type;

typedef enum {
    inprogress,
    finished
} lws_job_status;

typedef struct _lws_worker {
    pthread_t thread;
    unsigned short worker_number;
    unsigned short terminate;
    struct event_base *base;
    lws_worker_type worker_type;
    struct _lws_scheduler *scheduler;
    struct _lws_worker *prev;
    struct _lws_worker *next;
} lws_worker;

typedef struct _lws_evbase_loop_thread {
    pthread_t thread;
    unsigned short worker_number;
    unsigned short terminate;
    struct event_base *base;
} lws_evbase_loop_thread;

typedef struct _lws_job {
    void (*job_func)(struct _lws_job *job);
    void *data;
    void *data2;
    int sockfd;
    pthread_mutex_t job_lock;
    char ipaddr[INET_ADDRSTRLEN]; // Need to tie to client state
    int worker_number;
    lws_job_status status;
    lws_job_type type;
    libwebsock_context *ctx;
    pthread_mutex_t thread_lock;
    struct event_base *base;
    struct _lws_job *prev;
    struct _lws_job *next;
} lws_job;

typedef struct _lws_scheduler {
    struct _lws_worker *workers;
    struct _lws_job *pending_jobs;
    void *ctx;
    pthread_mutex_t lws_jobs_mutex;
    pthread_cond_t lws_jobs_cond;
} lws_scheduler;

typedef struct _lws_scheduler_context {
    lws_scheduler *connects;
    lws_scheduler *dispatcher;
    lws_scheduler *controlframes;
    lws_scheduler *evbase_scheduler;
    //lws_job *job_wrapper_pool;           // Pool of pre-allocated worker wrappers to reduce malloc calls
} lws_scheduler_context;

typedef struct _libwebsock_string {
    char *data;
    int length;
    int idx;
    int data_sz;
    pthread_mutex_t thread_lock;
} libwebsock_string;

typedef enum {
    LWS_HANDSHAKE_RECV,
    LWS_HANDSHAKE_ACK,
    LWS_HANDSHAKE_ERROR
} lws_handshake_status;

/* This is not in use yet
 
 typedef struct _lws_job_wrappers {
 int num;
 lws_job *wrapper;
 lws_job *prev;
 lws_job *next;
 } lws_job_wrapper;
 
 */

/* Scheduler / Worker End */

// core.c function definitions

void *lws_calloc(size_t);
void *lws_malloc(size_t);
void *lws_realloc(void *, size_t);
void lws_free(void *);

int lws_scheduler_init(libwebsock_context *);
void lws_scheduler_shutdown(libwebsock_context *);
void lws_scheduler_add_job(lws_job *item);
void lws_handle_signal(evutil_socket_t sig, short event, void *ptr);
void lws_evthread_handle_signal(evutil_socket_t sig, short event, void *ptr);
void lws_worker_cleanup(lws_worker *worker);
void *lws_worker_agent_function(void *ptr);
void *lws_evbase_thread_loop_function(void *ptr);

// websock.c function definitions

void lws_handle_connection_request(lws_sockfd fd, short ev, void *arg);
void lws_handle_accept(lws_job *);
void lws_handle_close(lws_job *);
void lws_add_client_to_evbase(lws_job *job);
void lws_parse_headers(void);

void libwebsock_handle_handshake(struct bufferevent *bev, void *ptr);
void libwebsock_schedule_recv(struct bufferevent *bev, void *ptr);
void libwebsock_handle_recv(lws_job *job);
void libwebsock_client_close(struct bufferevent *bev, short event, void *ptr);
void libwebsock_check_received(struct bufferevent *bev, void *ptr);

void libwebsock_fail_and_cleanup(void *ptr);
void libwebsock_new_continuation_frame(void *ptr);
void libwebsock_handle_control_frame(void *ptr);
void libwebsock_dispatch_message(void *ptr);
void libwebsock_schedule_dispatch(void *ptr);
void libwebsock_fail_connection(libwebsock_client_state *state, unsigned short close_code);
void libwebsock_cleanup_frames(libwebsock_frame *first);
void libwebsock_free_all_frames(libwebsock_client_state *state);

#endif /* core_h */
