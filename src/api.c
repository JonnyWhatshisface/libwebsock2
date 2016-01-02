/*
  api.c

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "api.h"

#include "libwebsock_config.h" // Dynamically generated

char *libwebsock_version(void) {
    return WEBSOCK_PACKAGE_VERSION;
}

libwebsock_listenserver_context *libwebsock_listenserver(char *listen_host, char *port) {
    // Start listen server and return file descriptor
    struct addrinfo hints, *servinfo, *p;
    lws_sockfd sockfd = 0;
    int reuseaddr_on = 1;
    libwebsock_listenserver_context *state = (libwebsock_listenserver_context *)lws_malloc(sizeof(libwebsock_listenserver_context));
    
#ifdef _WIN32
    WSADATA WSAData;
    WSAStartup(0x01, &WSAData);
#endif
    
    if(listen_host && port != NULL) {
        
        memset(&hints, 0, sizeof(struct addrinfo));
        
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        
        if ((getaddrinfo(listen_host, port, &hints, &servinfo)) !=0) {
            perror("getaddrinfo() failed while attempting to bind socket... Exiting.\n");
        }
        
        for (p = servinfo; p != NULL; p = p->ai_next) {
            if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1 ) {
                perror("Error binding to an interface...\n");
                continue;
            }
            
            if(evutil_make_socket_nonblocking(sockfd) == -1) {
                perror("Unable to make socket non-blocking... Exiting.\n");
            }
            
            if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_on, sizeof(int)) == -1) {
                perror("Unable to set socket options...\n");
            }
            
            if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
                perror("Error binding socket to interface...\n");
                close(sockfd);
                continue;
            } else {
#ifdef LIBWEBSOCK_DEBUG
                fprintf(stderr,"Bound to socket fd [%i]\n",sockfd);
#endif
            }
            break;
        }
        
        if (p == NULL) {
            fprintf(stderr,"Failed to bind to address and port. Exiting.\n");
        }
        
        freeaddrinfo(servinfo);
        
        if(listen(sockfd, LISTEN_BACKLOG) == -1) {
            fprintf(stderr,"Listen call failed for socket fd. Exiting.\n");
            return NULL;
        }
    }
    
    state->port = atoi(port);
    state->sockfd = (lws_sockfd) sockfd;
    
    return state;
}

void libwebsock_listenserver_stop(libwebsock_listenserver_context *ctx) {
    close(ctx->sockfd);
    lws_free(ctx);
}

libwebsock_context *libwebsock_init_context(void) {
    libwebsock_context *ctx;
    if (evthread_use_pthreads()) {
        fprintf(stderr,"Unable to enable pthread usage for libevent\n");
        return NULL;
    }
    event_set_mem_functions(lws_malloc,lws_realloc,lws_free);
    struct event_base *base = event_base_new();
    if (!base) {
        fprintf(stderr,"Unable to create event base!\n");
        return NULL;
    }
    
    ctx = (libwebsock_context *) lws_calloc(sizeof(libwebsock_context));
    ctx->base = base;
    ctx->onclose = libwebsock_onclose_callback;
    ctx->onopen = libwebsock_onopen_callback;
    ctx->onmessage = libwebsock_onmessage_callback;
    ctx->oncontrolframe = libwebsock_oncontrolframe_callback;
    
    ctx->connection_workers = 4;
    ctx->dispatch_workers = 4;
    ctx->controlframe_workers = 4;
    ctx->evbase_count = 4;
    
    return ctx;
}

void libwebsock_start(libwebsock_context *ctx, libwebsock_listenserver_context *lsctx, unsigned int max_payload) {
    struct event *listener_event;
    lws_scheduler_init(ctx); // Initialize the scheduler for this context
    
    listener_event = event_new(ctx->base, lsctx->sockfd, EV_READ | EV_PERSIST, lws_handle_connection_request, (void *) ctx);
    event_add(listener_event, NULL);
#ifdef LIBWEBSOCK_DEBUG
    printf("libwebsock v%s initialized...\n", libwebsock_version());
    printf("Running on libevent version: %s\n", event_get_version());
#endif
    ctx->running = 1;
    event_base_loop(ctx->base, 0);
}

void libwebsock_shutdown(libwebsock_context *ctx) {
    lws_scheduler_shutdown(ctx);
        
    event_base_free(ctx->base);
}


