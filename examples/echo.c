/*
 echo.c
 
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

#include <websock.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    char *origin = "http://localhost";
    char *ver = libwebsock_version();
    libwebsock_listenserver_context *lwsls;
    libwebsock_context *ctx;
    
    lwsls = libwebsock_listenserver("0.0.0.0","8080");
    
    ctx = libwebsock_init_context();
    ctx->checkorigin = 1;
    ctx->origin = origin;
    
    printf("libwebsock Version: %s listening on port %d (sockfd: %d)\n", ver, lwsls->port, lwsls->sockfd);
    
    libwebsock_start(ctx, lwsls, 1024);
    libwebsock_shutdown(ctx);
    libwebsock_listenserver_stop(lwsls);
}
