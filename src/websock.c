/*
  websock.c

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

#include "core.h"
#include "utilities.h"
#include "websock.h"

#define AA libwebsock_dispatch_message
#define BB libwebsock_handle_control_frame
#define CC libwebsock_new_continuation_frame
#define DD libwebsock_fail_and_cleanup

static void (* const libwebsock_frame_lookup_table[512])(
                                                         void *) = {
				DD, CC, CC, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, //00..0f
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//10..1f
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//20..2f
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//30..3f
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//40..4f
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//50..5f
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//60..6f
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//70..7f
				DD, AA, AA, DD, DD, DD, DD, DD, BB, BB, BB, DD, DD, DD, DD, DD,//80..8f
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//90..9f
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//a0..af
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//b0..bf
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//c0..cf
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//d0..df
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//e0..ef
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//f0..ff
				CC, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//100..10f
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//110..11f
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//120..12f
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//130..13f
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//140..14f
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//150..15f
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//160..16f
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//170..17f
				AA, DD, DD, DD, DD, DD, DD, DD, BB, BB, BB, DD, DD, DD, DD, DD,//180..18f
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//190..19f
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//1a0..1af
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//1b0..1bf
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//1c0..1cf
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD,//1d0..1df
				DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD, DD//1f0..1ff
};

static inline int libwebsock_read_header(libwebsock_frame *frame) {
    int i, new_size;
    enum WS_FRAME_STATE state;
    
    pthread_mutex_lock(&frame->thread_lock);
    state = frame->state;
    switch (state) {
        case sw_start:
            if (frame->rawdata_idx < 2) {
                return 0;
            }
            frame->state = sw_got_two;
        case sw_got_two:
            frame->mask_offset = 2;
            frame->fin = (*(frame->rawdata) & 0x80) == 0x80 ? 1 : 0;
            frame->opcode = *(frame->rawdata) & 0xf;
            frame->payload_len_short = *(frame->rawdata + 1) & 0x7f;
            frame->state = sw_got_short_len;
        case sw_got_short_len:
            switch (frame->payload_len_short) {
                case 126:
                    if (frame->rawdata_idx < 4) {
                        return 0;
                    }
                    frame->mask_offset += 2;
                    frame->payload_offset = frame->mask_offset + MASK_LENGTH;
                    frame->payload_len = ntohs(
                                               *((unsigned short int *) (frame->rawdata + 2)));
                    frame->state = sw_got_full_len;
                    break;
                case 127:
                    if (frame->rawdata_idx < 10) {
                        return 0;
                    }
                    frame->mask_offset += 8;
                    frame->payload_offset = frame->mask_offset + MASK_LENGTH;
                    frame->payload_len = ntohl(*((unsigned int *) (frame->rawdata + 6)));
                    frame->state = sw_got_full_len;
                    break;
                default:
                    frame->payload_len = frame->payload_len_short;
                    frame->payload_offset = frame->mask_offset + MASK_LENGTH;
                    frame->state = sw_got_full_len;
                    break;
            }
        case sw_got_full_len:
            if (frame->rawdata_idx < frame->payload_offset) {
                pthread_mutex_unlock(&frame->thread_lock);
                return 0;
            }
            for (i = 0; i < MASK_LENGTH; i++) {
                frame->mask[i] = *(frame->rawdata + frame->mask_offset + i) & 0xff;
            }
            frame->state = sw_loaded_mask;
            frame->size = frame->payload_offset + frame->payload_len;
            if (frame->size > frame->rawdata_sz) {
                new_size = frame->size;
                new_size--;
                new_size |= new_size >> 1;
                new_size |= new_size >> 2;
                new_size |= new_size >> 4;
                new_size |= new_size >> 8;
                new_size |= new_size >> 16;
                new_size++;
                frame->rawdata_sz = new_size;
                frame->rawdata = (char *) lws_realloc(frame->rawdata, new_size);
            }
            pthread_mutex_unlock(&frame->thread_lock);
            return 1;
        case sw_loaded_mask:
            return 1;
    }
    pthread_mutex_unlock(&frame->thread_lock);
    return 0;
}

void lws_handle_connection_request(lws_sockfd fd, short ev, void *arg) {
    struct sockaddr_in client_addr;
    char ipaddr[INET_ADDRSTRLEN];
    socklen_t client_len = sizeof(client_addr);
    int client_state_fd = accept(fd, (struct sockaddr *) &client_addr, &client_len);
    
    inet_ntop(AF_INET, &(client_addr.sin_addr), ipaddr, INET_ADDRSTRLEN);
    lws_job *job_wrapper = (lws_job *) lws_malloc(sizeof(lws_job)); // Free this
    memcpy(job_wrapper->ipaddr, &ipaddr, sizeof(ipaddr));
    job_wrapper->ctx = arg;
    job_wrapper->sockfd = client_state_fd;
//    job_wrapper->job_func = lws_add_client_to_evbase;
    job_wrapper->job_func = lws_handle_accept;
    job_wrapper->status = inprogress;
    //job_wrapper->type = LWS_EVBASE;
    job_wrapper->type = LWS_CONNECTION;
    lws_scheduler_add_job(job_wrapper);
}

void lws_handle_accept(lws_job *job) {
    libwebsock_client_state *client_state = (libwebsock_client_state *) lws_calloc(sizeof(libwebsock_client_state));
    struct bufferevent *bev;
    struct timeval tv = {5,0};
    
#ifdef LIBWEBSOCK_DEBUG
    printf("[%s]: Assigned evbase [%p] for connection from [%s]...\n", __func__, job->base,job->ipaddr);
#endif
    
    evutil_make_socket_nonblocking(job->sockfd);
    client_state->buf_ev = bufferevent_socket_new(job->base, job->sockfd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);
    memcpy(client_state->ipaddr, &job->ipaddr, sizeof(job->ipaddr));
    
    //client_state->buf_ev = bev;
    client_state->base = job->base;
    //if((client_state->base = event_base_new()) == NULL) {
    //    perror("Unable create client event base...\n");
    //}
    client_state->ctx = job->ctx;
    client_state->sockfd = (int)job->sockfd;
    client_state->flags |= STATE_CONNECTING;
    client_state->handshake_status = 0;
    /*
     * On receiving data, we want to immediately check for
     * the handshake. We have nothing to send on connect,
     * hence the null. If the socket closes at any time, we
     * want to know about it -> libwebsock_client_close();
     */
    
    bufferevent_setcb(client_state->buf_ev, libwebsock_handle_handshake, NULL, libwebsock_client_close, (void *) client_state);
    bufferevent_set_timeouts(client_state->buf_ev, &tv,&tv);
    bufferevent_enable(client_state->buf_ev, EV_READ|EV_WRITE);
    
    job->ctx->client_count++; // Perhaps only count this when the handshake is done??
#ifdef LIBWEBSOCK_DEBUG
    printf("[%s]: Connect worker [%d] handling accept for [%s]... FD: %d - %d connected clients\n", __func__, job->worker_number, job->ipaddr, job->sockfd, job->ctx->client_count);
#endif
    
    job->status = finished; // Mark the job as finished and it will get free'd
#ifdef LIBWEBSOCK_DEBUG
    printf("[%s]: Connection established on event base [%p]\n", __func__, job->base);
#endif

}

void libwebsock_schedule_recv(struct bufferevent *bev, void *ptr) {
    libwebsock_client_state *state = ptr;
    /*
    lws_job *job_wrapper = (lws_job *) lws_malloc(sizeof(lws_job)); // Free this
    
    job_wrapper->status = inprogress;
    job_wrapper->ctx = state->ctx;
    job_wrapper->data = state;
    job_wrapper->data2 = bev;
    job_wrapper->job_func = libwebsock_handle_recv;
    job_wrapper->type = LWS_DISPATCH;
    
    lws_scheduler_add_job(job_wrapper);
 */
    
    libwebsock_frame *current = NULL;
    struct evbuffer *input;
    struct evbuffer_iovec iovec[3], *iovec_p;
    int i, datalen, err, n_vec, consumed, in_fragment;
    void (*frame_fn)(void *);
    char *buf;
    
    pthread_mutex_lock(&state->thread_lock);
    
    input = bufferevent_get_input(bev);
    n_vec = evbuffer_peek(input, -1, NULL, iovec, 2);
    assert(n_vec > 0 && n_vec <= 2);
    iovec[n_vec].iov_base = NULL;
    iovec_p = iovec;
    consumed = 0;
    while ((buf = iovec_p->iov_base) != NULL) {
        datalen = (iovec_p++)->iov_len;
        consumed += datalen;
        for (i = 0; i < datalen;) {
            current = state->current_frame;
            if (current == NULL) {
                current = (libwebsock_frame *) lws_calloc(sizeof(libwebsock_frame));
                current->payload_len = -1;
                current->rawdata_sz = FRAME_CHUNK_LENGTH;
                current->rawdata = (char *) lws_malloc(FRAME_CHUNK_LENGTH);
                state->current_frame = current;
            }
            
            *(current->rawdata + current->rawdata_idx++) = *buf++;
            i++;
            
            if (current->state != sw_loaded_mask) {
                err = libwebsock_read_header(current);
                if (err == -1) {
                    if ((state->flags & STATE_SENT_CLOSE_FRAME) == 0) {
                        libwebsock_fail_connection(state, WS_CLOSE_PROTOCOL_ERROR);
                        continue;
                    }
                }
                if (err == 0) {
                    continue;
                }
            }
            
            if (current->rawdata_idx < current->size) {
                if (datalen - i >= current->size - current->rawdata_idx) { //remaining in current vector completes frame.  Copy remaining frame size
                    memcpy(current->rawdata + current->rawdata_idx, buf,
                           current->size - current->rawdata_idx);
                    buf += current->size - current->rawdata_idx;
                    i += current->size - current->rawdata_idx;
                    current->rawdata_idx = current->size;
                } else { //not complete frame, copy the rest of this vector into frame.
                    memcpy(current->rawdata + current->rawdata_idx, buf, datalen - i);
                    current->rawdata_idx += datalen - i;
                    i = datalen;
                    continue;
                }
            }
            
            //have full frame at this point
            
            if (state->flags & STATE_FAILING_CONNECTION) {
                if (current->opcode != WS_OPCODE_CLOSE) {
                    libwebsock_cleanup_frames(current);
                    state->current_frame = NULL;
                    continue;
                }
            }
            
            in_fragment = (state->flags & STATE_RECEIVING_FRAGMENT) ? 256 : 0;
            
            frame_fn = libwebsock_frame_lookup_table[in_fragment
                                                     | (*current->rawdata & 0xff)];
            /*
            job_wrapper->status = inprogress;
            job_wrapper->ctx = state->ctx;
            job_wrapper->data = state;
            job_wrapper->data2 = bev;
            job_wrapper->job_func = (void *)frame_fn;
            job_wrapper->type = LWS_DISPATCH;
            
            lws_scheduler_add_job(job_wrapper);
             */
            
            frame_fn(state);
        }
    }
    evbuffer_drain(input, consumed);
    pthread_mutex_unlock(&state->thread_lock);

}

void libwebsock_handle_handshake(struct bufferevent *bev, void *ptr) {
    libwebsock_client_state *state = ptr;
    if(!state) {
        printf("State does not exist...\n");
        return;
    }

    switch (state->handshake_status) {
            
        case 0 :
        {
            // Handshake not done or checked
            libwebsock_string *state_data_string = state->data;
            struct evbuffer *input;
            char buf[1024];
            int datalen;
            
            input = bufferevent_get_input(bev);
            
            if (state->data == NULL) {
                state->data = (libwebsock_string *) lws_calloc(sizeof(libwebsock_string));
                state_data_string = state->data;
                state_data_string->data_sz = FRAME_CHUNK_LENGTH;
                state_data_string->data = (char *) lws_calloc(FRAME_CHUNK_LENGTH);
            }
            

            while (evbuffer_get_length(input)) {
                datalen = evbuffer_remove(input, buf, sizeof(buf));
                if (state_data_string->idx + datalen >= state_data_string->data_sz) {
                    // The handshake shouldn't be more than 1,024 bytes...
                    bufferevent_setcb(bev, NULL,NULL,NULL,NULL);
                    libwebsock_client_close(bev, BEV_EVENT_ERROR | BEV_EVENT_EOF, state);
                    break;
                    
                }
                memcpy(state_data_string->data + state_data_string->idx, buf, datalen);
                state_data_string->idx += datalen;
            
                
                if(strstr(state_data_string->data, "\r\n\r\n") != NULL || strstr(state_data_string->data, "\n\n") != NULL) {
                    state->handshake_status = 1;
                    libwebsock_handle_handshake(bev, (void *) state);
                }
            }
            break;
        }
            
        case 1 :
        {
            // Complete the handshake...
            libwebsock_context *ctx = state->ctx;
            libwebsock_string *str = state->data;
            struct evbuffer *output;
            struct timeval tv = {120,0};
            char buf[1024], sha1buf[45], concat[1024];
            unsigned char sha1mac[20];
            char *tok = NULL, *headers = NULL, *key = NULL, *base64buf = NULL, *protocol = NULL, *origin = NULL;
            const char *GID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
            SHA1Context shactx;
            SHA1Reset(&shactx);
            int n = 0;
            
            output = bufferevent_get_output(bev);
            headers = str->data;
            
#ifdef LIBWEBSOCK_DEBUG
            printf("[%s]: Received the following headers:\n\n%s", __func__, headers);
#endif
            
            for (tok = strtok(headers, "\r\n"); tok != NULL; tok = strtok(NULL, "\r\n")) {
                if (strstr(tok, "Sec-WebSocket-Key: ") != NULL) {
                    key = (char *) lws_calloc(strlen(tok));
                    strncpy(key, tok + strlen("Sec-WebSocket-Key: "), strlen(tok));
                } else if (strstr(tok, "Sec-WebSocket-Protocol: ") != NULL) {
                    protocol = strdup(tok);
                } else if (strstr(tok, "Origin: ") != NULL) {
                    origin = (char *) lws_calloc(strlen(tok));
                    strncpy(origin, tok + strlen("Origin: "), strlen(tok));
                }
            }
            
            if (protocol) {
                char *comma = strchr(protocol, ',');
                if (comma)
                    *comma = '\0';
            }
            
            if(headers)
                lws_free(headers);
            state->data = NULL;
            
            if (key == NULL) {
#ifdef LIBWEBSOCK_DEBUG
                printf("[%s]: Unable to find key in request headers...\n", __func__);
#endif
                lws_free(protocol);
                lws_free(origin);
                lws_free(key);
                // Close the connection...
                bufferevent_setcb(bev, NULL,NULL,NULL,NULL);
                libwebsock_client_close(bev, BEV_EVENT_ERROR | BEV_EVENT_EOF, state);
                break;
            }
            
            // Check if specific origin is required
            if(state->ctx->checkorigin == 1) {
                if(origin) {
                    if (strcmp(origin, state->ctx->origin) != 0) {
                        if (protocol)
                            lws_free(protocol);
                        if (key)
                            lws_free(key);
                        if (origin)
                            lws_free(origin);
                        bufferevent_setcb(bev, NULL,NULL,NULL,NULL);
                        libwebsock_client_close(bev, BEV_EVENT_ERROR | BEV_EVENT_EOF, state);
                        break;
                    }
                } else {
                    // Origin was not supplied, close the session
                    if (protocol)
                        lws_free(protocol);
                    if (key)
                        lws_free(key);
                    if (origin)
                        lws_free(origin);
                    bufferevent_setcb(bev, NULL,NULL,NULL,NULL);
                    libwebsock_client_close(bev, BEV_EVENT_ERROR | BEV_EVENT_EOF, state);
                    break;
                }
            }
            
            memset(concat, '\0', sizeof(concat));
            strncat(concat, key, strlen(key));
            strncat(concat, GID, strlen(GID));
            
            SHA1Input(&shactx, (unsigned char *) concat, strlen(concat));
            SHA1Result(&shactx);
            if (key)
                lws_free(key);
            key = NULL;
            
            sprintf(sha1buf, "%08x%08x%08x%08x%08x", shactx.Message_Digest[0],
                    shactx.Message_Digest[1], shactx.Message_Digest[2],
                    shactx.Message_Digest[3], shactx.Message_Digest[4]);
            for (n = 0; n < (strlen(sha1buf) / 2); n++) {
                sscanf(sha1buf + (n * 2), "%02hhx", sha1mac + n);
            }
            base64buf = (char *) lws_malloc(256);
            base64_encode(sha1mac, 20, base64buf, 256);
            memset(buf, 0, 1024);
            snprintf(buf, 1024, "HTTP/1.1 101 Switching Protocols\r\n"
                     "Server: %s/%s\r\n"
                     "Upgrade: websocket\r\n"
                     "%s%s%s"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Accept: %s\r\n%s%s"
                     "Access-Control-Allow-Headers: content-type\r\n\r\n", WEBSOCK_PACKAGE_NAME,
                     WEBSOCK_PACKAGE_VERSION, origin ? "Access-Control-Allow-Origin: " : "", origin ? origin : "", origin ? "\r\n" : "", base64buf, protocol ? protocol : "", protocol ? "\r\n" : "");
            
#ifdef LIBWEBSOCK_DEBUG
            printf("[%s]: Sent the following response: \n\n%s", __func__, buf);
#endif
            if (base64buf)
                lws_free(base64buf);
            if(protocol)
                lws_free(protocol);
            if (origin)
                lws_free(origin);
            
            evbuffer_add(output, buf, strlen(buf));
            
            state->flags &= ~STATE_CONNECTING;
            state->flags |= STATE_CONNECTED;
            
            state->next = ctx->clients;
            if (state->next) {
                state->next->prev = state;
            }
            
            state->handshake_status = 2;
            ctx->clients = state;
            bufferevent_lock(bev);
            bufferevent_set_timeouts(bev, &tv,&tv);
            bufferevent_setcb(bev, libwebsock_schedule_recv, NULL, libwebsock_client_close, (void *) state);
            bufferevent_unlock(bev);
            
            break;
        }
            
        default :
            // Why did we hit this?
            break;
    }
}


void libwebsock_client_close(struct bufferevent *bev, short event, void *ptr) {

    libwebsock_client_state *state = ptr;
    
    if(event & (BEV_EVENT_TIMEOUT)) {
#ifdef LIBWEBSOCK_DEBUG 
        printf("[%s]: Connection to [%s] timed out...\n", __func__, state->ipaddr);
#endif
        lws_job *job_wrapper = (lws_job *) lws_malloc(sizeof(lws_job));
        job_wrapper->ctx = state->ctx;
        job_wrapper->job_func = lws_handle_close;
        job_wrapper->data = ptr;
        job_wrapper->data2 = state->buf_ev;
        job_wrapper->type = LWS_CONNECTION_CLOSE;
        job_wrapper->status = inprogress;
        lws_scheduler_add_job(job_wrapper);
    }
    
    if (event & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
        lws_job *job_wrapper = (lws_job *) lws_malloc(sizeof(lws_job));
        job_wrapper->ctx = state->ctx;
        job_wrapper->job_func = lws_handle_close;
        job_wrapper->data = ptr;
        job_wrapper->data2 = state->buf_ev;
        job_wrapper->type = LWS_CONNECTION_CLOSE;
        job_wrapper->status = inprogress;
        lws_scheduler_add_job(job_wrapper);
    }
     
}

void lws_handle_close(lws_job *job) {
    struct bufferevent *bev = job->data2;
    libwebsock_client_state *state = job->data;
    pthread_mutex_lock(&job->ctx->thread_lock);
    job->ctx->client_count--;
    pthread_mutex_unlock(&job->ctx->thread_lock);
    bufferevent_free(bev);
    lws_free(state->data);
    lws_free(state->headers);
#ifdef LIBWEBSOCK_DEBUG
    printf("[%s]: Socket closing for [%s] - sockfd: [%d]\n", __func__, state->ipaddr, state->sockfd);
#endif
    lws_free(state); // Free the client_state
    job->status = finished;
}

void libwebsock_dispatch_message(void *ptr) {
    libwebsock_client_state *state = ptr;
    pthread_mutex_lock(&state->thread_lock);

    unsigned int current_payload_len;
    unsigned long long message_payload_len;
    int message_opcode, i;
    libwebsock_frame *current = state->current_frame;
    libwebsock_message *msg = NULL;
    char *message_payload, *message_payload_orig, *rawdata_ptr;
    
    state->flags &= ~STATE_RECEIVING_FRAGMENT;
    if (state->flags & STATE_SENT_CLOSE_FRAME) {
        pthread_mutex_unlock(&state->thread_lock);
        return;
    }
    libwebsock_frame *first = NULL;
    if (current == NULL) {
        fprintf(stderr,
                "Somehow, null pointer passed to libwebsock_dispatch_message.\n");
        exit(1);
    }
    message_payload_len = 0;
    for (; current->prev_frame != NULL; current = current->prev_frame) {
        message_payload_len += current->payload_len;
    }
    message_payload_len += current->payload_len;
    first = current;
    message_opcode = current->opcode;
    message_payload = (char *) lws_malloc(message_payload_len + 1);
    message_payload_orig = message_payload;
    
    for (; current != NULL; current = current->next_frame) {
        current_payload_len = current->payload_len;
        rawdata_ptr = current->rawdata + current->payload_offset;
        for (i = 0; i < current_payload_len; i++) {
            *message_payload++ = *rawdata_ptr++ ^ current->mask[i & 3];
        }
    }
    
    *(message_payload) = '\0';
    
    if (message_opcode == WS_OPCODE_TEXT) {
        if (!validate_utf8_sequence((uint8_t *) message_payload_orig)) {
            fprintf(stderr, "Error validating UTF-8 sequence.\n");
#ifdef LIBWEBSOCK_DEBUG
            fprintf(stderr, "[%s]: freeing message_payload_orig at address: %p\n",
                    __func__, message_payload_orig);
#endif
            lws_free(message_payload_orig);
            libwebsock_fail_connection(state, WS_CLOSE_WRONG_TYPE);
            libwebsock_cleanup_frames(first);
            state->current_frame = NULL;
            pthread_mutex_unlock(&state->thread_lock);
            return;
        }
    }
    
    libwebsock_cleanup_frames(first->next_frame);
    first->rawdata_idx = 0;
    first->next_frame = NULL;
    first->payload_len = -1;
    first->state = 0;
    state->current_frame = first;
    

    
    msg = (libwebsock_message *) lws_malloc(sizeof(libwebsock_message));
    msg->opcode = message_opcode;
    msg->payload_len = message_payload_len;
    msg->payload = message_payload_orig;
    
    pthread_mutex_unlock(&state->thread_lock);
    
    lws_job *job_wrapper = (lws_job *) lws_malloc(sizeof(lws_job)); // Free this
    
    job_wrapper->status = inprogress;
    job_wrapper->ctx = state->ctx;
    job_wrapper->data = state;
    job_wrapper->data2 = msg;
    job_wrapper->job_func = libwebsock_schedule_dispatch;
    job_wrapper->type = LWS_DISPATCH;
    
    lws_scheduler_add_job(job_wrapper);

}

void libwebsock_schedule_dispatch(void *ptr) {
    lws_job *job = ptr;
    libwebsock_client_state *state = job->data;
    libwebsock_message *msg = job->data2;
    
    printf("Message dispatched: %s\n", msg->payload);
    
    lws_free(msg);
    
    job->status = finished;
}

void libwebsock_handle_control_frame(void *ptr) {
    printf("[%s]: Reached...\n", __func__);

}

void libwebsock_new_continuation_frame(void *ptr) {
    lws_job *job = ptr;
    libwebsock_client_state *state = job->data;
    printf("[%s]: Reached...\n", __func__);
}

void libwebsock_cleanup_frames(libwebsock_frame *first) {
    libwebsock_frame *this = NULL;
    libwebsock_frame *next = first;
    while (next != NULL) {
        this = next;
        next = this->next_frame;
        if (this->rawdata != NULL) {
#ifdef LIBWEBSOCK_DEBUG
            fprintf(stderr, "[%s]: freeing rawdata from frame with address: %p\n", __func__, this->rawdata);
#endif
            lws_free(this->rawdata);
        }
#ifdef LIBWEBSOCK_DEBUG
        fprintf(stderr, "[%s]: freeing this from frame with address: %p\n", __func__, this);
#endif
        lws_free(this);
    }
}

void libwebsock_fail_and_cleanup(void *ptr) {
    lws_job *job = ptr;
    libwebsock_client_state *state = job->data;
#ifdef LIBWEBSOCK_DEBUG
    printf("[%s]: Failing connection and cleaning frames...\n", __func__);
#endif
    libwebsock_free_all_frames(state);
    libwebsock_fail_connection(state, WS_CLOSE_PROTOCOL_ERROR);
    state->current_frame = NULL;

}

void libwebsock_fail_connection(libwebsock_client_state *state, unsigned short close_code) {

#ifdef LIBWEBSOCK_DEBUG
    printf("[%s]: Failing connection due to protocol error...\n", __func__);
#endif
    
    struct bufferevent *bev = state->buf_ev;

    struct evbuffer *output = bufferevent_get_output(state->buf_ev);
    char close_frame[4] = { 0x88, 0x02, 0x00, 0x00 };
    
    unsigned short *code_be = (unsigned short *) &close_frame[2];
    
    if ((state->flags & STATE_FAILING_CONNECTION) != 0) {
        return;
    }
    *code_be = lws_htobe16(close_code);
    

    
    evbuffer_add(output, close_frame, 4);
    state->flags |= STATE_SHOULD_CLOSE | STATE_SENT_CLOSE_FRAME
    | STATE_FAILING_CONNECTION;
    
    libwebsock_client_close(bev, BEV_EVENT_ERROR | BEV_EVENT_EOF, state);
}

void libwebsock_free_all_frames(libwebsock_client_state *state) {
    libwebsock_frame *current, *next;
//    pthread_mutex_lock(&state->frame_lock);
    if (state != NULL) {
        current = state->current_frame;
        if (current) {
            for (; current->prev_frame != NULL; current = current->prev_frame);
            while (current != NULL) {
                next = current->next_frame;
                if (current->rawdata) {
#ifdef LIBWEBSOCK_DEBUG
                    fprintf(stderr, "[%s]: freeing current->rawdata at address: %p\n", __func__, current->rawdata);
#endif
                    lws_free(current->rawdata);
                }
#ifdef LIBWEBSOCK_DEBUG
                fprintf(stderr, "[%s]: freeing current at address: %p\n", __func__, current);
#endif
                lws_free(current);
                current = next;
            }
        }
    }
//    pthread_mutex_unlock(&state->frame_lock);
}

void lws_parse_headers(void) {
    
}