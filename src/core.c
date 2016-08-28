/*
  core.c

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

pthread_mutex_t global_alloc_free_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t gc_lock = PTHREAD_MUTEX_INITIALIZER;

/* Using MACRO calls for the LL functions
   is faster than calling functions
                                         */

#define LL_ADD(item, list) { \
item->prev = NULL; \
item->next = list; \
list = item; \
}

#define LL_REMOVE(item, list) { \
if (item->prev != NULL) item->prev->next = item->next; \
if (item->next != NULL) item->next->prev = item->prev; \
if (list == item) list = item->next; \
item->prev = item->next = NULL; \
}

/* Memory Functions Begin
 * The goal here is to eventually
 * create a GC scheme using these
 * functions.
 */

void *
lws_calloc(size_t size)
{
    pthread_mutex_lock(&global_alloc_free_lock);
#ifdef LIBWEBSOCK_DEBUG
    //fprintf(stderr, "Lock aquired for calloc of size: %zd\n", size);
#endif
    void *alloc = calloc(1, size);
    if (!alloc) {
        fprintf(stderr, "Failed calloc!  Exiting.\n");
        exit(-1);
    }
    pthread_mutex_unlock(&global_alloc_free_lock);
#ifdef LIBWEBSOCK_DEBUG
    //fprintf(stderr, "Lock released for calloc, address returned: %p.\n", alloc);
#endif
    return alloc;
}

void *
lws_malloc(size_t size)
{
    pthread_mutex_lock(&global_alloc_free_lock);
#ifdef LIBWEBSOCK_DEBUG
    //fprintf(stderr, "Lock aquired for malloc of size: %zd\n", size);
#endif
    void *alloc = malloc(size);
    if (!alloc) {
        fprintf(stderr, "Failed malloc!  Exiting.\n");
        exit(-1);
    }
    pthread_mutex_unlock(&global_alloc_free_lock);
#ifdef LIBWEBSOCK_DEBUG
    //fprintf(stderr, "Lock released for malloc, address returned: %p.\n", alloc);
#endif
    return alloc;
}

void
lws_free(void *ptr)
{
    pthread_mutex_lock(&global_alloc_free_lock);
#ifdef LIBWEBSOCK_DEBUG
    //fprintf(stderr, "Lock aquired for free of: %p\n", ptr);
#endif
    free(ptr);
    pthread_mutex_unlock(&global_alloc_free_lock);
#ifdef LIBWEBSOCK_DEBUG
    //fprintf(stderr, "Lock released for free of: %p\n", ptr);
#endif
}

void *
lws_realloc(void *ptr, size_t size)
{
    pthread_mutex_lock(&global_alloc_free_lock);
#ifdef LIBWEBSOCK_DEBUG
    //fprintf(stderr, "Lock aquired for realloc of addr: %p to size: %zd\n", ptr, size);
#endif
    void *new = realloc(ptr, size);
    if (!new) {
        fprintf(stderr, "Failed realloc!  Exiting.\n");
        exit(-1);
    }
    pthread_mutex_unlock(&global_alloc_free_lock);
#ifdef LIBWEBSOCK_DEBUG
    //fprintf(stderr, "Lock released for realloc of addr: %p to size: %zd and new addr: %p\n", ptr, size, new);
#endif
    return new;
}

/* Memory Functions End */

/* Scheduler Worker Functions Begin
 *
 * All agents use the same function.
 * The worker type is determined by
 * lws_worker_type enum.
 *
 */

void *lws_evbase_thread_loop_function(void *ptr) {
    
    lws_evbase_loop_thread *thread = (lws_evbase_loop_thread *)ptr;
#ifdef LIBWEBSOCK_DEBUG
    printf("[%s]: Loop event base agent thread [%d] starting event loop!\n", __func__, thread->worker_number);
#endif
    event_base_loop(thread->base, 0);
#ifdef LIBWEBSOCK_DEBUG
    printf("[%s]: Killing client event base loop thread [%d]...\n", __func__, thread->worker_number);
#endif
    free(thread);
    pthread_exit(NULL);
}

void *lws_worker_agent_function(void *ptr) {
    lws_worker *worker = (lws_worker *)ptr;
    lws_job *job;
    
//#ifdef LIBWEBSOCK_DEBUG
    switch(worker->worker_type) {
        case LWS_DISPATCH_WORKER :
            printf("[%s]: Dispatch worker [%d] started...\n", __func__, worker->worker_number);
            break;
        case LWS_CONTROLFRAME_WORKER :
            printf("[%s]: Control frame worker [%d] started...\n", __func__, worker->worker_number);
            break;
        case LWS_CONNECTION_WORKER :
            printf("[%s]: Connection worker [%d] started...\n", __func__, worker->worker_number);
            break;
        case LWS_EVBASE_WORKER :
            //worker->base = event_base_new();
            printf("[%s]: Event base worker [%d] started...\n", __func__, worker->worker_number);
            while (1) {
                event_base_dispatch(worker->base);
            }
        default : // Debugging / Just in case
            printf("[WARNING] : An unknown worker type has been started...\n");
            break;
    }
//#endif
    
    while (1) {
        pthread_mutex_lock(&worker->scheduler->lws_jobs_mutex);
        
        while(worker->scheduler->pending_jobs == NULL) {
            if (worker->terminate) break;
            pthread_cond_wait(&worker->scheduler->lws_jobs_cond, &worker->scheduler->lws_jobs_mutex);
        }
        
        if (worker->terminate) {
            pthread_mutex_unlock(&worker->scheduler->lws_jobs_mutex);
            break;
        }
        
        job = worker->scheduler->pending_jobs;
        if (job != NULL) {
            LL_REMOVE(job, worker->scheduler->pending_jobs);
        }
        pthread_mutex_unlock(&worker->scheduler->lws_jobs_mutex);
        
        if (job == NULL) continue;
        
        // Check the worker type and perform based on that.
        // In the event of being an EVBASE worker, it needs
        // to assign the event base to the wrapper for processing
        
        job->worker_number = worker->worker_number;
#ifdef LIBWEBSOCK_DEBUG
        printf("[%s]: Worker type [%d] number [%d] is executing job...\n", __func__, worker->worker_type, worker->worker_number);
#endif

        //if (job->type == LWS_EVBASE)
        job->base = worker->base;
        job->job_func(job);
        if (job->status == finished) {
            lws_free(job);
#ifdef LIBWEBSOCK_DEBUG
            printf("[%s]: Worker type [%d] number [%d] has freed job wrapper...\n", __func__, worker->worker_type, worker->worker_number);
#endif
        }
        
    }
    lws_worker_cleanup(worker); // Check worker type and cleanup accordingly
    pthread_exit(NULL);

}

/* Scheduler Worker Functions End */

int lws_scheduler_init(libwebsock_context *ctx) {
    int i, dispatch_workers, connection_workers, controlframe_workers, client_event_bases;
    lws_worker_type workertype;
    struct event *sig_event;
    
    lws_evbase_loop_thread *evbase_loop_thread;
    lws_worker *evbase_thread, *connection_worker, *dispatch_worker, *controlframe_worker;
    
    lws_scheduler_context *scheduler;
    
    connection_workers = ctx->connection_workers;
    dispatch_workers = ctx->dispatch_workers;
    controlframe_workers = ctx->controlframe_workers;
    client_event_bases = ctx->evbase_count;
    
    if (connection_workers < 1) connection_workers = 1;
    if (dispatch_workers < 1) dispatch_workers = 1;
    if (controlframe_workers < 1) controlframe_workers = 1;

#ifdef LIBWEBSOCK_DEBUG
    printf("[%s]: Allocating schedulers and scheduler context...\n", __func__);
#endif
    
    // Can certainly do the lws_scheduler bits in one malloc...
    // lws_evbase_thread_scheduler has different members,
    // so it's a few bytes bigger.
    lws_scheduler *connection_scheduler = (lws_scheduler *)lws_calloc(sizeof(lws_scheduler));
    lws_scheduler *dispatch_scheduler = (lws_scheduler *)lws_calloc(sizeof(lws_scheduler));
    lws_scheduler *controlframe_scheduler = (lws_scheduler *)lws_calloc(sizeof(lws_scheduler));
    lws_scheduler *evbase_scheduler = (lws_scheduler *)lws_calloc(sizeof(lws_scheduler));
    scheduler = (lws_scheduler_context *)lws_calloc(sizeof(lws_scheduler_context));
    
    scheduler->connects = connection_scheduler;
    scheduler->dispatcher = dispatch_scheduler;
    scheduler->controlframes = controlframe_scheduler;
    scheduler->evbase_scheduler = evbase_scheduler;
    
    pthread_mutex_t lws_connects_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t lws_connects_cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t lws_dispatch_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t lws_dispatch_cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t lws_controlframe_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t lws_controlframe_cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t lws_evbase_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t lws_evbase_cond = PTHREAD_COND_INITIALIZER;
    memcpy(&scheduler->connects->lws_jobs_mutex, &lws_connects_mutex, sizeof(scheduler->connects->lws_jobs_mutex));
    memcpy(&scheduler->connects->lws_jobs_cond, &lws_connects_cond, sizeof(scheduler->connects->lws_jobs_cond));
    memcpy(&scheduler->dispatcher->lws_jobs_mutex, &lws_dispatch_mutex, sizeof(scheduler->dispatcher->lws_jobs_mutex));
    memcpy(&scheduler->dispatcher->lws_jobs_cond, &lws_dispatch_cond, sizeof(scheduler->dispatcher->lws_jobs_cond));
    memcpy(&scheduler->controlframes->lws_jobs_mutex, &lws_controlframe_mutex, sizeof(scheduler->controlframes->lws_jobs_mutex));
    memcpy(&scheduler->controlframes->lws_jobs_cond, &lws_controlframe_cond, sizeof(scheduler->controlframes->lws_jobs_cond));
    memcpy(&scheduler->evbase_scheduler->lws_jobs_mutex, &lws_evbase_mutex, sizeof(scheduler->evbase_scheduler->lws_jobs_mutex));
    memcpy(&scheduler->evbase_scheduler->lws_jobs_cond, &lws_evbase_cond, sizeof(scheduler->evbase_scheduler->lws_jobs_cond));
    
    // connection scheduler
    for (i = 0; i < connection_workers; i++) {
        if ((connection_worker = lws_calloc(sizeof(lws_worker))) == NULL) {
            perror("Failed to allocate connection worker threads.");
            return 1;
        }
        connection_worker->scheduler = scheduler->connects;
        connection_worker->scheduler->ctx = scheduler;
        connection_worker->worker_number = i;
        workertype = LWS_CONNECTION_WORKER;
        connection_worker->worker_type = workertype;
        if (pthread_create(&connection_worker->thread, NULL, lws_worker_agent_function, (void *)connection_worker)) {
            perror("Failed to start all connection worker threads.");
            lws_free(connection_worker);
            return 1;
        }
        LL_ADD(connection_worker, connection_worker->scheduler->workers);
    //}
    // dispatch scheduler
    //for (i = 0; i < dispatch_workers; i++) {
        if ((dispatch_worker = lws_calloc(sizeof(lws_worker))) == NULL) {
            perror("Failed to allocate dispatch worker threads.");
            return 1;
        }
        dispatch_worker->scheduler = scheduler->dispatcher;
        dispatch_worker->scheduler->ctx = scheduler;
        dispatch_worker->worker_number = i;
        workertype = LWS_DISPATCH_WORKER;
        dispatch_worker->worker_type = workertype;
        if (pthread_create(&dispatch_worker->thread, NULL, lws_worker_agent_function, (void *)dispatch_worker)) {
            perror("Failed to start all dispatch worker threads.");
            lws_free(dispatch_worker);
            return 1;
        }
        LL_ADD(dispatch_worker, dispatch_worker->scheduler->workers);
    //}
    // control frame scheduler
    //for (i = 0; i < controlframe_workers; i++) {
        if ((controlframe_worker = lws_calloc(sizeof(lws_worker))) == NULL) {
            perror("Failed to allocate control frame worker threads.");
            return 1;
        }
        controlframe_worker->scheduler = scheduler->controlframes;
        controlframe_worker->scheduler->ctx = scheduler;
        controlframe_worker->worker_number = i;
        workertype = LWS_CONTROLFRAME_WORKER;
        controlframe_worker->worker_type = workertype;
        if (pthread_create(&controlframe_worker->thread, NULL, lws_worker_agent_function, (void *)controlframe_worker)) {
            perror("Failed to start all control frame worker threads.");
            lws_free(controlframe_worker);
            return 1;
        }
        LL_ADD(controlframe_worker, controlframe_worker->scheduler->workers);
    //}
    // event base threads
    //for (i = 0; i < client_event_bases; i++) {
        if ((evbase_thread = lws_calloc(sizeof(lws_worker))) == NULL) {
            perror("Failed to allocate event base threads.");
            return 1;
        }
        
        if((evbase_loop_thread = lws_calloc(sizeof(lws_evbase_loop_thread))) == NULL) {
            perror("Failed to allocate memory for event base loop thread...\n");
            return 1;
        }

        evbase_thread->scheduler = scheduler->evbase_scheduler;
        evbase_thread->worker_number = i;
        workertype = LWS_EVBASE_WORKER;
        evbase_thread->base = event_base_new();
        evbase_thread->worker_type = workertype;
        if (pthread_create(&evbase_thread->thread, NULL, lws_worker_agent_function, (void *)evbase_thread)) {
            perror("Failed to start all event base threads.");
            lws_free(evbase_thread);
            return 1;
        }
        
        
        connection_worker->base = evbase_thread->base;
        dispatch_worker->base = evbase_thread->base;
        controlframe_worker->base = evbase_thread->base;

        LL_ADD(evbase_thread, evbase_thread->scheduler->workers);
        
    }
    
    ctx->scheduler = scheduler;
    
    return 0;
}

void lws_scheduler_shutdown(libwebsock_context *ctx) {
    /* Loop through the workers and set the flag to
     * terminate them. Then trigger the condition to
     * make them kill themselves. They'll call the
     * lws_worker_cleanup function.
     */
    lws_scheduler_context *scheduler = ctx->scheduler;
    lws_worker *worker;
    lws_worker *evbase_agent;
    
    for (worker = scheduler->connects->workers; worker != NULL; worker = worker->next) {
        worker->terminate = 1;
        pthread_cond_signal(&scheduler->connects->lws_jobs_cond);
    }
    
    for (worker = scheduler->dispatcher->workers; worker != NULL; worker = worker->next) {
        worker->terminate = 1;
        pthread_cond_signal(&scheduler->dispatcher->lws_jobs_cond);
    }
    
    
    for (worker = scheduler->controlframes->workers; worker != NULL; worker = worker->next) {
        worker->terminate = 1;
        pthread_cond_signal(&scheduler->controlframes->lws_jobs_cond);
    }
    
    
    for (evbase_agent = scheduler->evbase_scheduler->workers; evbase_agent != NULL; evbase_agent = evbase_agent->next) {
        evbase_agent->terminate = 1;
        pthread_cond_signal(&scheduler->evbase_scheduler->lws_jobs_cond);
    }
    
    lws_free(scheduler->connects);
    lws_free(scheduler->dispatcher);
    lws_free(scheduler->controlframes);
    lws_free(scheduler->evbase_scheduler);
    lws_free(scheduler);
}

void lws_worker_cleanup(lws_worker *worker) {
    switch(worker->worker_type) {
        case LWS_DISPATCH_WORKER :
#ifdef LIBWEBSOCK_DEBUG
            printf("[%s]: Dispatch worker [%d] being shut down...\n", __func__, worker->worker_number);
#endif
            break;
        case LWS_CONTROLFRAME_WORKER :
#ifdef LIBWEBSOCK_DEBUG
            printf("[%s]: Control frame worker [%d] being shut down...\n", __func__, worker->worker_number);
#endif
            break;
        case LWS_CONNECTION_WORKER :
#ifdef LIBWEBSOCK_DEBUG
            printf("[%s]: Connection worker [%d] being shut down...\n", __func__, worker->worker_number);
#endif
            break;
        case LWS_EVBASE_WORKER :
#ifdef LIBWEBSOCK_DEBUG
            printf("[%s]: Event base worker [%d] being shut down...\n", __func__, worker->worker_number);
#endif
            event_base_free(worker->base); // Free the event base on the worker
            break;
        default :
#ifdef LIBWEBSOCK_DEBUG
            printf("[WARNING] : An unknown worker type is being shut down...\n");
#endif
            break;
    }
    lws_free(worker); // Free the worker wrapper
}

void lws_scheduler_add_job(lws_job *item) {
    lws_scheduler_context *scheduler = item->ctx->scheduler;
    lws_scheduler *queue = scheduler->connects; // Default assignment to stop warnings at compile time
    lws_job_type type = item->type;
    switch(type) {
        case LWS_CONNECTION :
            queue = scheduler->connects;
            break;
            
        case LWS_CONNECTION_CLOSE :
            queue = scheduler->connects;
            break;
            
        case LWS_EVBASE :
            queue = scheduler->evbase_scheduler;
            break;
            
        case LWS_DISPATCH :
            queue = scheduler->dispatcher;
            break;
            
        case LWS_CONTROLFRAME :
            queue = scheduler->controlframes;
            break;
            
        case LWS_FRAME : // Standard dispatcher... ?
            queue = scheduler->dispatcher;
            break;
            
        default :
            // Something went wrong here...
#ifdef LIBWEBSOCK_DEBUG
            printf("[WARNING] : Tried to schedule a job type that doesn't exist...\n");
#endif
            break;
    }
    pthread_mutex_lock(&queue->lws_jobs_mutex);
    LL_ADD(item,queue->pending_jobs);
    pthread_cond_signal(&queue->lws_jobs_cond);
    pthread_mutex_unlock(&queue->lws_jobs_mutex);
}

void lws_handle_signal(evutil_socket_t sig, short event, void *ptr) {
#ifdef LIBWEBSOCK_DEBUG
    printf("[%s]: Break signal received... Killing main event loop...\n", __func__);
#endif
    libwebsock_context *ctx = ptr;
    switch (sig) {
        case SIGUSR2:
            break;
        case SIGINT:
        default:
            event_base_loopexit(ctx->base, NULL);
            // The event base is free'd at the end of libwebsock_shutdown()
            break;
    }
}

void lws_evthread_handle_signal(evutil_socket_t sig, short event, void *ptr) {
    lws_evbase_loop_thread *thread = ptr;
#ifdef LIBWEBSOCK_DEBUG
    printf("[%s]: Killing event base loop on thread [%d]\n", __func__, thread->worker_number);
#endif
    switch (sig) {
        case SIGUSR2:
            break;
        case SIGINT:
        default:
            event_base_loopexit(thread->base, NULL);
            // The event base free occurs in the worker cleanup
            break;
    }
}
