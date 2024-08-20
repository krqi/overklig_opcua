
#include "eventloop_posix.h"
#include <signal.h>


typedef struct UA_RegisteredSignal {
#ifdef UA_HAVE_EPOLL
    UA_RegisteredFD rfd;
#endif

    LIST_ENTRY(UA_RegisteredSignal) listPointers;

    UA_InterruptCallback signalCallback;
    void *context;
    int signal; 

    UA_Boolean active; 
    UA_Boolean triggered;
} UA_RegisteredSignal;

typedef struct {
    UA_InterruptManager im;

    LIST_HEAD(, UA_RegisteredSignal) signals; 

#ifndef UA_HAVE_EPOLL
    UA_DelayedCallback dc; 
#endif
} UA_POSIXInterruptManager;


static void activateSignal(UA_RegisteredSignal *rs);
static void deactivateSignal(UA_RegisteredSignal *rs);

#ifdef UA_HAVE_EPOLL
#include <sys/signalfd.h>

static void
handlePOSIXInterruptEvent(UA_EventSource *es, UA_RegisteredFD *rfd, short event) {
    UA_EventLoopPOSIX *el = (UA_EventLoopPOSIX *)es->eventLoop;
    (void)el;
    UA_LOCK_ASSERT(&el->elMutex, 1);

    UA_RegisteredSignal *rs = (UA_RegisteredSignal*)rfd;
    struct signalfd_siginfo fdsi;
    ssize_t s = read(rfd->fd, &fdsi, sizeof(fdsi));
    if(s < (ssize_t)sizeof(fdsi)) {
        
        deactivateSignal(rs);
        return;
    }

    
    UA_LOG_DEBUG(es->eventLoop->logger, UA_LOGCATEGORY_EVENTLOOP,
                 "Interrupt %u\t| Received a signal %u",
                 (unsigned)rfd->fd, fdsi.ssi_signo);

    UA_UNLOCK(&el->elMutex);
    rs->signalCallback((UA_InterruptManager *)es, (uintptr_t)rfd->fd,
                       rs->context, &UA_KEYVALUEMAP_NULL);
    UA_LOCK(&el->elMutex);
}

static void
activateSignal(UA_RegisteredSignal *rs) {
    UA_EventLoopPOSIX *el = (UA_EventLoopPOSIX *)rs->rfd.es->eventLoop;
    UA_LOCK_ASSERT(&el->elMutex, 1);

    if(rs->active)
        return;

    
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, rs->signal);
    int res2 = sigprocmask(SIG_BLOCK, &mask, NULL);
    if(res2 == -1) {
        UA_LOG_SOCKET_ERRNO_WRAP(
            UA_LOG_WARNING(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                           "Interrupt\t| Could not block the default "
                           "signal handling with an error: %s",
                           errno_str));
        return;
    }

    
    UA_FD newfd = signalfd(-1, &mask, 0);
    if(newfd < 0) {
        UA_LOG_SOCKET_ERRNO_WRAP(
            UA_LOG_WARNING(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                           "Interrupt\t| Could not create a signal file "
                           "description with error: %s",
                           errno_str));
        sigprocmask(SIG_UNBLOCK, &mask, NULL); 
        return;
    }

    rs->rfd.fd = newfd;
    rs->rfd.eventSourceCB = handlePOSIXInterruptEvent;
    rs->rfd.listenEvents = UA_FDEVENT_IN;

    
    UA_StatusCode res = UA_EventLoopPOSIX_registerFD(el, &rs->rfd);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                       "Interrupt\t| Could not register the a signal file "
                       "description in the EventLoop");
        UA_close(newfd);
        sigprocmask(SIG_UNBLOCK, &mask, NULL); 
        return;
    }

    rs->active = true;
}

static void
deactivateSignal(UA_RegisteredSignal *rs) {
    UA_EventLoopPOSIX *el = (UA_EventLoopPOSIX *)rs->rfd.es->eventLoop;
    UA_LOCK_ASSERT(&el->elMutex, 1);

    
    if(!rs->active)
        return;
    rs->active = false;

    
    UA_EventLoopPOSIX_deregisterFD(el, &rs->rfd);

    
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, (int)rs->signal);
    sigprocmask(SIG_UNBLOCK, &mask, NULL);

    
    UA_close(rs->rfd.fd);
}

#else 

static UA_POSIXInterruptManager *singletonIM = NULL;


static void
executeTriggeredPOSIXInterrupts(UA_POSIXInterruptManager *im, void *_) {
    im->dc.callback = NULL; 

    UA_RegisteredSignal *rs, *rs_tmp;
    LIST_FOREACH_SAFE(rs, &im->signals, listPointers, rs_tmp) {
        rs->triggered = false;
        rs->signalCallback(&im->im, (uintptr_t)rs->signal,
                           rs->context, &UA_KEYVALUEMAP_NULL);
    }
}

static void
triggerPOSIXInterruptEvent(int sig) {
    UA_assert(singletonIM != NULL);

    
    UA_RegisteredSignal *rs;
    LIST_FOREACH(rs, &singletonIM->signals, listPointers) {
        if(rs->signal == sig)
            break;
    }
    if(!rs || rs->triggered || !rs->active)
        return;

    
    rs->triggered = true;

#ifdef _WIN32
    
    signal(sig, triggerPOSIXInterruptEvent);
#endif

    UA_EventLoopPOSIX *el = (UA_EventLoopPOSIX*)singletonIM->im.eventSource.eventLoop;

    
    if(!singletonIM->dc.callback) {
        singletonIM->dc.callback = (UA_Callback)executeTriggeredPOSIXInterrupts;
        singletonIM->dc.application = singletonIM;
        singletonIM->dc.context = NULL;
        UA_EventLoopPOSIX_addDelayedCallback(&el->eventLoop, &singletonIM->dc);
    }

    
    UA_EventLoopPOSIX_cancel(el);
}

static void
activateSignal(UA_RegisteredSignal *rs) {
    UA_assert(singletonIM != NULL);
    UA_EventLoopPOSIX *el = (UA_EventLoopPOSIX*)singletonIM->im.eventSource.eventLoop;
    UA_LOCK_ASSERT(&el->elMutex, 1);

    
    if(rs->active)
        return;

    void (*prev)(int);
    prev = signal(rs->signal, triggerPOSIXInterruptEvent);
    if(prev == SIG_ERR) {
        UA_LOG_SOCKET_ERRNO_WRAP(
           UA_LOG_WARNING(singletonIM->im.eventSource.eventLoop->logger,
                          UA_LOGCATEGORY_EVENTLOOP,
                          "Error registering the signal: %s", errno_str));
        return;
    }

    rs->active = true;
}

static void
deactivateSignal(UA_RegisteredSignal *rs) {
    UA_assert(singletonIM != NULL);
    UA_EventLoopPOSIX *el = (UA_EventLoopPOSIX*)singletonIM->im.eventSource.eventLoop;
    UA_LOCK_ASSERT(&el->elMutex, 1);

    
    if(!rs->active)
        return;

    
    signal(rs->signal, SIG_DFL);

    rs->triggered = false;
    rs->active = false;
}

#endif 

static UA_StatusCode
registerPOSIXInterrupt(UA_InterruptManager *im, uintptr_t interruptHandle,
                       const UA_KeyValueMap *params,
                       UA_InterruptCallback callback, void *interruptContext) {
    UA_EventLoopPOSIX *el = (UA_EventLoopPOSIX *)im->eventSource.eventLoop;
    if(!UA_KeyValueMap_isEmpty(params)) {
        UA_LOG_ERROR(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                     "Interrupt\t| Supplied parameters invalid for the "
                     "POSIX InterruptManager");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_LOCK(&el->elMutex);

    
    int signal = (int)interruptHandle;
    UA_POSIXInterruptManager *pim = (UA_POSIXInterruptManager *)im;
    UA_RegisteredSignal *rs;
    LIST_FOREACH(rs, &pim->signals, listPointers) {
        if(rs->signal == signal)
            break;
    }
    if(rs) {
        UA_LOG_WARNING(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                       "Interrupt\t| Signal %u already registered",
                       (unsigned)interruptHandle);
        UA_UNLOCK(&el->elMutex);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    
    rs = (UA_RegisteredSignal *)UA_calloc(1, sizeof(UA_RegisteredSignal));
    if(!rs) {
        UA_UNLOCK(&el->elMutex);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

#ifdef UA_HAVE_EPOLL
    rs->rfd.es = &im->eventSource;
#endif
    rs->signal = (int)interruptHandle;
    rs->signalCallback = callback;
    rs->context = interruptContext;

    
    LIST_INSERT_HEAD(&pim->signals, rs, listPointers);

    
    if(pim->im.eventSource.state == UA_EVENTSOURCESTATE_STARTED)
        activateSignal(rs);

    UA_UNLOCK(&el->elMutex);
    return UA_STATUSCODE_GOOD;
}

static void
deregisterPOSIXInterrupt(UA_InterruptManager *im, uintptr_t interruptHandle) {
    UA_EventLoopPOSIX *el = (UA_EventLoopPOSIX *)im->eventSource.eventLoop;
    (void)el;
    UA_POSIXInterruptManager *pim = (UA_POSIXInterruptManager *)im;
    UA_LOCK(&el->elMutex);

    int signal = (int)interruptHandle;
    UA_RegisteredSignal *rs;
    LIST_FOREACH(rs, &pim->signals, listPointers) {
        if(rs->signal == signal)
            break;
    }
    if(rs) {
        deactivateSignal(rs);
        LIST_REMOVE(rs, listPointers);
        UA_free(rs);
    }

    UA_UNLOCK(&el->elMutex);
}

static UA_StatusCode
startPOSIXInterruptManager(UA_EventSource *es) {
    UA_EventLoopPOSIX *el = (UA_EventLoopPOSIX *)es->eventLoop;
    (void)el;
    UA_LOCK(&el->elMutex);

    
    if(es->state != UA_EVENTSOURCESTATE_STOPPED) {
        UA_LOG_ERROR(es->eventLoop->logger, UA_LOGCATEGORY_EVENTLOOP,
                     "Interrupt\t| To start the InterruptManager, "
                     "it has to be registered in an EventLoop and not started");
        UA_UNLOCK(&el->elMutex);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_POSIXInterruptManager *pim = (UA_POSIXInterruptManager *)es;
    UA_LOG_DEBUG(es->eventLoop->logger, UA_LOGCATEGORY_EVENTLOOP,
                 "Interrupt\t| Starting the InterruptManager");

    
    UA_RegisteredSignal*rs;
    LIST_FOREACH(rs, &pim->signals, listPointers) {
        activateSignal(rs);
    }

    
    es->state = UA_EVENTSOURCESTATE_STARTED;

    UA_UNLOCK(&el->elMutex);
    return UA_STATUSCODE_GOOD;
}

static void
stopPOSIXInterruptManager(UA_EventSource *es) {
    UA_EventLoopPOSIX *el = (UA_EventLoopPOSIX *)es->eventLoop;
    (void)el;
    UA_LOCK(&el->elMutex);

    if(es->state != UA_EVENTSOURCESTATE_STARTED) {
        UA_UNLOCK(&el->elMutex);
        return;
    }

    UA_LOG_DEBUG(es->eventLoop->logger, UA_LOGCATEGORY_EVENTLOOP,
                 "Interrupt\t| Stopping the InterruptManager");

    
    UA_POSIXInterruptManager *pim = (UA_POSIXInterruptManager *)es;
    UA_RegisteredSignal*rs;
    LIST_FOREACH(rs, &pim->signals, listPointers) {
        deactivateSignal(rs);
    }

    
    es->state = UA_EVENTSOURCESTATE_STOPPED;

    UA_UNLOCK(&el->elMutex);
}

static UA_StatusCode
freePOSIXInterruptmanager(UA_EventSource *es) {
    UA_EventLoopPOSIX *el = (UA_EventLoopPOSIX *)es->eventLoop;
    (void)el;
    UA_LOCK_ASSERT(&el->elMutex, 1);

    if(es->state >= UA_EVENTSOURCESTATE_STARTING) {
        UA_LOG_ERROR(es->eventLoop->logger, UA_LOGCATEGORY_EVENTLOOP,
                     "Interrupt\t| The EventSource must be stopped "
                     "before it can be deleted");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    
    UA_POSIXInterruptManager *pim = (UA_POSIXInterruptManager *)es;
    UA_RegisteredSignal *rs, *rs_tmp;
    LIST_FOREACH_SAFE(rs, &pim->signals, listPointers, rs_tmp) {
        deactivateSignal(rs);
        LIST_REMOVE(rs, listPointers);
        UA_free(rs);
    }

    UA_String_clear(&es->name);
    UA_free(es);

#ifndef UA_HAVE_EPOLL
    singletonIM = NULL; 
#endif

    return UA_STATUSCODE_GOOD;
}

UA_InterruptManager *
UA_InterruptManager_new_POSIX(const UA_String eventSourceName) {
#ifndef UA_HAVE_EPOLL
    
    if(singletonIM)
        return NULL;
#endif

    UA_POSIXInterruptManager *pim = (UA_POSIXInterruptManager *)
        UA_calloc(1, sizeof(UA_POSIXInterruptManager));
    if(!pim)
        return NULL;

#ifndef UA_HAVE_EPOLL
    singletonIM = pim; 
#endif

    UA_InterruptManager *im = &pim->im;
    im->eventSource.eventSourceType = UA_EVENTSOURCETYPE_INTERRUPTMANAGER;
    UA_String_copy(&eventSourceName, &im->eventSource.name);
    im->eventSource.start = startPOSIXInterruptManager;
    im->eventSource.stop = stopPOSIXInterruptManager;
    im->eventSource.free = freePOSIXInterruptmanager;
    im->registerInterrupt = registerPOSIXInterrupt;
    im->deregisterInterrupt = deregisterPOSIXInterrupt;
    return im;
}
