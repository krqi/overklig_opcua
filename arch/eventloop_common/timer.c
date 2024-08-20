
#include "timer.h"

static enum ZIP_CMP
cmpDateTime(const UA_DateTime *a, const UA_DateTime *b) {
    if(*a == *b)
        return ZIP_CMP_EQ;
    return (*a < *b) ? ZIP_CMP_LESS : ZIP_CMP_MORE;
}

static enum ZIP_CMP
cmpId(const UA_UInt64 *a, const UA_UInt64 *b) {
    if(*a == *b)
        return ZIP_CMP_EQ;
    return (*a < *b) ? ZIP_CMP_LESS : ZIP_CMP_MORE;
}

ZIP_FUNCTIONS(UA_TimerTree, UA_TimerEntry, treeEntry, UA_DateTime, nextTime, cmpDateTime)
ZIP_FUNCTIONS(UA_TimerIdTree, UA_TimerEntry, idTreeEntry, UA_UInt64, id, cmpId)

static UA_DateTime
calculateNextTime(UA_DateTime currentTime, UA_DateTime baseTime,
                  UA_DateTime interval) {
    
    UA_DateTime diffCurrentTimeBaseTime = currentTime - baseTime;

    UA_DateTime cycleDelay = diffCurrentTimeBaseTime % interval;

    
    if(UA_UNLIKELY(cycleDelay < 0))
        cycleDelay += interval;

    return currentTime + interval - cycleDelay;
}

void
UA_Timer_init(UA_Timer *t) {
    memset(t, 0, sizeof(UA_Timer));
    UA_LOCK_INIT(&t->timerMutex);
}

static UA_StatusCode
addCallback(UA_Timer *t, UA_ApplicationCallback callback, void *application,
            void *data, UA_DateTime nextTime, UA_UInt64 interval,
            UA_TimerPolicy timerPolicy, UA_UInt64 *callbackId) {
    
    if(!callback)
        return UA_STATUSCODE_BADINTERNALERROR;

    
    UA_TimerEntry *te = (UA_TimerEntry*)UA_malloc(sizeof(UA_TimerEntry));
    if(!te)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    
    te->interval = (UA_UInt64)interval;
    te->id = ++t->idCounter;
    te->callback = callback;
    te->application = application;
    te->data = data;
    te->nextTime = nextTime;
    te->timerPolicy = timerPolicy;

    
    if(callbackId)
        *callbackId = te->id;

    ZIP_INSERT(UA_TimerTree, &t->tree, te);
    ZIP_INSERT(UA_TimerIdTree, &t->idTree, te);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Timer_addTimedCallback(UA_Timer *t, UA_ApplicationCallback callback,
                          void *application, void *data, UA_DateTime date,
                          UA_UInt64 *callbackId) {
    UA_LOCK(&t->timerMutex);
    UA_StatusCode res = addCallback(t, callback, application, data, date,
                                    0, UA_TIMER_HANDLE_CYCLEMISS_WITH_CURRENTTIME,
                                    callbackId);
    UA_UNLOCK(&t->timerMutex);
    return res;
}

UA_StatusCode
UA_Timer_addRepeatedCallback(UA_Timer *t, UA_ApplicationCallback callback,
                             void *application, void *data, UA_Double interval_ms,
                             UA_DateTime now, UA_DateTime *baseTime,
                             UA_TimerPolicy timerPolicy, UA_UInt64 *callbackId) {
    
    if(interval_ms <= 0.0)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_UInt64 interval = (UA_UInt64)(interval_ms * UA_DATETIME_MSEC);
    if(interval == 0)
        return UA_STATUSCODE_BADINTERNALERROR;

    
    UA_DateTime nextTime;
    if(baseTime == NULL) {
        nextTime = now + (UA_DateTime)interval;
    } else {
        nextTime = calculateNextTime(now, *baseTime, (UA_DateTime)interval);
    }

    UA_LOCK(&t->timerMutex);
    UA_StatusCode res = addCallback(t, callback, application, data, nextTime,
                                    interval, timerPolicy, callbackId);
    UA_UNLOCK(&t->timerMutex);
    return res;
}

UA_StatusCode
UA_Timer_changeRepeatedCallback(UA_Timer *t, UA_UInt64 callbackId,
                                UA_Double interval_ms, UA_DateTime now,
                                UA_DateTime *baseTime, UA_TimerPolicy timerPolicy) {
    
    if(interval_ms <= 0.0)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_UInt64 interval = (UA_UInt64)(interval_ms * UA_DATETIME_MSEC);
    if(interval == 0)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_LOCK(&t->timerMutex);

    
    UA_TimerEntry *te = ZIP_FIND(UA_TimerIdTree, &t->idTree, &callbackId);
    if(!te) {
        UA_UNLOCK(&t->timerMutex);
        return UA_STATUSCODE_BADNOTFOUND;
    }

    UA_Boolean normalTree = (ZIP_REMOVE(UA_TimerTree, &t->tree, te) != NULL);

    if(baseTime == NULL) {
        te->nextTime = now + (UA_DateTime)interval;
    } else {
        te->nextTime = calculateNextTime(now, *baseTime, (UA_DateTime)interval);
    }

    
    te->interval = interval;
    te->timerPolicy = timerPolicy;

    if(normalTree)
        ZIP_INSERT(UA_TimerTree, &t->tree, te);

    UA_UNLOCK(&t->timerMutex);
    return UA_STATUSCODE_GOOD;
}

void
UA_Timer_removeCallback(UA_Timer *t, UA_UInt64 callbackId) {
    UA_LOCK(&t->timerMutex);
    UA_TimerEntry *te = ZIP_FIND(UA_TimerIdTree, &t->idTree, &callbackId);
    if(UA_LIKELY(te != NULL)) {
        if(t->processTree.root == NULL) {
            
            ZIP_REMOVE(UA_TimerTree, &t->tree, te);
            ZIP_REMOVE(UA_TimerIdTree, &t->idTree, te);
            UA_free(te);
        } else {
            te->callback = NULL;
        }
    }
    UA_UNLOCK(&t->timerMutex);
}

struct TimerProcessContext {
    UA_Timer *t;
    UA_DateTime now;
};

static void *
processEntryCallback(void *context, UA_TimerEntry *te) {
    struct TimerProcessContext *tpc = (struct TimerProcessContext*)context;
    UA_Timer *t = tpc->t;

    if(te->callback) {
        UA_UNLOCK(&t->timerMutex);
        te->callback(te->application, te->data);
        UA_LOCK(&t->timerMutex);
    }

    if(!te->callback || te->interval == 0) {
        ZIP_REMOVE(UA_TimerIdTree, &t->idTree, te);
        UA_free(te);
        return NULL;
    }

    
    te->nextTime += (UA_DateTime)te->interval;

    if(te->nextTime < tpc->now) {
        if(te->timerPolicy == UA_TIMER_HANDLE_CYCLEMISS_WITH_BASETIME)
            te->nextTime = calculateNextTime(tpc->now, te->nextTime,
                                              (UA_DateTime)te->interval);
        else
            te->nextTime = tpc->now + (UA_DateTime)te->interval;
    }

    
    ZIP_INSERT(UA_TimerTree, &t->tree, te);
    return NULL;
}

UA_DateTime
UA_Timer_process(UA_Timer *t, UA_DateTime now) {
    UA_LOCK(&t->timerMutex);

    
    if(!t->processTree.root) {
        
        ZIP_UNZIP(UA_TimerTree, &t->tree, &now, &t->processTree, &t->tree);

        
        UA_assert(!ZIP_MIN(UA_TimerTree, &t->tree) ||
                  ZIP_MIN(UA_TimerTree, &t->tree)->nextTime > now);
        
        struct TimerProcessContext ctx;
        ctx.t = t;
        ctx.now = now;
        ZIP_ITER(UA_TimerTree, &t->processTree, processEntryCallback, &ctx);
        
        
        t->processTree.root = NULL;
    }

    
    UA_TimerEntry *first = ZIP_MIN(UA_TimerTree, &t->tree);
    UA_DateTime next = (first) ? first->nextTime : UA_INT64_MAX;
    UA_UNLOCK(&t->timerMutex);
    return next;
}

UA_DateTime
UA_Timer_nextRepeatedTime(UA_Timer *t) {
    UA_LOCK(&t->timerMutex);
    UA_TimerEntry *first = ZIP_MIN(UA_TimerTree, &t->tree);
    UA_DateTime next = (first) ? first->nextTime : UA_INT64_MAX;
    UA_UNLOCK(&t->timerMutex);
    return next;
}

static void *
freeEntryCallback(void *context, UA_TimerEntry *entry) {
    UA_free(entry);
    return NULL;
}

void
UA_Timer_clear(UA_Timer *t) {
    UA_LOCK(&t->timerMutex);

    ZIP_ITER(UA_TimerIdTree, &t->idTree, freeEntryCallback, NULL);
    t->tree.root = NULL;
    t->idTree.root = NULL;
    t->idCounter = 0;

    UA_UNLOCK(&t->timerMutex);

#if UA_MULTITHREADING >= 100
    UA_LOCK_DESTROY(&t->timerMutex);
#endif
}
