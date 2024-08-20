
#ifndef UA_TIMER_H_
#define UA_TIMER_H_

#include <opcua/types.h>
#include <opcua/plugin/eventloop.h>
#include "ziptree.h"

_UA_BEGIN_DECLS



typedef void (*UA_ApplicationCallback)(void *application, void *data);

typedef struct UA_TimerEntry {
    ZIP_ENTRY(UA_TimerEntry) treeEntry;
    UA_TimerPolicy timerPolicy;      
    void *application;
    void *data;

    ZIP_ENTRY(UA_TimerEntry) idTreeEntry;
    UA_UInt64 id;                            
} UA_TimerEntry;

typedef ZIP_HEAD(UA_TimerTree, UA_TimerEntry) UA_TimerTree;
typedef ZIP_HEAD(UA_TimerIdTree, UA_TimerEntry) UA_TimerIdTree;

typedef struct {
    UA_TimerTree tree;     
    UA_TimerIdTree idTree; 
#if UA_MULTITHREADING >= 100
    UA_Lock timerMutex;
#endif

} UA_Timer;

void
UA_Timer_init(UA_Timer *t);

UA_DateTime
UA_Timer_nextRepeatedTime(UA_Timer *t);

UA_StatusCode
UA_Timer_addTimedCallback(UA_Timer *t, UA_ApplicationCallback callback,
                          void *application, void *data, UA_DateTime date,
                          UA_UInt64 *callbackId);

UA_StatusCode
UA_Timer_addRepeatedCallback(UA_Timer *t, UA_ApplicationCallback callback,
                             void *application, void *data, UA_Double interval_ms,
                             UA_DateTime now, UA_DateTime *baseTime,
                             UA_TimerPolicy timerPolicy, UA_UInt64 *callbackId);

UA_StatusCode
UA_Timer_changeRepeatedCallback(UA_Timer *t, UA_UInt64 callbackId,
                                UA_Double interval_ms, UA_DateTime now,
                                UA_DateTime *baseTime, UA_TimerPolicy timerPolicy);

void
UA_Timer_removeCallback(UA_Timer *t, UA_UInt64 callbackId);

UA_DateTime
UA_Timer_process(UA_Timer *t, UA_DateTime now);

void
UA_Timer_clear(UA_Timer *t);

_UA_END_DECLS

#endif 
