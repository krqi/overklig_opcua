
#include <opcua/plugin/log_stdout.h>
#include <opcua/types.h>

#include <stdio.h>

#include "mp_printf.h"


#ifdef UA_ARCHITECTURE_POSIX
# define ANSI_COLOR_RED     "\x1b[31m"
# define ANSI_COLOR_GREEN   "\x1b[32m"
# define ANSI_COLOR_YELLOW  "\x1b[33m"
# define ANSI_COLOR_BLUE    "\x1b[34m"
# define ANSI_COLOR_MAGENTA "\x1b[35m"
# define ANSI_COLOR_CYAN    "\x1b[36m"
# define ANSI_COLOR_RESET   "\x1b[0m"
#else
# define ANSI_COLOR_RED     ""
# define ANSI_COLOR_GREEN   ""
# define ANSI_COLOR_YELLOW  ""
# define ANSI_COLOR_BLUE    ""
# define ANSI_COLOR_MAGENTA ""
# define ANSI_COLOR_CYAN    ""
# define ANSI_COLOR_RESET   ""
#endif

static
const char *logLevelNames[6] = {"trace", "debug",
                                ANSI_COLOR_GREEN "info",
                                ANSI_COLOR_YELLOW "warn",
                                ANSI_COLOR_RED "error",
                                ANSI_COLOR_MAGENTA "fatal"};
static const char *
logCategoryNames[UA_LOGCATEGORIES] =
    {"network", "channel", "session", "server", "client",
     "userland", "securitypolicy", "eventloop", "pubsub", "discovery"};

#if UA_MULTITHREADING >= 100
# ifdef UA_ARCHITECTURE_POSIX
UA_Lock logLock = UA_LOCK_STATIC_INIT;
# else
void * volatile logSpinLock = NULL;
static UA_INLINE void spinLock(void) {
    while(UA_atomic_cmpxchg(&logSpinLock, NULL, (void*)0x1) != NULL) {}
}
static UA_INLINE void spinUnLock(void) {
    UA_atomic_xchg(&logSpinLock, NULL);
}
# endif
#endif

#ifdef __clang__
__attribute__((__format__(__printf__, 4 , 0)))
#endif
static void
UA_Log_Stdout_log(void *context, UA_LogLevel level, UA_LogCategory category,
                  const char *msg, va_list args) {
    
    UA_LogLevel minLevel = (UA_LogLevel)(uintptr_t)context;
    if(minLevel > level)
        return;

    UA_Int64 tOffset = UA_DateTime_localTimeUtcOffset();
    UA_DateTimeStruct dts = UA_DateTime_toStruct(UA_DateTime_now() + tOffset);

    int logLevelSlot = ((int)level / 100) - 1;
    if(logLevelSlot < 0 || logLevelSlot > 5)
        logLevelSlot = 5; 

    
#if UA_MULTITHREADING >= 100
# ifdef UA_ARCHITECTURE_POSIX
    UA_LOCK(&logLock);
# else
    spinLock();
# endif
#endif

#define STDOUT_LOGBUFSIZE 512
    char logbuf[STDOUT_LOGBUFSIZE];

    
    printf("[%04u-%02u-%02u %02u:%02u:%02u.%03u (UTC%+05d)] %s/%s" ANSI_COLOR_RESET "\t",
           dts.year, dts.month, dts.day, dts.hour, dts.min, dts.sec, dts.milliSec,
           (int)(tOffset / UA_DATETIME_SEC / 36), logLevelNames[logLevelSlot],
           logCategoryNames[category]);
    mp_vsnprintf(logbuf, STDOUT_LOGBUFSIZE, msg, args);
    printf("%s\n", logbuf);
    fflush(stdout);

    
#if UA_MULTITHREADING >= 100
# ifdef UA_ARCHITECTURE_POSIX
    UA_UNLOCK(&logLock);
# else
    spinUnLock();
# endif
#endif
}

static void
UA_Log_Stdout_clear(UA_Logger *logger) {
    UA_free(logger);
}

const UA_Logger UA_Log_Stdout_ = {UA_Log_Stdout_log, NULL, NULL};
const UA_Logger *UA_Log_Stdout = &UA_Log_Stdout_;

UA_Logger
UA_Log_Stdout_withLevel(UA_LogLevel minlevel) {
    UA_Logger logger =
        {UA_Log_Stdout_log, (void*)(uintptr_t)minlevel, NULL};
    return logger;
}

UA_Logger *
UA_Log_Stdout_new(UA_LogLevel minlevel) {
    UA_Logger *logger = (UA_Logger*)UA_malloc(sizeof(UA_Logger));
    if(!logger)
        return NULL;
    *logger = UA_Log_Stdout_withLevel(minlevel);
    logger->clear = UA_Log_Stdout_clear;
    return logger;
}
