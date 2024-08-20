
#include <opcua/types.h>


#ifdef UA_ARCHITECTURE_POSIX

#include <time.h>
#include <sys/time.h>

#if defined(__APPLE__) || defined(__MACH__)
# include <mach/clock.h>
# include <mach/mach.h>
#endif

UA_DateTime UA_DateTime_now(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * UA_DATETIME_SEC) +
        (tv.tv_usec * UA_DATETIME_USEC) +
        UA_DATETIME_UNIX_EPOCH;
}


UA_Int64 UA_DateTime_localTimeUtcOffset(void) {
    time_t rawtime = time(NULL);
    struct tm gbuf;
    struct tm *ptm = gmtime_r(&rawtime, &gbuf);
    
    ptm->tm_isdst = -1;
    time_t gmt = mktime(ptm);
    return (UA_Int64) (difftime(rawtime, gmt) * UA_DATETIME_SEC);
}

UA_DateTime UA_DateTime_nowMonotonic(void) {
#if defined(__APPLE__) || defined(__MACH__)
    
    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    mach_port_deallocate(mach_task_self(), cclock);
    return (mts.tv_sec * UA_DATETIME_SEC) + (mts.tv_nsec / 100);
#elif !defined(CLOCK_MONOTONIC_RAW)
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * UA_DATETIME_SEC) + (ts.tv_nsec / 100);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (ts.tv_sec * UA_DATETIME_SEC) + (ts.tv_nsec / 100);
#endif
}

#endif 

#ifdef UA_ARCHITECTURE_WIN32

#include <time.h>

# ifdef SLIST_ENTRY
#  pragma push_macro("SLIST_ENTRY")
#  undef SLIST_ENTRY
#  define POP_SLIST_ENTRY
# endif
# include <windows.h>

# ifdef POP_SLIST_ENTRY
#  undef SLIST_ENTRY
#  undef POP_SLIST_ENTRY
#  pragma pop_macro("SLIST_ENTRY")
# endif


UA_DateTime
UA_DateTime_now(void) {
    FILETIME ft;
    SYSTEMTIME st;
    GetSystemTime(&st);
    SystemTimeToFileTime(&st, &ft);
    ULARGE_INTEGER ul;
    ul.LowPart = ft.dwLowDateTime;
    ul.HighPart = ft.dwHighDateTime;
    return (UA_DateTime)ul.QuadPart;
}


UA_Int64
UA_DateTime_localTimeUtcOffset(void) {
    time_t rawtime = time(NULL);
    struct tm ptm;
#ifdef __CODEGEARC__
    gmtime_s(&rawtime, &ptm);
#else
    gmtime_s(&ptm, &rawtime);
#endif

    
    ptm.tm_isdst = -1;
    time_t gmt = mktime(&ptm);

    return (UA_Int64) (difftime(rawtime, gmt) * UA_DATETIME_SEC);
}

UA_DateTime
UA_DateTime_nowMonotonic(void) {
    LARGE_INTEGER freq, ticks;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&ticks);
    UA_Double ticks2dt = UA_DATETIME_SEC / (UA_Double)freq.QuadPart;
    return (UA_DateTime)(ticks.QuadPart * ticks2dt);
}

#endif 
