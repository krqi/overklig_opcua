
#include <limits.h>
#include "libc_time.h"


#define LEAPOCH (946684800LL + 86400*(31+29))

#define DAYS_PER_400Y (365*400 + 97)
#define DAYS_PER_100Y (365*100 + 24)
#define DAYS_PER_4Y   (365*4   + 1)

int __secs_to_tm(long long t, struct mytm *tm) {
    long long days, secs, years;
    int remdays, remsecs, remyears;
    int qc_cycles, c_cycles, q_cycles;
    int months;
    static const char days_in_month[] = {31,30,31,30,31,31,30,31,30,31,31,29};

    
    if (t < INT_MIN * 31622400LL || t > INT_MAX * 31622400LL)
        return -1;

    secs = t - LEAPOCH;
    days = secs / 86400LL;
    remsecs = (int)(secs % 86400);
    if (remsecs < 0) {
        remsecs += 86400;
        --days;
    }

    qc_cycles = (int)(days / DAYS_PER_400Y);
    remdays = (int)(days % DAYS_PER_400Y);
    if (remdays < 0) {
        remdays += DAYS_PER_400Y;
        --qc_cycles;
    }

    c_cycles = remdays / DAYS_PER_100Y;
    if (c_cycles == 4) --c_cycles;
    remdays -= c_cycles * DAYS_PER_100Y;

    q_cycles = remdays / DAYS_PER_4Y;
    if (q_cycles == 25) --q_cycles;
    remdays -= q_cycles * DAYS_PER_4Y;

    remyears = remdays / 365;
    if (remyears == 4) --remyears;
    remdays -= remyears * 365;

    years = remyears + 4*q_cycles + 100*c_cycles + 400LL*qc_cycles;

    for (months=0; days_in_month[months] <= remdays; ++months)
        remdays -= days_in_month[months];

    if (years+100 > INT_MAX || years+100 < INT_MIN)
        return -1;

    tm->tm_year = (int)(years + 100);
    tm->tm_mon = months + 2;
    if (tm->tm_mon >= 12) {
        tm->tm_mon -=12;
        ++tm->tm_year;
    }
    tm->tm_mday = remdays + 1;
    tm->tm_hour = remsecs / 3600;
    tm->tm_min = remsecs / 60 % 60;
    tm->tm_sec = remsecs % 60;

    return 0;
}

static const int secs_through_month[] =
    {0, 31*86400, 59*86400, 90*86400,
     120*86400, 151*86400, 181*86400, 212*86400,
     243*86400, 273*86400, 304*86400, 334*86400 };

static int
__month_to_secs(int month, int is_leap) {
    int t = secs_through_month[month];
    if (is_leap && month >= 2)
        t+=86400;
    return t;
}

static long long
__year_to_secs(const long long year, int *is_leap) {
    int cycles, centuries, leaps, rem;
    int is_leap_val = 0;
    if (!is_leap) {
        is_leap = &is_leap_val;
    }
    cycles = (int)((year-100) / 400);
    rem = (int)((year-100) % 400);
    if (rem < 0) {
        cycles--;
        rem += 400;
    }
    if (!rem) {
        *is_leap = 1;
        centuries = 0;
        leaps = 0;
    } else {
        if (rem >= 200) {
            if (rem >= 300) centuries = 3, rem -= 300;
            else centuries = 2, rem -= 200;
        } else {
            if (rem >= 100) centuries = 1, rem -= 100;
            else centuries = 0;
        }
        if (!rem) {
            *is_leap = 0;
            leaps = 0;
        } else {
            leaps = (rem / (int)4U);
            rem %= (int)4U;
            *is_leap = !rem;
        }
    }

    leaps += 97*cycles + 24*centuries - *is_leap;

    return (year-100) * 31536000LL + leaps * 86400LL + 946684800 + 86400;
}

long long __tm_to_secs(const struct mytm *tm) {
    int is_leap;
    long long year = tm->tm_year;
    int month = tm->tm_mon;
    if (month >= 12 || month < 0) {
        int adj = month / 12;
        month %= 12;
        if (month < 0) {
            adj--;
            month += 12;
        }
        year += adj;
    }
    long long t = __year_to_secs(year, &is_leap);
    t += __month_to_secs(month, is_leap);
    t += 86400LL * (tm->tm_mday-1);
    t += 3600LL * tm->tm_hour;
    t += 60LL * tm->tm_min;
    t += tm->tm_sec;
    return t;
}
