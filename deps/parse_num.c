
#include "parse_num.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>

size_t
parseUInt64(const char *str, size_t size, uint64_t *result) {
    size_t i = 0;
    uint64_t n = 0, prev = 0;

    
    if(size > 2 && str[0] == '0' && (str[1] | 32) == 'x') {
        i = 2;
        for(; i < size; i++) {
            uint8_t c = (uint8_t)str[i] | 32;
            if(c >= '0' && c <= '9')
                c = (uint8_t)(c - '0');
            else if(c >= 'a' && c <='f')
                c = (uint8_t)(c - 'a' + 10);
            else if(c >= 'A' && c <='F')
                c = (uint8_t)(c - 'A' + 10);
            else
                break;
            n = (n << 4) | (c & 0xF);
            if(n < prev) 
                return 0;
            prev = n;
        }
        *result = n;
        return (i > 2) ? i : 0; 
    }

    
    for(; i < size; i++) {
        if(str[i] < '0' || str[i] > '9')
            break;
        
        n = (n << 3) + (n << 1) + (uint8_t)(str[i] - '0');
        if(n < prev) 
            return 0;
        prev = n;
    }
    *result = n;
    return i;
}

size_t
parseInt64(const char *str, size_t size, int64_t *result) {
    
    size_t i = 0;
    bool neg = false;
    if(*str == '-' || *str == '+') {
        neg = (*str == '-');
        i++;
    }

    
    uint64_t n = 0;
    size_t len = parseUInt64(&str[i], size - i, &n);
    if(len == 0)
        return 0;

    
    if(!neg) {
        if(n > 9223372036854775807UL)
            return 0;
        *result = (int64_t)n;
    } else {
        if(n > 9223372036854775808UL)
            return 0;
        *result = -(int64_t)n;
    }
    return len + i;
}

size_t parseDouble(const char *str, size_t size, double *result) {
    char buf[2000];
    if(size >= 2000)
        return 0;
    memcpy(buf, str, size);
    buf[size] = 0;
    errno = 0;
    char *endptr;
    *result = strtod(str, &endptr);
    if(errno != 0 && errno != ERANGE)
        return 0;
    return (uintptr_t)endptr - (uintptr_t)str;
}
