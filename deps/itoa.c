

#include "itoa.h"

static void swap(char *x, char *y) {
    char t = *x;
    *x = *y;
    *y = t;
}


static char* reverse(char *buffer, UA_UInt16 i, UA_UInt16 j) {
    while (i < j)
        swap(&buffer[i++], &buffer[j--]);

    return buffer;
}


UA_UInt16 itoaUnsigned(UA_UInt64 value, char* buffer, UA_Byte base) {
    
    UA_UInt64 n = value;

    UA_UInt16 i = 0;
    while (n) {
        UA_UInt64 r = n % base;

        if (r >= 10)
            buffer[i++] = (char)(65 + (r - 10));
        else
            buffer[i++] = (char)(48 + r);

        n = n / base;
    }
    
    if (i == 0)
        buffer[i++] = '0';

    buffer[i] = '\0'; 
    i--;
    
    reverse(buffer, 0, i);
    i++;
    return i;
}


UA_UInt16 itoaSigned(UA_Int64 value, char* buffer) {
    
    
    UA_UInt64 n;
    if(value == UA_INT64_MIN) {
        n = (UA_UInt64)UA_INT64_MAX + 1;
    } else {
        n = (UA_UInt64)value;
        if(value < 0){
            n = (UA_UInt64)-value;
        }
    }

    UA_UInt16 i = 0;
    while(n) {
        UA_UInt64 r = n % 10;
        buffer[i++] = (char)('0' + r);
        n = n / 10;
    }

    if(i == 0)
        buffer[i++] = '0'; 
    if(value < 0)
        buffer[i++] = '-';
    buffer[i] = '\0'; 
    i--;
    reverse(buffer, 0, i); 
    i++;
    return i;
}

