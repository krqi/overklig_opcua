
#ifndef PCG_BASIC_H_
#define PCG_BASIC_H_

#if defined(UNDER_CE) || !defined(_MSC_VER) || _MSC_VER >= 1800
# include <stdint.h>
#else
# include "ms_stdint.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pcg_state_setseq_64 {
    uint64_t state;  
} pcg32_random_t;

#define PCG32_INITIALIZER { 0x853c49e6748fea9bULL, 0xda3e39cb94b95bdbULL }

void pcg32_srandom_r(pcg32_random_t* rng, uint64_t initial_state, uint64_t initseq);
uint32_t pcg32_random_r(pcg32_random_t* rng);

#ifdef __cplusplus
}
#endif

#endif 
