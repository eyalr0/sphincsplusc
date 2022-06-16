#ifndef SPX_CONTEXT_H
#define SPX_CONTEXT_H

#include <stdint.h>
#error Not implemented for SPHINCS+C
#include "params.h"

typedef struct {
    uint8_t pub_seed[SPX_N];
    uint8_t sk_seed[SPX_N];
} spx_ctx;

#endif
