#include <stdint.h>
#include <string.h>

#include "thash.h"
#include "address.h"
#include "params.h"

#include "fips202.h"

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    unsigned char buf[SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N];

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_N + SPX_ADDR_BYTES, in, inblocks * SPX_N);

    shake256(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N);
}

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash_init_bitmask(unsigned char *bitmask_out, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    (void) bitmask_out;
    (void) inblocks;
    (void) ctx;
    (void) addr;
}

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash_fin(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8], const unsigned char *bitmask)
{
    (void) bitmask;
    thash(out, in, inblocks, ctx, addr);
}