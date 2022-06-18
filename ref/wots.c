#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "utilsx1.h"
#include "hash.h"
#include "thash.h"
#include "wots.h"
#include "wotsx1.h"
#include "address.h"
#include "params.h"



/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays.
 *
 * Interprets in as start-th value of the chain.
 * addr has to contain the address of the chain.
 */
static void gen_chain(unsigned char *out, const unsigned char *in,
                      unsigned int start, unsigned int steps,
                      const spx_ctx *ctx, uint32_t addr[8])
{
    uint32_t i;

    /* Initialize out with the value at position 'start'. */
    memcpy(out, in, SPX_N);

    /* Iterate 'steps' calls to the hash function. */
    for (i = start; i < (start+steps) && i < SPX_WOTS_W; i++) {
        set_hash_addr(addr, i);
        thash(out, out, 1, ctx, addr);
    }
}

/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 * This only works when log_w is a divisor of 8.
 */
static void base_w(unsigned int *output, const int out_len,
                   const unsigned char *input)
{
    /* new code to support w that are not 16 or 256, also seems to be faster */
    int i, j;
    unsigned int offset = 0;

    for (i = 0; i < out_len; i++) {
        output[i] = 0;
        for (j = 0; j < SPX_WOTS_LOGW; j++) {
            output[i] ^= ((input[offset >> 3] >> (offset & 0x7)) & 0x1) << j;
            offset++;
        }
    }
}

/* Computes the WOTS+C checksum over a message (in base_w).  concatenating checksum to lengths removed! */
static unsigned int wots_checksum(const unsigned int *msg_base_w)
{
    unsigned int csum = 0;
    unsigned int i;

    /* Compute checksum. */
    for (i = 0; i < SPX_WOTS_LEN1; i++) {
        csum += SPX_WOTS_W - 1 - msg_base_w[i];
    }
    return csum;
}

/* Takes a message and derives the matching chain lengths. */
unsigned int chain_lengths(unsigned int *lengths, const unsigned char *msg)
{
    unsigned int csum;

    base_w(lengths, SPX_WOTS_LEN1, msg);
    csum = wots_checksum(lengths);
    return csum;
}

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const spx_ctx *ctx, uint32_t addr[8], uint32_t counter)
{
    unsigned int lengths[SPX_WOTS_LEN];
    uint32_t i;
    uint32_t mask =  (~0U << (8-WOTS_ZERO_BITS));
    unsigned char bitmask[SPX_N];

    /*Initial parameters for validation of checksum*/
    int csum;
    unsigned char digest[SPX_N];

    /*Set thash address for custom hash to type 6 & PK format*/
    uint32_t wots_pk_addr[8] = {0};
    set_type(wots_pk_addr, SPX_ADDR_TYPE_COMPRESS_WOTS);
    copy_keypair_addr(wots_pk_addr, addr);
    thash_init_bitmask(bitmask, 1, ctx, wots_pk_addr);

    /*Set padding*/
    ull_to_bytes(((unsigned char *) (wots_pk_addr))+(SPX_OFFSER_COUNTER) , COUNTER_SIZE, counter);
    /*Calculate checksum*/
    thash_fin(digest, msg, 1, ctx, wots_pk_addr, bitmask);
    

    csum = chain_lengths(lengths, digest);

    /*Validate Checksum*/
    if ((csum != WANTED_CHECKSUM) || (((digest[SPX_N-1]) & (mask)) !=0)){   
        memset(pk,0,SPX_PK_BYTES);
    }
    else
    {
    for (i = 0; i < SPX_WOTS_LEN; i++) {
        set_chain_addr(addr, i);
        gen_chain(pk + i*SPX_N, sig + i*SPX_N,
                  lengths[i], SPX_WOTS_W - 1 - lengths[i], ctx, addr);
        }
    }
}
