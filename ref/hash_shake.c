#include <stdint.h>
#include <string.h>

#include "address.h"
#include "utils.h"
#include "params.h"
#include "hash.h"
#include "fips202.h"

/* For SHAKE256, there is no immediate reason to initialize at the start,
   so this function is an empty operation. */
void initialize_hash_function(spx_ctx* ctx)
{
    (void)ctx; /* Suppress an 'unused parameter' warning. */
}

/*
 * Computes PRF(pk_seed, sk_seed, addr)
 */
void prf_addr(unsigned char *out, const spx_ctx *ctx,
              const uint32_t addr[8])
{
    unsigned char buf[2*SPX_N + SPX_ADDR_BYTES];

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_N + SPX_ADDR_BYTES, ctx->sk_seed, SPX_N);

    shake256(out, SPX_N, buf, 2*SPX_N + SPX_ADDR_BYTES);
}

/**
 * Computes the message-dependent randomness R, using a secret seed and an
 * optional randomization value as well as the message.
 */
void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const spx_ctx *ctx)
{
    (void)ctx;
    uint64_t s_inc[26];

    shake256_inc_init(s_inc);
    shake256_inc_absorb(s_inc, sk_prf, SPX_N);
    shake256_inc_absorb(s_inc, optrand, SPX_N);
    shake256_inc_absorb(s_inc, m, mlen);
    shake256_inc_finalize(s_inc);
    shake256_inc_squeeze(R, SPX_N, s_inc);
}

void hash_with_counter(unsigned char *buf,const unsigned char *R,const unsigned char *pk,
                       const unsigned char *m, unsigned long long mlen,unsigned char *counter_bytes)
{
#define MAX_HASH_TRIALS_FORS (1 << (SPX_FORS_ZERO_LAST_BITS + 10))
#define SPX_FORS_ZEROED_BYTES ((SPX_FORS_ZERO_LAST_BITS + 7) / 8)

#define SPX_TREE_BITS (SPX_TREE_HEIGHT * (SPX_D - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (SPX_FORS_ZEROED_BYTES+SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

    uint64_t s_inc[26];
    shake256_inc_init(s_inc);
    shake256_inc_absorb(s_inc, R, SPX_N);
    shake256_inc_absorb(s_inc, pk, SPX_PK_BYTES);
    shake256_inc_absorb(s_inc, m, mlen);
    shake256_inc_absorb(s_inc, counter_bytes, COUNTER_SIZE);
    shake256_inc_finalize(s_inc);
    shake256_inc_squeeze(buf, SPX_DGST_BYTES, s_inc);
}

/**
 * Computes the message hash using R, the public key, the message, and a counter.
 * if passed counter is zero, searches for counter that zeros out last NUM_OF_ZEROED_BITS
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 */
int hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const spx_ctx *ctx, uint32_t *counter)
{
    (void)ctx;
    unsigned char buf[SPX_DGST_BYTES];
    unsigned char *bufp = buf;
    unsigned char counter_bytes[COUNTER_SIZE];
    int found_flag=1;
    unsigned long long int mask =  ~(~0U << (SPX_FORS_ZERO_LAST_BITS));
    unsigned long long int zero_bits;

    /*verify stage*/
    if (*counter!=0)
    {
        ull_to_bytes(counter_bytes,COUNTER_SIZE,*counter);
        hash_with_counter(buf,R,pk,m,mlen,counter_bytes);
        //If the expected bits are not zero the verification fails.
        zero_bits = bytes_to_ull(bufp, SPX_FORS_ZEROED_BYTES);
        if( (zero_bits& (mask))!=0)
            return -1;
    }
    /*sign stage, searches for counter*/
    else
    {
        while(found_flag)
        {
            //counter should be 1 or larger.
            (*counter)++;
            if (*counter > MAX_HASH_TRIALS_FORS)
                return -1;
            ull_to_bytes(counter_bytes, COUNTER_SIZE, *counter);
            hash_with_counter(buf,R,pk,m,mlen,counter_bytes);
            zero_bits = bytes_to_ull(bufp, SPX_FORS_ZEROED_BYTES);
            if( (zero_bits & (mask))==0)
            {
                found_flag = 0;
                /*Save Counter*/
                break;
            }

        }
    }
    bufp += SPX_FORS_ZEROED_BYTES;

    memcpy(digest, bufp, SPX_FORS_MSG_BYTES);
    bufp += SPX_FORS_MSG_BYTES;

#if SPX_TREE_BITS > 64
    #error For given height and depth, 64 bits cannot represent all subtrees
#endif

    *tree = bytes_to_ull(bufp, SPX_TREE_BYTES);
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    bufp += SPX_TREE_BYTES;

    *leaf_idx = bytes_to_ull(bufp, SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
    return 0;
}
