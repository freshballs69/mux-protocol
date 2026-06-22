/* Minimal SHA-256 + HMAC-SHA256 for daemon-side tunnel authentication.
 *
 * libmux itself is crypto-agnostic (it only carries opaque AUTH/NONCE TLVs);
 * the daemons compute and verify the pre-shared-key proof here. This is a
 * small, dependency-free implementation so `edge`/`edge-peer` need no OpenSSL.
 */
#ifndef MUX_AUTH_H
#define MUX_AUTH_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_LEN 32u

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[SHA256_DIGEST_LEN]);
void sha256(const void *data, size_t len, uint8_t out[SHA256_DIGEST_LEN]);

/* HMAC-SHA256(key, msg) -> out[32]. */
void hmac_sha256(const void *key, size_t keylen,
                 const void *msg, size_t msglen,
                 uint8_t out[SHA256_DIGEST_LEN]);

/* Constant-time equality (1 if equal, 0 otherwise). */
int ct_equal(const void *a, const void *b, size_t n);

/* Tunnel auth proof for a pre-shared token, bound to a per-session nonce:
 *   proof = HMAC-SHA256(token, "mux/v1/auth" || nonce)
 * Both peers compute the other's expected proof from the nonce carried in the
 * peer's HELLO and compare in constant time. (Replay resistance comes from the
 * transport layer (TLS/Noise) added in a later milestone; this gates the
 * handshake on token possession without sending the token.) */
void mux_auth_proof(const void *token, size_t token_len,
                    const uint8_t *nonce, size_t nonce_len,
                    uint8_t out[SHA256_DIGEST_LEN]);

#endif /* MUX_AUTH_H */
