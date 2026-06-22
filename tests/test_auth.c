/* Known-answer tests for the SHA-256 / HMAC-SHA256 used in tunnel auth. */
#include "auth.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0;

static void hex(const uint8_t *d, size_t n, char *out) {
    static const char *h = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[i*2]=h[d[i]>>4]; out[i*2+1]=h[d[i]&0xf]; }
    out[n*2] = 0;
}
static void expect(const uint8_t *got, const char *want, const char *name) {
    char h[2*SHA256_DIGEST_LEN + 1];
    hex(got, SHA256_DIGEST_LEN, h);
    if (strcmp(h, want) != 0) {
        fprintf(stderr, "FAIL %s\n  got  %s\n  want %s\n", name, h, want);
        g_fail++;
    }
}

int main(void) {
    uint8_t d[SHA256_DIGEST_LEN];

    /* NIST SHA-256 vectors */
    sha256("abc", 3, d);
    expect(d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256(abc)");
    sha256("", 0, d);
    expect(d, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256()");
    sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d);
    expect(d, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "sha256(2-block)");

    /* RFC 4231 HMAC-SHA256 test case 2 */
    hmac_sha256("Jefe", 4, "what do ya want for nothing?", 28, d);
    expect(d, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "hmac(Jefe)");

    /* constant-time compare */
    uint8_t a[8] = {1,2,3,4,5,6,7,8}, b[8] = {1,2,3,4,5,6,7,8}, c2[8] = {1,2,3,4,5,6,7,9};
    if (!ct_equal(a, b, 8)) { fprintf(stderr, "FAIL ct_equal eq\n"); g_fail++; }
    if (ct_equal(a, c2, 8)) { fprintf(stderr, "FAIL ct_equal neq\n"); g_fail++; }

    /* auth proof: deterministic, and nonce-sensitive */
    uint8_t p1[SHA256_DIGEST_LEN], p2[SHA256_DIGEST_LEN], p3[SHA256_DIGEST_LEN];
    const uint8_t n1[4] = {0xde,0xad,0xbe,0xef};
    const uint8_t n2[4] = {0xde,0xad,0xbe,0xf0};
    mux_auth_proof("secret", 6, n1, 4, p1);
    mux_auth_proof("secret", 6, n1, 4, p2);
    mux_auth_proof("secret", 6, n2, 4, p3);
    if (!ct_equal(p1, p2, SHA256_DIGEST_LEN)) { fprintf(stderr, "FAIL proof determinism\n"); g_fail++; }
    if (ct_equal(p1, p3, SHA256_DIGEST_LEN))  { fprintf(stderr, "FAIL proof nonce-sensitivity\n"); g_fail++; }

    if (g_fail) { fprintf(stderr, "\n%d auth check(s) failed\n", g_fail); return 1; }
    printf("all auth tests passed\n");
    return 0;
}
