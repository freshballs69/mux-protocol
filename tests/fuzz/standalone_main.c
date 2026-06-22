/* Standalone driver for fuzz targets when libFuzzer is unavailable.
 *
 * Two modes:
 *   - With file arguments: replays each file through the target (corpus /
 *     regression replay), exactly like a libFuzzer binary does.
 *   - With no arguments: feeds a large batch of deterministic pseudo-random
 *     buffers (xorshift, fixed seed) so a plain ASan/UBSan build still gets
 *     meaningful coverage and stays reproducible in CI.
 *
 * Same ASan/UBSan crash semantics either way; the only thing missing vs.
 * real libFuzzer is coverage-guided mutation. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static uint64_t xs_state = 0x9e3779b97f4a7c15ull;
static uint64_t xs_next(void) {
    uint64_t x = xs_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    xs_state = x;
    return x;
}

static int run_file(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { perror(path); return 1; }
    fseek(fp, 0, SEEK_END);
    long n = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (n < 0) { fclose(fp); return 1; }
    uint8_t *buf = (uint8_t *)malloc((size_t)n ? (size_t)n : 1);
    size_t got = fread(buf, 1, (size_t)n, fp);
    fclose(fp);
    LLVMFuzzerTestOneInput(buf, got);
    free(buf);
    printf("replayed %s (%zu bytes)\n", path, got);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        int rc = 0;
        for (int i = 1; i < argc; i++)
            rc |= run_file(argv[i]);
        return rc;
    }

    /* No corpus: hammer the target with random + structured-ish inputs. */
    enum { ITERS = 200000, MAXLEN = 512 };
    uint8_t buf[MAXLEN];
    for (int it = 0; it < ITERS; it++) {
        size_t len = (size_t)(xs_next() % (MAXLEN + 1));
        for (size_t i = 0; i < len; i++)
            buf[i] = (uint8_t)(xs_next() & 0xff);
        /* Bias a fraction toward plausible headers (ver byte = 0x01) so the
         * fuzzer reaches past the version gate into payload/length handling. */
        if (len >= 12 && (it & 3) == 0)
            buf[0] = 0x01;
        LLVMFuzzerTestOneInput(buf, len);
    }
    printf("standalone fuzz: %d iterations, no crash\n", ITERS);
    return 0;
}
