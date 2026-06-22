/* Fuzz target for the framing + TLV parsers.
 *
 * Standard libFuzzer entry point: build with a fuzzing-capable toolchain
 * (clang -fsanitize=fuzzer,address,undefined) for coverage-guided fuzzing.
 * Where libFuzzer is unavailable (e.g. Apple clang), the same entry point
 * is driven by tests/fuzz/standalone_main.c under ASan/UBSan.
 *
 * The contract being fuzzed: no input — however malformed or truncated —
 * may cause a crash, OOB read, or infinite loop. Hostile public bytes
 * land here first, so this is the anti-DoS frontline. */
#include "mux.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* 1) Frame drain loop: parse frames until SHORT (need more) or a
     *    protocol error. Must always terminate and never read past `size`. */
    size_t cursor = 0;
    for (;;) {
        mux_frame_t f;
        size_t consumed = 0;
        int r = mux_parse(data + cursor, size - cursor, &f, &consumed);
        if (r != MUX_OK)
            break;
        /* A well-formed frame must make forward progress, else the loop
         * could spin. consumed >= header size is an invariant we assert. */
        if (consumed < MUX_HEADER_SIZE)
            __builtin_trap();
        /* Touch the payload view so ASan flags any out-of-bounds extent. */
        if (f.payload && f.len) {
            volatile uint8_t sink = 0;
            sink ^= f.payload[0];
            sink ^= f.payload[f.len - 1];
            (void)sink;
        }
        cursor += consumed;
        if (cursor > size)
            __builtin_trap(); /* over-consume would be a parser bug */
    }

    /* 2) TLV iterator over the raw bytes: also must terminate and stay
     *    in bounds for arbitrary input. */
    size_t tc = 0;
    uint16_t t, vlen;
    const uint8_t *val;
    int guard = 0;
    for (;;) {
        int g = mux_tlv_next(data, size, &tc, &t, &val, &vlen);
        if (g <= 0)
            break;
        if (val && vlen) {
            volatile uint8_t sink = 0;
            sink ^= val[0];
            sink ^= val[vlen - 1];
            (void)sink;
        }
        if (++guard > (int)size + 1)
            __builtin_trap(); /* iterator failed to terminate */
    }

    return 0;
}
