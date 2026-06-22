/* evloop — a thin portable readiness loop over epoll (Linux) and kqueue
 * (macOS/BSD). Level-triggered, like poll(), but O(ready) per wait instead of
 * O(registered): this is what lets one edge thread carry tens of thousands of
 * public sockets without rescanning them all every iteration.
 *
 * Each fd carries an opaque udata pointer returned on its ready events. Interest
 * is expressed as two booleans (want_read / want_write); evloop_set adds a new
 * fd or updates an existing one. Update interest only when it actually changes.
 */
#ifndef MUX_EVLOOP_H
#define MUX_EVLOOP_H

#include <stddef.h>

typedef struct evloop evloop;

typedef struct {
    void *udata;
    int   readable;   /* fd is readable / hung up / errored                */
    int   writable;   /* fd is writable                                    */
} ev_event;

evloop *evloop_new(void);
void    evloop_free(evloop *l);

/* Register fd (or change its interest). Returns 0 on success, -1 on error. */
int evloop_set(evloop *l, int fd, int want_read, int want_write, void *udata);

/* Stop watching fd. */
int evloop_del(evloop *l, int fd);

/* Wait up to timeout_ms (-1 = forever) for readiness; fill out[0..max) and
 * return the count, 0 on timeout, -1 on error (EINTR yields 0). */
int evloop_wait(evloop *l, ev_event *out, int max, int timeout_ms);

#endif /* MUX_EVLOOP_H */
