/* evloop — epoll / kqueue backends. See evloop.h. */
#include "evloop.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__)
/* ============================ epoll ============================ */
#include <sys/epoll.h>

struct evloop { int epfd; };

evloop *evloop_new(void) {
    evloop *l = (evloop *)calloc(1, sizeof *l);
    if (!l) return NULL;
    l->epfd = epoll_create1(0);
    if (l->epfd < 0) { free(l); return NULL; }
    return l;
}
void evloop_free(evloop *l) { if (!l) return; close(l->epfd); free(l); }

int evloop_set(evloop *l, int fd, int want_read, int want_write, void *udata) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof ev);
    ev.events = (want_read ? EPOLLIN : 0) | (want_write ? EPOLLOUT : 0);
    ev.data.ptr = udata;
    if (epoll_ctl(l->epfd, EPOLL_CTL_MOD, fd, &ev) == 0)
        return 0;
    if (errno == ENOENT)
        return epoll_ctl(l->epfd, EPOLL_CTL_ADD, fd, &ev);
    return -1;
}
int evloop_del(evloop *l, int fd) {
    return epoll_ctl(l->epfd, EPOLL_CTL_DEL, fd, NULL);
}
int evloop_wait(evloop *l, ev_event *out, int max, int timeout_ms) {
    struct epoll_event evs[1024];
    int want = max < 1024 ? max : 1024;
    int n = epoll_wait(l->epfd, evs, want, timeout_ms);
    if (n < 0) return errno == EINTR ? 0 : -1;
    for (int i = 0; i < n; i++) {
        out[i].udata = evs[i].data.ptr;
        out[i].readable = (evs[i].events & (EPOLLIN | EPOLLHUP | EPOLLERR)) != 0;
        out[i].writable = (evs[i].events & EPOLLOUT) != 0;
    }
    return n;
}

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
/* ============================ kqueue ============================ */
#include <sys/event.h>
#include <sys/types.h>
#include <sys/time.h>

struct evloop { int kq; };

evloop *evloop_new(void) {
    evloop *l = (evloop *)calloc(1, sizeof *l);
    if (!l) return NULL;
    l->kq = kqueue();
    if (l->kq < 0) { free(l); return NULL; }
    return l;
}
void evloop_free(evloop *l) { if (!l) return; close(l->kq); free(l); }

int evloop_set(evloop *l, int fd, int want_read, int want_write, void *udata) {
    /* Register both filters, enabling the wanted ones and disabling the rest.
     * EV_ADD on an existing filter updates it; udata rides on each kevent. */
    struct kevent ch[2];
    EV_SET(&ch[0], fd, EVFILT_READ,  EV_ADD | (want_read  ? EV_ENABLE : EV_DISABLE), 0, 0, udata);
    EV_SET(&ch[1], fd, EVFILT_WRITE, EV_ADD | (want_write ? EV_ENABLE : EV_DISABLE), 0, 0, udata);
    return kevent(l->kq, ch, 2, NULL, 0, NULL);
}
int evloop_del(evloop *l, int fd) {
    struct kevent ch[2];
    EV_SET(&ch[0], fd, EVFILT_READ,  EV_DELETE, 0, 0, NULL);
    EV_SET(&ch[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
    kevent(l->kq, ch, 2, NULL, 0, NULL);   /* ignore ENOENT on already-closed */
    return 0;
}
int evloop_wait(evloop *l, ev_event *out, int max, int timeout_ms) {
    struct kevent evs[1024];
    int want = max < 1024 ? max : 1024;
    struct timespec ts, *pts = NULL;
    if (timeout_ms >= 0) { ts.tv_sec = timeout_ms / 1000; ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000L; pts = &ts; }
    int n = kevent(l->kq, NULL, 0, evs, want, pts);
    if (n < 0) return errno == EINTR ? 0 : -1;
    /* Coalesce read+write readiness for the same fd into one ev_event. */
    int m = 0;
    for (int i = 0; i < n; i++) {
        void *ud = evs[i].udata;
        int readable = (evs[i].filter == EVFILT_READ) || (evs[i].flags & EV_EOF);
        int writable = (evs[i].filter == EVFILT_WRITE);
        int found = -1;
        for (int j = 0; j < m; j++) if (out[j].udata == ud) { found = j; break; }
        if (found >= 0) { out[found].readable |= readable; out[found].writable |= writable; }
        else { out[m].udata = ud; out[m].readable = readable; out[m].writable = writable; m++; }
    }
    return m;
}

#else
#error "evloop: no epoll or kqueue backend for this platform"
#endif
