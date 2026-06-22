/* muxpeer — Python binding for libpeer.
 *
 * Gives a Python worker a socket-shaped handle on inbound mux streams while
 * paying for one tunnel fd. Designed for the supervisord model: each replica
 * binds its own unix socket and the edge-peer dials in.
 *
 *   import muxpeer
 *   peer = muxpeer.listen("/run/app_00.sock", token="KEY", id="W0", weight=4)
 *   while True:
 *       conn = peer.accept()          # blocking; None on shutdown
 *       if conn is None: break
 *       req = conn.recv(65536)        # blocking; b"" on EOF
 *       conn.sendall(b"HTTP/1.1 200 OK\r\n...")
 *       conn.close()
 *   peer.close()
 *
 * Blocking calls release the GIL, so a thread-per-connection worker scales.
 * peer.fileno() exposes an accept-readiness fd for selectors/asyncio loops.
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "libpeer.h"
#include "net.h"

#include <string.h>

/* ============================ Stream ============================ */
typedef struct {
    PyObject_HEAD
    lp_stream *s;
    PyObject  *peer;       /* strong ref to the owning Peer (poll mode) */
} StreamObj;

static PyTypeObject StreamType;
static PyObject *peer_drop_stream(PyObject *peer, lp_stream *s); /* fwd */

static PyObject *Stream_recv(StreamObj *self, PyObject *args) {
    Py_ssize_t n = 65536;
    if (!PyArg_ParseTuple(args, "|n", &n)) return NULL;
    if (!self->s) { PyErr_SetString(PyExc_OSError, "stream closed"); return NULL; }
    if (n <= 0) return PyBytes_FromStringAndSize("", 0);

    PyObject *buf = PyBytes_FromStringAndSize(NULL, n);
    if (!buf) return NULL;
    lp_stream *s = self->s;
    ssize_t got;
    Py_BEGIN_ALLOW_THREADS
    got = lp_read(s, PyBytes_AS_STRING(buf), (size_t)n);
    Py_END_ALLOW_THREADS
    if (got < 0) { Py_DECREF(buf); PyErr_SetString(PyExc_OSError, "stream reset"); return NULL; }
    if (got == 0) { Py_DECREF(buf); return PyBytes_FromStringAndSize("", 0); } /* EOF */
    if (got != n) _PyBytes_Resize(&buf, got);
    return buf;
}

static PyObject *Stream_sendall(StreamObj *self, PyObject *args) {
    Py_buffer view;
    if (!PyArg_ParseTuple(args, "y*", &view)) return NULL;
    if (!self->s) { PyBuffer_Release(&view); PyErr_SetString(PyExc_OSError, "stream closed"); return NULL; }
    lp_stream *s = self->s;
    const char *p = (const char *)view.buf;
    size_t len = (size_t)view.len;
    ssize_t w = 0;
    if (len > 0) {
        Py_BEGIN_ALLOW_THREADS
        w = lp_write(s, p, len);
        Py_END_ALLOW_THREADS
    }
    PyBuffer_Release(&view);
    if (w < 0) { PyErr_SetString(PyExc_OSError, "stream reset"); return NULL; }
    Py_RETURN_NONE;
}

/* Non-blocking recv for event-loop use: bytes, b'' on EOF, or None if it would
 * block. Drain in a loop until None/b''. */
static PyObject *Stream_recv_nb(StreamObj *self, PyObject *args) {
    Py_ssize_t n = 65536;
    if (!PyArg_ParseTuple(args, "|n", &n)) return NULL;
    if (!self->s) Py_RETURN_NONE;
    if (n <= 0) return PyBytes_FromStringAndSize("", 0);
    PyObject *buf = PyBytes_FromStringAndSize(NULL, n);
    if (!buf) return NULL;
    ssize_t got = lp_read_nb(self->s, PyBytes_AS_STRING(buf), (size_t)n);
    if (got == LP_AGAIN) { Py_DECREF(buf); Py_RETURN_NONE; }
    if (got < 0)         { Py_DECREF(buf); PyErr_SetString(PyExc_OSError, "stream reset"); return NULL; }
    if (got == 0)        { Py_DECREF(buf); return PyBytes_FromStringAndSize("", 0); }
    if (got != n) _PyBytes_Resize(&buf, got);
    return buf;
}

/* Non-blocking send: returns bytes queued, or None if the send buffer is full
 * (await a WRITABLE event, then retry). */
static PyObject *Stream_send_nb(StreamObj *self, PyObject *args) {
    Py_buffer view;
    if (!PyArg_ParseTuple(args, "y*", &view)) return NULL;
    if (!self->s) { PyBuffer_Release(&view); PyErr_SetString(PyExc_OSError, "stream closed"); return NULL; }
    ssize_t w = view.len > 0 ? lp_write_nb(self->s, view.buf, (size_t)view.len) : 0;
    PyBuffer_Release(&view);
    if (w == LP_AGAIN) Py_RETURN_NONE;
    if (w < 0) { PyErr_SetString(PyExc_OSError, "stream reset"); return NULL; }
    return PyLong_FromSsize_t(w);
}

static PyObject *Stream_close(StreamObj *self, PyObject *Py_UNUSED(ignored)) {
    if (self->s) {
        if (self->peer) peer_drop_stream(self->peer, self->s);  /* poll-mode map */
        lp_close(self->s);
        self->s = NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *Stream_get_meta(StreamObj *self, void *Py_UNUSED(c)) {
    if (!self->s) Py_RETURN_NONE;
    size_t len = 0;
    const uint8_t *m = lp_stream_meta(self->s, &len);
    return PyBytes_FromStringAndSize((const char *)(m ? m : (const uint8_t*)""), (Py_ssize_t)len);
}

static PyObject *Stream_enter(StreamObj *self, PyObject *Py_UNUSED(i)) { Py_INCREF(self); return (PyObject*)self; }
static PyObject *Stream_exit(StreamObj *self, PyObject *Py_UNUSED(a)) {
    if (self->s) {
        if (self->peer) peer_drop_stream(self->peer, self->s);  /* every close path prunes the map */
        lp_close(self->s); self->s = NULL;
    }
    Py_RETURN_FALSE;
}

static void Stream_dealloc(StreamObj *self) {
    if (self->s) {
        if (self->peer) peer_drop_stream(self->peer, self->s);
        lp_close(self->s); self->s = NULL;
    }
    Py_XDECREF(self->peer);
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyMethodDef Stream_methods[] = {
    {"recv", (PyCFunction)Stream_recv, METH_VARARGS, "recv(n=65536) -> bytes; b'' on EOF (blocking)"},
    {"sendall", (PyCFunction)Stream_sendall, METH_VARARGS, "sendall(data) -> None (blocking)"},
    {"recv_nb", (PyCFunction)Stream_recv_nb, METH_VARARGS, "recv_nb(n) -> bytes | b'' (EOF) | None (would block)"},
    {"send_nb", (PyCFunction)Stream_send_nb, METH_VARARGS, "send_nb(data) -> int queued | None (would block)"},
    {"close", (PyCFunction)Stream_close, METH_NOARGS, "close the stream (FIN)"},
    {"__enter__", (PyCFunction)Stream_enter, METH_NOARGS, NULL},
    {"__exit__", (PyCFunction)Stream_exit, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};
static PyGetSetDef Stream_getset[] = {
    {"meta", (getter)Stream_get_meta, NULL, "client metadata bytes (src ip:port / PROXY info)", NULL},
    {NULL, NULL, NULL, NULL, NULL}
};
static PyTypeObject StreamType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "muxpeer.Stream",
    .tp_basicsize = sizeof(StreamObj),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "A conn-like inbound mux stream",
    .tp_methods = Stream_methods,
    .tp_getset = Stream_getset,
    .tp_dealloc = (destructor)Stream_dealloc,
};

/* ============================ Peer ============================ */
typedef struct {
    PyObject_HEAD
    lp_client *c;
    PyObject  *streams;    /* poll mode: dict {lp_stream* -> StreamObj}   */
    char *s_listen, *s_host, *s_token, *s_id;
} PeerObj;

static PyTypeObject PeerType;

/* Remove a stream from the Peer's poll-mode map (called on Stream.close). */
static PyObject *peer_drop_stream(PyObject *peer, lp_stream *s) {
    PeerObj *p = (PeerObj *)peer;
    if (p->streams) {
        PyObject *key = PyLong_FromVoidPtr(s);
        if (key) { PyDict_DelItem(p->streams, key); PyErr_Clear(); Py_DECREF(key); }
    }
    Py_RETURN_NONE;
}

/* Wrap a raw lp_stream into a StreamObj bound to this peer (new ref). */
static StreamObj *peer_wrap(PeerObj *self, lp_stream *s) {
    StreamObj *o = PyObject_New(StreamObj, &StreamType);
    if (!o) return NULL;
    o->s = s;
    Py_INCREF(self); o->peer = (PyObject *)self;
    return o;
}

static PyObject *Peer_accept(PeerObj *self, PyObject *Py_UNUSED(i)) {
    if (!self->c) { PyErr_SetString(PyExc_OSError, "peer closed"); return NULL; }
    lp_client *c = self->c;
    lp_stream *s;
    Py_BEGIN_ALLOW_THREADS
    s = lp_accept(c);
    Py_END_ALLOW_THREADS
    if (!s) Py_RETURN_NONE;                 /* shutting down */
    StreamObj *o = PyObject_New(StreamObj, &StreamType);
    if (!o) { lp_close(s); return NULL; }
    o->s = s; o->peer = NULL;               /* blocking mode: not in the map */
    return (PyObject *)o;
}

static PyObject *Peer_fileno(PeerObj *self, PyObject *Py_UNUSED(i)) {
    if (!self->c) { PyErr_SetString(PyExc_OSError, "peer closed"); return NULL; }
    return PyLong_FromLong(lp_fileno(self->c));
}

/* Non-blocking poll for event-loop integration. Returns a list of
 * (Stream, events) where events is an OR of muxpeer.ACCEPT/READABLE/WRITABLE/
 * CLOSED. New (ACCEPT) streams are wrapped and remembered so later events for
 * the same stream return the same Stream object. */
static PyObject *Peer_poll(PeerObj *self, PyObject *args) {
    int maxev = 256;
    if (!PyArg_ParseTuple(args, "|i", &maxev)) return NULL;
    if (!self->c) { PyErr_SetString(PyExc_OSError, "peer closed"); return NULL; }
    if (maxev < 1) maxev = 1;
    if (maxev > 4096) maxev = 4096;

    lp_event evs[4096];
    int n = lp_poll(self->c, evs, maxev);
    PyObject *list = PyList_New(0);
    if (!list) return NULL;

    for (int i = 0; i < n; i++) {
        StreamObj *so = NULL;
        PyObject *key = PyLong_FromVoidPtr(evs[i].stream);
        if (!key) { lp_close(evs[i].stream); goto fail; }

        if (evs[i].events & LP_ACCEPT) {
            so = peer_wrap(self, evs[i].stream);   /* new ref */
            if (!so) { Py_DECREF(key); lp_close(evs[i].stream); goto fail; }
            if (PyDict_SetItem(self->streams, key, (PyObject *)so) != 0) {
                Py_DECREF(key); Py_DECREF(so); lp_close(evs[i].stream); goto fail;
            }
        } else {
            PyObject *found = PyDict_GetItem(self->streams, key);  /* borrowed */
            if (!found) { Py_DECREF(key); continue; }   /* already-closed stream */
            so = (StreamObj *)found;
            Py_INCREF(so);
        }

        PyObject *tup = Py_BuildValue("(Oi)", (PyObject *)so, evs[i].events);
        Py_DECREF(so);
        if (!tup) { Py_DECREF(key); goto fail; }
        int rc = PyList_Append(list, tup);
        Py_DECREF(tup);
        if (rc != 0) { Py_DECREF(key); goto fail; }

        /* A closed stream won't appear again: drop the map's strong ref so the
         * StreamObj (and its C stream, once the handler closes it) can be reaped
         * and the map can't grow without bound or alias a reused pointer. */
        if (evs[i].events & LP_CLOSED)
            PyDict_DelItem(self->streams, key);
        Py_DECREF(key);
    }
    return list;
fail:
    PyErr_Clear();
    Py_DECREF(list);
    PyErr_SetString(PyExc_RuntimeError, "muxpeer poll failed");
    return NULL;
}

static PyObject *Peer_close(PeerObj *self, PyObject *Py_UNUSED(i)) {
    if (self->c) { lp_client *c = self->c; self->c = NULL;
        Py_BEGIN_ALLOW_THREADS
        lp_disconnect(c);
        Py_END_ALLOW_THREADS
    }
    Py_RETURN_NONE;
}

static PyObject *Peer_enter(PeerObj *self, PyObject *Py_UNUSED(i)) { Py_INCREF(self); return (PyObject*)self; }
static PyObject *Peer_exit(PeerObj *self, PyObject *Py_UNUSED(a)) {
    if (self->c) { lp_client *c = self->c; self->c = NULL; Py_BEGIN_ALLOW_THREADS lp_disconnect(c); Py_END_ALLOW_THREADS }
    Py_RETURN_FALSE;
}

static void Peer_dealloc(PeerObj *self) {
    if (self->c) { lp_disconnect(self->c); self->c = NULL; }
    Py_XDECREF(self->streams);
    free(self->s_listen); free(self->s_host); free(self->s_token); free(self->s_id);
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyMethodDef Peer_methods[] = {
    {"accept", (PyCFunction)Peer_accept, METH_NOARGS, "accept() -> Stream or None (blocking)"},
    {"fileno", (PyCFunction)Peer_fileno, METH_NOARGS, "fileno() -> int readiness fd for select/asyncio"},
    {"poll", (PyCFunction)Peer_poll, METH_VARARGS, "poll(max=256) -> [(Stream, events), ...] (non-blocking)"},
    {"close", (PyCFunction)Peer_close, METH_NOARGS, "stop the I/O thread and drop the tunnel"},
    {"__enter__", (PyCFunction)Peer_enter, METH_NOARGS, NULL},
    {"__exit__", (PyCFunction)Peer_exit, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};
static PyTypeObject PeerType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "muxpeer.Peer",
    .tp_basicsize = sizeof(PeerObj),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "A worker tunnel to an edge-peer",
    .tp_methods = Peer_methods,
    .tp_dealloc = (destructor)Peer_dealloc,
};

/* ============================ module funcs ============================ */
static char *dup_or_null(const char *s) { return s ? strdup(s) : NULL; }

static PeerObj *build_peer(const char *listen_addr, const char *dial_addr,
                           const char *token, const char *id, unsigned weight,
                           unsigned init_window, unsigned session_window, unsigned heartbeat_ms) {
    PeerObj *self = PyObject_New(PeerObj, &PeerType);
    if (!self) return NULL;
    self->c = NULL;
    self->streams = PyDict_New();
    if (!self->streams) { Py_DECREF(self); return NULL; }
    self->s_listen = dup_or_null(listen_addr);
    self->s_host = NULL; self->s_token = dup_or_null(token); self->s_id = dup_or_null(id);

    lp_config cfg; memset(&cfg, 0, sizeof cfg);
    cfg.token = self->s_token; cfg.peer_id = self->s_id;
    cfg.weight = weight; cfg.init_window = init_window;
    cfg.session_window = session_window; cfg.heartbeat_ms = heartbeat_ms;

    if (listen_addr) {
        cfg.listen_addr = self->s_listen;
    } else {
        /* dial: unix path stays as host; "host:port" is split */
        if (net_addr_is_unix(dial_addr)) {
            self->s_host = dup_or_null(dial_addr);
            cfg.host = self->s_host;
        } else {
            char host[256]; uint16_t port;
            if (net_parse_addr(dial_addr, host, sizeof host, &port) != 0) {
                PyErr_SetString(PyExc_ValueError, "address must be 'host:port' or a unix path");
                Py_DECREF(self); return NULL;
            }
            self->s_host = strdup(host);
            cfg.host = self->s_host; cfg.port = port;
        }
    }

    lp_client *c;
    Py_BEGIN_ALLOW_THREADS
    c = lp_connect(&cfg);
    Py_END_ALLOW_THREADS
    if (!c) { PyErr_SetString(PyExc_OSError, "lp_connect failed"); Py_DECREF(self); return NULL; }
    self->c = c;
    return self;
}

static PyObject *mod_listen(PyObject *Py_UNUSED(m), PyObject *args, PyObject *kw) {
    static char *kws[] = {"addr", "token", "id", "weight", "init_window", "session_window", "heartbeat_ms", NULL};
    const char *addr, *token = NULL, *id = NULL;
    unsigned weight = 1, iw = 0, sw = 0, hb = 0;
    if (!PyArg_ParseTupleAndKeywords(args, kw, "s|zzIIII", kws, &addr, &token, &id, &weight, &iw, &sw, &hb))
        return NULL;
    return (PyObject *)build_peer(addr, NULL, token, id, weight, iw, sw, hb);
}

static PyObject *mod_connect(PyObject *Py_UNUSED(m), PyObject *args, PyObject *kw) {
    static char *kws[] = {"addr", "token", "id", "weight", "init_window", "session_window", "heartbeat_ms", NULL};
    const char *addr, *token = NULL, *id = NULL;
    unsigned weight = 1, iw = 0, sw = 0, hb = 0;
    if (!PyArg_ParseTupleAndKeywords(args, kw, "s|zzIIII", kws, &addr, &token, &id, &weight, &iw, &sw, &hb))
        return NULL;
    return (PyObject *)build_peer(NULL, addr, token, id, weight, iw, sw, hb);
}

static PyMethodDef module_methods[] = {
    {"listen", (PyCFunction)mod_listen, METH_VARARGS | METH_KEYWORDS,
     "listen(addr, token=None, id=None, weight=1, ...) -> Peer\n"
     "Bind a unix path or 'host:port'; the edge-peer dials in (supervisord model)."},
    {"connect", (PyCFunction)mod_connect, METH_VARARGS | METH_KEYWORDS,
     "connect(addr, token=None, id=None, weight=1, ...) -> Peer\n"
     "Dial the edge-peer at a 'host:port' or unix path."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef muxpeermodule = {
    PyModuleDef_HEAD_INIT, "muxpeer",
    "Worker SDK: terminate mux streams as socket-like conns over one fd.",
    -1, module_methods, NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC PyInit_muxpeer(void) {
    if (PyType_Ready(&StreamType) < 0) return NULL;
    if (PyType_Ready(&PeerType) < 0) return NULL;
    PyObject *m = PyModule_Create(&muxpeermodule);
    if (!m) return NULL;
    Py_INCREF(&StreamType); Py_INCREF(&PeerType);
    PyModule_AddObject(m, "Stream", (PyObject *)&StreamType);
    PyModule_AddObject(m, "Peer", (PyObject *)&PeerType);
    PyModule_AddIntConstant(m, "ACCEPT",   LP_ACCEPT);
    PyModule_AddIntConstant(m, "READABLE", LP_READABLE);
    PyModule_AddIntConstant(m, "WRITABLE", LP_WRITABLE);
    PyModule_AddIntConstant(m, "CLOSED",   LP_CLOSED);
    return m;
}
