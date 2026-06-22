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
} StreamObj;

static PyTypeObject StreamType;

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

static PyObject *Stream_close(StreamObj *self, PyObject *Py_UNUSED(ignored)) {
    if (self->s) { lp_close(self->s); self->s = NULL; }
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
    if (self->s) { lp_close(self->s); self->s = NULL; }
    Py_RETURN_FALSE;
}

static void Stream_dealloc(StreamObj *self) {
    if (self->s) { lp_close(self->s); self->s = NULL; }
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyMethodDef Stream_methods[] = {
    {"recv", (PyCFunction)Stream_recv, METH_VARARGS, "recv(n=65536) -> bytes; b'' on EOF"},
    {"sendall", (PyCFunction)Stream_sendall, METH_VARARGS, "sendall(data) -> None"},
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
    /* keep owned copies of the config strings alive */
    char *s_listen, *s_host, *s_token, *s_id;
} PeerObj;

static PyTypeObject PeerType;

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
    o->s = s;
    return (PyObject *)o;
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
    free(self->s_listen); free(self->s_host); free(self->s_token); free(self->s_id);
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyMethodDef Peer_methods[] = {
    {"accept", (PyCFunction)Peer_accept, METH_NOARGS, "accept() -> Stream or None (blocking)"},
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
    return m;
}
