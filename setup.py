"""Build the muxpeer C extension at install time.

Project metadata lives in pyproject.toml; this file only declares the compiled
Extension (setuptools can't express that in pyproject). The extension links
libpeer + the libmux core + common helpers straight in — no separate install of
the C libraries needed — so `pip install git+https://github.com/.../mux-protocol`
compiles a `muxpeer` module against whatever Python is running.
"""
from setuptools import Extension, setup

# Paths are RELATIVE to this setup.py (the project root) — setuptools rejects
# absolute paths in `sources`, and relative paths also work in an sdist build.
muxpeer = Extension(
    "muxpeer",
    sources=[
        "python/muxpeermodule.c",
        "libpeer/src/libpeer.c",
        "libmux/src/frame.c",
        "libmux/src/session.c",
        "common/auth.c",
        "common/net.c",
    ],
    include_dirs=[
        "libpeer/include",
        "libmux/include",
        "common",
    ],
    # gnu11 + _GNU_SOURCE: the non-Python TUs (net.c, libpeer.c, ...) need POSIX
    # symbols that glibc gates behind feature macros under strict c11.
    extra_compile_args=["-O2", "-std=gnu11", "-D_GNU_SOURCE", "-Wall"],
)

setup(ext_modules=[muxpeer])
