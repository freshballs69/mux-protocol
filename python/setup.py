"""Build the muxpeer C extension.

    cd python && python3 setup.py build_ext --inplace

Compiles libpeer + the libmux core + common helpers straight into the module
(no separate install of the C libraries needed). Optimized, no sanitizers.
"""
from setuptools import setup, Extension
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

sources = [
    "muxpeermodule.c",
    os.path.join(ROOT, "libpeer/src/libpeer.c"),
    os.path.join(ROOT, "libmux/src/frame.c"),
    os.path.join(ROOT, "libmux/src/session.c"),
    os.path.join(ROOT, "common/auth.c"),
    os.path.join(ROOT, "common/net.c"),
]

ext = Extension(
    "muxpeer",
    sources=sources,
    include_dirs=[
        os.path.join(ROOT, "libpeer/include"),
        os.path.join(ROOT, "libmux/include"),
        os.path.join(ROOT, "common"),
    ],
    extra_compile_args=["-O2", "-std=c11", "-Wall"],
)

setup(
    name="muxpeer",
    version="0.1.0",
    description="Worker SDK for the mux protocol (libpeer binding)",
    ext_modules=[ext],
)
