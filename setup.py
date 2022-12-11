from setuptools import setup, Extension


setup(
    ext_modules = [
        Extension(
            name = "n3map.nsec3hash",
            sources = ["n3map/nsec3hash.c"],
            libraries = ["crypto"],
            extra_compile_args = ["-O3"],
            ),
        ],
)
