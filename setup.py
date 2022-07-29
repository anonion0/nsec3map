from setuptools import setup, find_packages, Extension
import pathlib

wd = pathlib.Path(__file__).parent.resolve()

long_desc = ( wd / "README.md").read_text(encoding="utf-8")

# https://packaging.python.org/en/latest/guides/distributing-packages-using-setuptools/
setup(
        name = "n3map",
        description = "Enumerate DNS zones based on DNSSEC records",
        long_description = long_desc,
        long_description_content_type = "text/markdown",
        url = "https://github.com/anonion0/nsec3map",
        author = "Ralf Sager",
        author_email = "nsec3map(at)3fnc.org",
        packages = find_packages(),
        ext_modules = [
            Extension(
                name = "n3map.nsec3hash",
                sources = ["n3map/nsec3hash.c"],
                libraries = ["crypto"],
                extra_compile_args = ["-O3"],
                ),
            ],
        entry_points = {
            'console_scripts': [
                    'n3map=n3map.map:main',
                    'johnify=n3map.johnify:main',
                    'hashcatify=n3map.hashcatify:main',
                    'nsec3-lookup=n3map.nsec3lookup:main',
                ],

            },
        python_requires = ">=3.9",
        install_requires = [
            "dnspython",
            ],
        extras_require = {
            'prediction' : [
                "numpy",
                "scipy",
                ],
            },
        data_files = [
            ('share/man/man1', [
                'doc/n3map.1',
                'doc/n3map-nsec3-lookup.1',
                'doc/n3map-johnify.1',
                'doc/n3map-hashcatify.1',
                ]
            ),
        ],
        license='GPLv3',
        keywords = 'security network cryptography dns dnssec nsec nsec3 scanner',
        classifiers = [
            "Development Status :: 5 - Production/Stable",
            "Environment :: Console",
            "Intended Audience :: Developers",
            "Intended Audience :: Information Technology",
            "Intended Audience :: Science/Research",
            "Intended Audience :: System Administrators",
            "Intended Audience :: Telecommunications Industry",
            "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
            "Operating System :: POSIX",
            "Programming Language :: C",
            "Programming Language :: Python :: 3",
            "Topic :: Security",
            "Topic :: Security :: Cryptography",
            "Topic :: System :: Networking",
            "Topic :: Internet :: Name Service (DNS)",
            "Topic :: Internet",
            ],
    )
