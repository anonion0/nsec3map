import n3map.version
import sys, os, shutil, gzip
from distutils.core import setup, Extension

shutil.copyfile("map.py", os.path.join("n3map", "n3map"))
shutil.copyfile("nsec3-lookup.py", os.path.join("n3map", "n3map-nsec3-lookup"))
shutil.copyfile("johnify.py", os.path.join("n3map", "n3map-johnify"))

for mp in ('doc/n3map.1', 'doc/n3map-johnify.1', 'doc/n3map-nsec3-lookup.1'):
    man_in = open(mp, 'rb')
    man_out = gzip.open(mp + '.gz', 'wb')
    man_out.writelines(man_in)
    man_out.close()
    man_in.close()

nsec3hashmod = Extension('n3map.nsec3hash',
                            sources = ['n3map/nsec3hash.c'],
                            libraries = ['ssl'],
                            extra_compile_args=['-O3'])

setup (name = 'n3map',
        version = n3map.version.version_str(),
        packages = ['n3map', 
                    'n3map.rrtypes',
                    'n3map.tree'],
        ext_modules = [nsec3hashmod],
        scripts = ['n3map/n3map', 'n3map/n3map-nsec3-lookup',
            'n3map/n3map-johnify'],
        data_files = [('/usr/local/share/man/man1/', ['doc/n3map.1.gz',
            'doc/n3map-nsec3-lookup.1.gz', 'doc/n3map-johnify.1.gz'])]
        )

print "cleaning..."

try:
    os.remove("n3map/n3map")
    os.remove("n3map/n3map-nsec3-lookup")
    os.remove("n3map/n3map-johnify")
    os.remove("doc/n3map.1.gz")
    os.remove("doc/n3map-johnify.1.gz")
    os.remove("doc/n3map-nsec3-lookup.1.gz")
except:
    pass
