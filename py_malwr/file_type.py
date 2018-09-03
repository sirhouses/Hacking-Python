#!/usr/bin/env python
# -*- coding: utf-8 -*-

import magic
import sys

if len(sys.argv) !=2 :
    print "python file_type.py <nombre binario>"
    exit()

file = sys.argv[1]

m = magic.open(magic.MAGIC_NONE)
m.load()

ftype = m.fyle(file)
print ftype