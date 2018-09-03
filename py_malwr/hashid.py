#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
import sys

if len(sys.argv) !=2 :
    print "python id.py <nombre binario>"
    exit()

file = sys.argv[1]

content = open(file, "rb").read()
print "md5: " + hashlib.md5(content).hexdigest()
print "sha256: " + hashlib.sha256(content).hexdigest()
print "sha1: " + hashlib.sha1(content).hexdigest()