#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pefile
import sys

mal_file = sys.argv[1]

pe = pefile.PE(mal_file)
if hasattr(pe, 'DIRECTOR_ENTRY_IMPORT'):
	for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
		print "%s" % exp.name