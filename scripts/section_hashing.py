#!/bin/python

import sys
import pefile
pe_file = sys.argv[1]
pe = pefile.PE(pe_file)
for section in pe.sections:
    print(section.Name[0:6], "MD5 hash    :", section.get_hash_md5())
    print(section.Name[0:6], "SHA256 hash :", section.get_hash_sha256())
