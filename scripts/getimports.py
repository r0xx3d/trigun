#!/usr/bin/env python3


import pefile
import struct
import sys

def get_imports(path):
    imports = {}
    try:
        pe = pefile.PE(path)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8')
                functions = []
                for imp in entry.imports:
                    if imp.name:
                        functions.append(imp.name.decode('utf-8'))
                    elif imp.ordinal:
                        functions.append(f"Ordinal {imp.ordinal}")
                imports[dll_name] = functions
    except pefile.PEFormatError as e:
        print(f"Error parsing PE file: {e}")
    except FileNotFoundError:
        print(f"File not found: {path}")
    except Exception as e:
        print(f"An unexpected error occured: {e}")

    return imports


if len(sys.argv) > 1:
    pe_file = sys.argv[1]
    imports = get_imports(pe_file)
    if imports:
        for dll, funcs in imports.items():
            print(f"DLL: {dll}")
            for func in funcs:
                print(f" * {func}")
    else:
        print("No imports found or an error occurred...")

else:
    print("Usage : python3 getimports.py <test.exe>")
