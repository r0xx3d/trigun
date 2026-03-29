import pefile
import struct
import sys

try:
    pe = pefile.PE(sys.argv[1])
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORTS'):
        print("Exported Functions:")
        for exp in pe.DIRECTORY_ENTRY_EXPORTS.symbols:
            if exp.name:
                print(f" Name: {exp.name.decode('utf-8')}, Ordinal: {exp.ordinal}, Address: 0x{exp.address:X}")
            else:
                print(f" Ordinal: {exp.ordinal}, Address: 0x{exp.address:X}")
    else:
        print("No exports found in this PE file...")
except pefile.PEFormatError as e:
    print(f"Error parsing PE file: {e}")
finally:
    if 'pe' in locals() and pe:
        pe.close()


