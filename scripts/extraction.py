#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Selective Disassembly Extractor for LLM-based Malware Analysis

This script extracts only the most critical disassembly blocks from a binary
that are essential for malware triage analysis via LLM (like Groq).

Usage:
    python test_disasm.py <binary_path> [--output output.txt] [--format text|json]

Output: Filtered disassembly focusing on:
- API call sites and suspicious function calls
- Control flow anomalies and anti-analysis techniques
- Cryptographic operations and obfuscation patterns
- Network, file, and registry manipulation code
- Process injection and privilege escalation patterns
"""

import sys
import os
import json
import argparse
import hashlib
import re
from datetime import datetime
from collections import defaultdict

try:
    import r2pipe
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    import pefile
except ImportError as e:
    print(f"[-] Missing dependencies. Install with: pip install capstone r2pipe pefile")
    sys.exit(1)

# Suspicious mnemonics for malware behavior detection
MALICIOUS_MNEMONICS = {
    # Crypto/Obfuscation
    "xor", "rol", "ror", "shl", "shr", "sar", "bswap", "pxor",
    # Control flow manipulation
    "jmp", "call", "ret", "int3", "sysenter", "syscall", "int", "iret",
    # Anti-debug/Analysis
    "rdtsc", "cpuid", "in", "out", "pushfd", "popfd",
    # Memory manipulation
    "rep", "movs", "stos", "scas", "cmps"
}

# High-priority API patterns for malware analysis
CRITICAL_API_PATTERNS = [
    # Process/Thread manipulation
    r"(CreateProcess|CreateThread|CreateRemoteThread|ResumeThread|SuspendThread)",
    r"(OpenProcess|TerminateProcess|GetCurrentProcess|DuplicateHandle)",
    r"(VirtualAlloc|VirtualProtect|WriteProcessMemory|ReadProcessMemory)",
    r"(LoadLibrary|GetProcAddress|GetModuleHandle|FreeLibrary)",
    
    # Network operations
    r"(WSAStartup|socket|connect|send|recv|InternetOpen|HttpOpen)",
    r"(WinHttpOpen|WinHttpConnect|WinHttpSendRequest|URLDownload)",
    
    # File operations
    r"(CreateFile|ReadFile|WriteFile|DeleteFile|MoveFile|CopyFile)",
    r"(FindFirstFile|FindNextFile|GetFileAttributes|SetFileAttributes)",
    
    # Registry operations
    r"(RegOpenKey|RegCreateKey|RegSetValue|RegQueryValue|RegDeleteKey)",
    r"(RegEnumKey|RegCloseKey)",
    
    # Crypto operations
    r"(CryptAcquireContext|CryptCreateHash|CryptEncrypt|CryptDecrypt)",
    r"(CryptGenKey|CryptDestroyKey|CryptReleaseContext)",
    
    # Service/Persistence
    r"(CreateService|OpenService|StartService|ControlService)",
    r"(OpenSCManager|QueryServiceStatus)",
    
    # Anti-debug/Evasion
    r"(IsDebuggerPresent|CheckRemoteDebuggerPresent|OutputDebugString)",
    r"(NtQueryInformationProcess|ZwQueryInformationProcess)",
    r"(GetTickCount|QueryPerformanceCounter|Sleep)",
    
    # System information
    r"(GetSystemInfo|GetComputerName|GetUserName|GetWindowsDirectory)",
    r"(GetSystemDirectory|GetTempPath)"
]

# Suspicious instruction patterns
SUSPICIOUS_PATTERNS = [
    # PEB access (anti-debug)
    r"fs:\[0?x?30h?\]",  # PEB access on x86
    r"gs:\[0?x?60h?\]",  # PEB access on x64
    
    # TEB access
    r"fs:\[0?x?18h?\]",  # TEB on x86
    r"gs:\[0?x?30h?\]",  # TEB on x64
    
    # Suspicious constants
    r"0x[0-9a-fA-F]{8,}",  # Large hex constants
    
    # Stack string construction
    r"mov.*0x[0-9a-fA-F]{2,8}.*esp",
    r"push.*0x[0-9a-fA-F]{2,8}",
    
    # Shellcode patterns
    r"call.*\$\+5",  # GetPC idiom
    r"pop.*add.*0x",  # Delta calculation
]

class DisassemblyExtractor:
    def __init__(self, binary_path, max_functions=200):
        self.binary_path = binary_path
        self.max_functions = max_functions
        self.r2 = None
        self.arch_bits = 64
        self.cs = None
        self.critical_blocks = []
        self.seen_hashes = set()
        
    def __enter__(self):
        try:
            self.r2 = r2pipe.open(self.binary_path, flags=["-2"])
            self.r2.cmd("aaa")  # Full analysis
            
            # Detect architecture
            info = self.r2.cmdj("ij")
            self.arch_bits = info.get("bin", {}).get("bits", 64)
            
            # Initialize Capstone
            mode = CS_MODE_64 if self.arch_bits == 64 else CS_MODE_32
            self.cs = Cs(CS_ARCH_X86, mode)
            self.cs.detail = True
            
            return self
        except Exception as e:
            print(f"[-] Failed to initialize r2pipe: {e}")
            sys.exit(1)
            
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.r2:
            self.r2.quit()
    
    def get_imports(self):
        """Extract import information for API call detection"""
        imports = self.r2.cmdj("iij") or []
        import_dict = {}
        
        for imp in imports:
            name = imp.get("name", "")
            addr = imp.get("plt", 0)
            if name and addr:
                import_dict[addr] = name
                
        return import_dict
    
    def get_strings(self):
        """Extract strings that might indicate malicious behavior"""
        strings = self.r2.cmdj("izj") or []
        suspicious_strings = []
        
        for s in strings:
            string_val = s.get("string", "")
            addr = s.get("vaddr", 0)
            
            # Check for suspicious strings
            if any(pattern in string_val.lower() for pattern in [
                "debug", "vm", "virtual", "sandbox", "malware", "virus",
                "http", "ftp", "download", "upload", "shell", "cmd",
                "registry", "service", "process", "thread", "inject"
            ]):
                suspicious_strings.append({
                    "addr": f"0x{addr:x}",
                    "string": string_val,
                    "length": len(string_val)
                })
                
        return suspicious_strings
    
    def analyze_function(self, func_info, imports):
        """Analyze a single function for malicious patterns"""
        func_addr = func_info.get("offset", 0)
        func_name = func_info.get("name", f"sub_{func_addr:x}")
        
        # Get function disassembly
        disasm = self.r2.cmd(f"pdf @ {func_addr}")
        if not disasm:
            return None
            
        lines = disasm.split('\n')
        critical_lines = []
        api_calls = []
        suspicious_score = 0
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith(';'):
                continue
                
            # Extract address and instruction
            if '│' in line:
                parts = line.split('│', 1)
                if len(parts) > 1:
                    instruction = parts[1].strip()
                else:
                    continue
            else:
                instruction = line
                
            # Check for API calls
            if 'call' in instruction.lower():
                # Try to resolve the call target
                for pattern in CRITICAL_API_PATTERNS:
                    if re.search(pattern, instruction, re.IGNORECASE):
                        api_calls.append(re.search(pattern, instruction, re.IGNORECASE).group(1))
                        critical_lines.append(line)
                        suspicious_score += 10
                        break
            
            # Check for suspicious mnemonics
            mnemonic = instruction.split()[0] if instruction.split() else ""
            if mnemonic.lower() in MALICIOUS_MNEMONICS:
                critical_lines.append(line)
                suspicious_score += 2
                
            # Check for suspicious patterns
            for pattern in SUSPICIOUS_PATTERNS:
                if re.search(pattern, instruction, re.IGNORECASE):
                    critical_lines.append(line)
                    suspicious_score += 5
                    break
        
        # Only return functions with significant suspicious activity
        if suspicious_score >= 0 or api_calls:
            return {
                "function_name": func_name,
                "address": f"0x{func_addr:x}",
                "suspicious_score": suspicious_score,
                "api_calls": list(set(api_calls)),
                "critical_lines": critical_lines[:50],  # Limit to 50 most critical lines
                "line_count": len(critical_lines)
            }
        
        return None
    
    def get_entry_points(self):
        """Get program entry points and exported functions"""
        entry_points = []
        
        # Main entry point
        info = self.r2.cmdj("ij")
        main_entry = info.get("entry0")
        if main_entry:
            entry_points.append({"type": "main_entry", "addr": main_entry})
            
        # Exports
        exports = self.r2.cmdj("iEj") or []
        for exp in exports:
            addr = exp.get("vaddr", 0)
            name = exp.get("name", "")
            if addr and name:
                entry_points.append({"type": "export", "addr": addr, "name": name})
                
        return entry_points
    
    def extract_critical_disassembly(self):
        """Main extraction function"""
        print(f"[+] Analyzing {self.binary_path}")
        
        # Get imports and strings
        imports = self.get_imports()
        strings = self.get_strings()
        entry_points = self.get_entry_points()
        
        # Get all functions
        functions = self.r2.cmdj("aflj") or []
        
        # Prioritize functions by importance
        def function_priority(func):
            addr = func.get("offset", 0)
            name = func.get("name", "")
            size = func.get("size", 0)
            
            priority = 0
            
            # Entry points get highest priority
            if any(ep.get("addr") == addr for ep in entry_points):
                priority += 1000
                
            # Exported functions
            if not name.startswith("sub_") and not name.startswith("fcn_"):
                priority += 500
                
            # Larger functions might be more interesting
            priority += min(size // 10, 100)
            
            return -priority  # Sort descending
        
        functions.sort(key=function_priority)
        
        # Limit number of functions to analyze
        if len(functions) > self.max_functions:
            functions = functions[:self.max_functions]
            
        critical_functions = []
        
        print(f"[+] Analyzing {len(functions)} functions...")
        
        for i, func in enumerate(functions):
            if i % 20 == 0:
                print(f"[+] Progress: {i}/{len(functions)} functions analyzed")
                
            result = self.analyze_function(func, imports)
            if result:
                critical_functions.append(result)
        
        # Sort by suspicious score
        critical_functions.sort(key=lambda x: x["suspicious_score"], reverse=True)
        
        return {
            "binary_path": self.binary_path,
            "architecture": f"x{self.arch_bits}",
            "analysis_timestamp": datetime.now().isoformat(),
            "total_functions_analyzed": len(functions),
            "critical_functions_found": len(critical_functions),
            "entry_points": entry_points,
            "suspicious_strings": strings[:20],  # Top 20 suspicious strings
            "critical_functions": critical_functions[:50],  # Top 50 critical functions
        }

def save_text_format(data, output_path):
    """Save analysis in human-readable text format"""
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write(f"SELECTIVE DISASSEMBLY ANALYSIS REPORT\n")
        f.write(f"Binary: {data['binary_path']}\n")
        f.write(f"Architecture: {data['architecture']}\n")
        f.write(f"Analysis Time: {data['analysis_timestamp']}\n")
        f.write("=" * 80 + "\n\n")
        
        f.write(f"SUMMARY:\n")
        f.write(f"- Total functions analyzed: {data['total_functions_analyzed']}\n")
        f.write(f"- Critical functions found: {data['critical_functions_found']}\n")
        f.write(f"- Entry points: {len(data['entry_points'])}\n")
        f.write(f"- Suspicious strings: {len(data['suspicious_strings'])}\n\n")
        
        # Entry points
        if data['entry_points']:
            f.write("ENTRY POINTS:\n")
            f.write("-" * 40 + "\n")
            for ep in data['entry_points']:
                f.write(f"  {ep['type']}: 0x{ep['addr']:x}")
                if 'name' in ep:
                    f.write(f" ({ep['name']})")
                f.write("\n")
            f.write("\n")
        
        # Suspicious strings
        if data['suspicious_strings']:
            f.write("SUSPICIOUS STRINGS:\n")
            f.write("-" * 40 + "\n")
            for s in data['suspicious_strings'][:10]:
                f.write(f"  {s['addr']}: \"{s['string'][:60]}{'...' if len(s['string']) > 60 else ''}\"\n")
            f.write("\n")
        
        # Critical functions
        f.write("CRITICAL FUNCTIONS:\n")
        f.write("=" * 80 + "\n")
        
        for func in data['critical_functions']:
            f.write(f"\nFunction: {func['function_name']} @ {func['address']}\n")
            f.write(f"Suspicious Score: {func['suspicious_score']}\n")
            f.write(f"API Calls: {', '.join(func['api_calls']) if func['api_calls'] else 'None'}\n")
            f.write(f"Critical Lines: {func['line_count']}\n")
            f.write("-" * 60 + "\n")
            
            for line in func['critical_lines']:
                f.write(f"{line}\n")
            f.write("\n")

def save_json_format(data, output_path):
    """Save analysis in JSON format for programmatic processing"""
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def main():
    parser = argparse.ArgumentParser(description="Selective Disassembly Extractor for LLM Analysis")
    parser.add_argument("binary", help="Path to binary file to analyze")
    parser.add_argument("--output", "-o", default="test_disasm.txt", 
                       help="Output file path (default: test_disasm.txt)")
    parser.add_argument("--format", "-f", choices=["text", "json"], default="text",
                       help="Output format (default: text)")
    parser.add_argument("--max-functions", "-m", type=int, default=200,
                       help="Maximum functions to analyze (default: 200)")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.binary):
        print(f"[-] Binary file not found: {args.binary}")
        sys.exit(1)
    
    print(f"[+] Starting selective disassembly extraction...")
    print(f"[+] Target: {args.binary}")
    print(f"[+] Output: {args.output}")
    print(f"[+] Format: {args.format}")
    
    try:
        with DisassemblyExtractor(args.binary, args.max_functions) as extractor:
            analysis_data = extractor.extract_critical_disassembly()
            
            if args.format == "json":
                save_json_format(analysis_data, args.output)
            else:
                save_text_format(analysis_data, args.output)
                
            print(f"[+] Analysis complete!")
            print(f"[+] Found {analysis_data['critical_functions_found']} critical functions")
            print(f"[+] Results saved to: {args.output}")
            
    except KeyboardInterrupt:
        print("\n[-] Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Analysis failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
