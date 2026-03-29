import sys
import os
import argparse
import r2pipe
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
from capstone.x86 import X86_OP_IMM
import json

def get_pe_entry_point(r2):
    info = r2.cmdj('ij')
    entry = info.get('bin', {}).get('entry0')
    if entry:
        print(f"[+] PE Header Entry Point: 0x{entry:x}")
        return entry
    print("[!] No PE header entry point found")
    return None

def get_symbol_entry_points(r2):
    entry_points = set()
    exports = r2.cmdj('iEj') or []
    for exp in exports:
        if exp.get('vaddr'):
            entry_points.add(exp['vaddr'])
    print(f"[+] Found {len(entry_points)} exported entry points")
    return entry_points

def get_common_start_functions(r2):
    entry_points = set()
    syms = r2.cmdj('isj') or []
    for s in syms:
        name = s.get('name', '').lower()
        vaddr = s.get('vaddr', 0)
        if any(n in name for n in ["main", "winmain", "start", "entry", "crt"]):
            entry_points.add(vaddr)
    print(f"[+] Heuristic common start functions: {len(entry_points)}")
    return entry_points

def get_functions(r2):
    funcs = r2.cmdj('aflj') or []
    print(f"[+] Functions found by analysis: {len(funcs)}")
    return funcs

SUSPICIOUS_STRINGS_PATTERNS = [
    "debug", "vm", "virtual", "sandbox", "malware", "virus",
    "http", "ftp", "download", "upload", "shell", "cmd",
    "registry", "service", "process", "thread", "inject",
]

def extract_suspicious_strings(r2):
    strings = r2.cmdj("izj") or []
    suspicious = []
    for s in strings:
        val = s.get('string', '').lower()
        if any(pat in val for pat in SUSPICIOUS_STRINGS_PATTERNS):
            suspicious.append({"address": hex(s.get('vaddr',0)), "string": s.get('string','')})
    return suspicious


def disassemble_func(r2, func, arch_bits, import_map):
    MAX_INSTRUCTIONS = 100
    count = 0
    code_size = func.get('size')
    code_addr = func.get('offset', func.get('addr'))
    if not code_addr or code_size is None:
        return []

    # Read raw bytes hex from radare2
    code_hex = r2.cmd(f"p8 {code_size} @ {code_addr}").strip()
    if not code_hex:
        return []

    md = Cs(CS_ARCH_X86, CS_MODE_64 if arch_bits == 64 else CS_MODE_32)
    md.detail = True
    instructions = []

    try:
        bytes_code = bytes.fromhex(code_hex)
    except Exception as e:
        print(f"[!] Failed to convert hex to bytes at 0x{code_addr:x}: {e}")
        return []

    for ins in md.disasm(bytes_code, code_addr):
        api_name = None
        # Attempt to resolve call indirect target if possible
        if ins.mnemonic == 'call' and ins.operands:
            op = ins.operands[0]
            if op.type == X86_OP_IMM:
                target_addr = op.imm
                api_name = import_map.get(target_addr)
            elif op.type == 1:  # Memory operand, sometimes used for IAT calls
                pass

        op_str = ins.op_str
        if api_name:
            op_str = f"{op_str} ; API: {api_name}"

        instructions.append({
            'address': f"0x{ins.address:x}",
            'mnemonic': ins.mnemonic,
            'op_str': op_str,
            'api_name': api_name
        })
        count += 1
        if count >= MAX_INSTRUCTIONS:
            break
    return instructions


suspicious_mnemonics_set = {
    "xor", "rol", "ror", "shl", "shr", "sar", "bswap", "pxor",
    "call", "jmp", "ret", "int3", "sysenter", "syscall", "int", "iret",
    "rdtsc", "cpuid", "in", "out", "pushfd", "popfd",
    "rep", "movs", "stos", "scas", "cmps",
    "mov", "push", "pop"
}

def score_function(instructions):
    score = 0
    api_calls = []

    high_value_api_patterns = [
    "CreateToolhelp32Snapshot","EnumDeviceDrivers","EnumProcesses","EnumProcessModules",
    "EnumProcessModulesEx","FindFirstFileA","FindNextFileA","GetLogicalProcessorInformation",
    "GetLogicalProcessorInformationEx","GetModuleBaseNameA","GetSystemDefaultLangId",
    "GetVersionExA","GetWindowsDirectoryA","IsWoW64Process","Module32First","Module32Next",
    "Process32First","Process32Next","ReadProcessMemory","Thread32First","Thread32Next",
    "GetSystemDirectoryA","GetSystemTime","ReadFile","GetComputerNameA","VirtualQueryEx",
    "GetProcessIdOfThread","GetProcessId","GetCurrentThread","GetCurrentThreadId","GetThreadId",
    "GetThreadInformation","GetCurrentProcess","GetCurrentProcessId","SearchPathA","GetFileTime",
    "GetFileAttributesA","LookupPrivilegeValueA","LookupAccountNameA","GetCurrentHwProfileA",
    "GetUserNameA","RegEnumKeyExA","RegEnumValueA","RegQueryInfoKeyA","RegQueryMultipleValuesA",
    "RegQueryValueExA","NtQueryDirectoryFile","NtQueryInformationProcess","NtQuerySystemEnvironmentValueEx",
    "EnumDesktopWindows","EnumWindows","NetShareEnum","NetShareGetInfo","NetShareCheck","GetAdaptersInfo",
    "PathFileExistsA","GetNativeSystemInfo","RtlGetVersion","GetIpNetTable","GetLogicalDrives",
    "GetDriveTypeA","RegEnumKeyA","WNetEnumResourceA","WNetCloseEnum","FindFirstUrlCacheEntryA",
    "FindNextUrlCacheEntryA","WNetAddConnection2A","WNetAddConnectionA","EnumResourceTypesA",
    "EnumResourceTypesExA","GetSystemTimeAsFileTime","GetThreadLocale","EnumSystemLocalesA",
    "CreateFileMappingA","CreateProcessA","CreateRemoteThread","CreateRemoteThreadEx",
    "GetModuleHandleA","GetProcAddress","GetThreadContext","HeapCreate","LoadLibraryA",
    "LoadLibraryExA","LocalAlloc","MapViewOfFile","MapViewOfFile2","MapViewOfFile3","MapViewOfFileEx",
    "OpenThread","Process32First","Process32Next","QueueUserAPC","ReadProcessMemory","ResumeThread",
    "SetProcessDEPPolicy","SetThreadContext","SuspendThread","Thread32First","Thread32Next",
    "Toolhelp32ReadProcessMemory","VirtualAlloc","VirtualAllocEx","VirtualProtect","VirtualProtectEx",
    "WriteProcessMemory","VirtualAllocExNuma","VirtualAlloc2","VirtualAlloc2FromApp","VirtualAllocFromApp",
    "VirtualProtectFromApp","CreateThread","WaitForSingleObject","OpenProcess","OpenFileMappingA","GetProcessHeap",
    "GetProcessHeaps","HeapAlloc","HeapReAlloc","GlobalAlloc","AdjustTokenPrivileges","CreateProcessAsUserA",
    "OpenProcessToken","CreateProcessWithTokenW","NtAdjustPrivilegesToken","NtAllocateVirtualMemory","NtContinue",
    "NtCreateProcess","NtCreateProcessEx","NtCreateSection","NtCreateThread","NtCreateThreadEx","NtCreateUserProcess",
    "NtDuplicateObject","NtMapViewOfSection","NtOpenProcess","NtOpenThread","NtProtectVirtualMemory","NtQueueApcThread",
    "NtQueueApcThreadEx","NtQueueApcThreadEx2","NtReadVirtualMemory","NtResumeThread","NtUnmapViewOfSection",
    "NtWaitForMultipleObjects","NtWaitForSingleObject","NtWriteVirtualMemory","RtlCreateHeap","LdrLoadDll",
    "RtlMoveMemory","RtlCopyMemory","SetPropA","WaitForSingleObjectEx","WaitForMultipleObjects","WaitForMultipleObjectsEx",
    "KeInsertQueueApc","Wow64SetThreadContext","NtSuspendProcess","NtResumeProcess","DuplicateToken",
    "NtReadVirtualMemoryEx","CreateProcessInternal","EnumSystemLocalesA","UuidFromStringA","DebugActiveProcessStop",
    "CreateFileMappingA","DeleteFileA","GetModuleHandleA","GetProcAddress","LoadLibraryA","LoadLibraryExA","LoadResource",
    "SetEnvironmentVariableA","SetFileTime","Sleep","WaitForSingleObject","SetFileAttributesA","SleepEx","NtDelayExecution",
    "NtWaitForMultipleObjects","NtWaitForSingleObject","CreateWindowExA","RegisterHotKey","timeSetEvent","IcmpSendEcho",
    "WaitForSingleObjectEx","WaitForMultipleObjects","WaitForMultipleObjectsEx","SetWaitableTimer","CreateTimerQueueTimer",
    "CreateWaitableTimer","SetWaitableTimer","SetTimer","Select","ImpersonateLoggedOnUser","SetThreadToken","DuplicateToken",
    "SizeOfResource","LockResource","CreateProcessInternal","TimeGetTime","EnumSystemLocalesA","UuidFromStringA",
    "CryptProtectData","AttachThreadInput","CallNextHookEx","GetAsyncKeyState","GetClipboardData","GetDC","GetDCEx",
    "GetForegroundWindow","GetKeyboardState","GetKeyState","GetMessageA","GetRawInputData","GetWindowDC","MapVirtualKeyA",
    "MapVirtualKeyExA","PeekMessageA","PostMessageA","PostThreadMessageA","RegisterHotKey","RegisterRawInputDevices",
    "SendMessageA","SendMessageCallbackA","SendMessageTimeoutA","SendNotifyMessageA","SetWindowsHookExA","SetWinEventHook",
    "UnhookWindowsHookEx","BitBlt","StretchBlt","GetKeynameTextA","WinExec","FtpPutFileA","HttpOpenRequestA",
    "HttpSendRequestA","HttpSendRequestExA","InternetCloseHandle","InternetOpenA","InternetOpenUrlA","InternetReadFile",
    "InternetReadFileExA","InternetWriteFile","URLDownloadToFile","URLDownloadToCacheFile","URLOpenBlockingStream",
    "URLOpenStream","Accept","Bind","Connect","Gethostbyname","Inet_addr","Recv","Send","WSAStartup","Gethostname",
    "Socket","WSACleanup","Listen","ShellExecuteA","ShellExecuteExA","DnsQuery_A","DnsQueryEx","WNetOpenEnumA","FindFirstUrlCacheEntryA",
    "FindNextUrlCacheEntryA","InternetConnectA","InternetSetOptionA","WSASocketA","Closesocket","WSAIoctl","ioctlsocket",
    "HttpAddRequestHeaders","CreateToolhelp32Snapshot","GetLogicalProcessorInformation","GetLogicalProcessorInformationEx",
    "GetTickCount","OutputDebugStringA","CheckRemoteDebuggerPresent","Sleep","GetSystemTime","GetComputerNameA","SleepEx",
    "IsDebuggerPresent","GetUserNameA","NtQueryInformationProcess","ExitWindowsEx","FindWindowA","FindWindowExA","GetForegroundWindow",
    "GetTickCount64","QueryPerformanceFrequency","QueryPerformanceCounter","GetNativeSystemInfo","RtlGetVersion",
    "GetSystemTimeAsFileTime","CountClipboardFormats","CryptAcquireContextA","EncryptFileA","CryptEncrypt","CryptDecrypt",
    "CryptCreateHash","CryptHashData","CryptDeriveKey","CryptSetKeyParam","CryptGetHashParam","CryptSetKeyParam",
    "CryptDestroyKey","CryptGenRandom","DecryptFileA","FlushEfsCache","GetLogicalDrives","GetDriveTypeA","CryptStringToBinary",
    "CryptBinaryToString","CryptReleaseContext","CryptDestroyHash","EnumSystemLocalesA","CryptProtectData","ConnectNamedPipe",
    "CopyFileA","CreateFileA","CreateMutexA","CreateMutexExA","DeviceIoControl","FindResourceA","FindResourceExA",
    "GetModuleBaseNameA","GetModuleFileNameA","GetModuleFileNameExA","GetTempPathA","IsWoW64Process","MoveFileA","MoveFileExA",
    "PeekNamedPipe","WriteFile","TerminateThread","CopyFile2","CopyFileExA","CreateFile2","GetTempFileNameA","TerminateProcess",
    "SetCurrentDirectory","FindClose","SetThreadPriority","UnmapViewOfFile","ControlService","ControlServiceExA","CreateServiceA",
    "DeleteService","OpenSCManagerA","OpenServiceA","RegOpenKeyA","RegOpenKeyExA","StartServiceA","StartServiceCtrlDispatcherA",
    "RegCreateKeyExA","RegCreateKeyA","RegSetValueExA","RegSetKeyValueA","RegDeleteValueA","RegOpenKeyExA","RegEnumKeyExA","RegEnumValueA",
    "RegGetValueA","RegFlushKey","RegGetKeySecurity","RegLoadKeyA","RegLoadMUIStringA","RegOpenCurrentUser","RegOpenKeyTransactedA",
    "RegOpenUserClassesRoot","RegOverridePredefKey","RegReplaceKeyA","RegRestoreKeyA","RegSaveKeyA","RegSaveKeyExA","RegSetKeySecurity",
    "RegUnLoadKeyA","RegConnectRegistryA","RegCopyTreeA","RegCreateKeyTransactedA","RegDeleteKeyA","RegDeleteKeyExA",
    "RegDeleteKeyTransactedA","RegDeleteKeyValueA","RegDeleteTreeA","RegDeleteValueA","RegCloseKey","NtClose","NtCreateFile",
    "NtDeleteKey","NtDeleteValueKey","NtMakeTemporaryObject","NtSetContextThread","NtSetInformationProcess","NtSetInformationThread",
    "NtSetSystemEnvironmentValueEx","NtSetValueKey","NtShutdownSystem","NtTerminateProcess","NtTerminateThread","RtlSetProcessIsCritical",
    "DrawTextExA","GetDesktopWindow","SetClipboardData","SetWindowLongA","SetWindowLongPtrA","OpenClipboard","SetForegroundWindow",
    "BringWindowToTop","SetFocus","ShowWindow","NetShareSetInfo","NetShareAdd","NtQueryTimer","GetIpNetTable","GetLogicalDrives",
    "GetDriveTypeA","CreatePipe","RegEnumKeyA","WNetOpenEnumA","WNetEnumResourceA","WNetAddConnection2A","CallWindowProcA",
    "NtResumeProcess","lstrcatA","ImpersonateLoggedOnUser","SetThreadToken","SizeOfResource","LockResource","UuidFromStringA"
    ]

    for ins in instructions:
        mnem = ins['mnemonic'].lower()
        op_str = ins['op_str']

        if mnem in suspicious_mnemonics_set:
            score += 2
        if any(api.lower() in op_str.lower() for api in high_value_api_patterns):
            api_calls.append(op_str)
            score += 20
        if len(instructions) > 0:
            score = score / len(instructions)
    return score, list(set(api_calls))

def analyze_function(func, instructions):
    score, api_calls = score_function(instructions)
    critical_threshold = 0.03  # Adjust threshold for critical suspiciousness/ keeping it 0.03 for test
    critical = (score >= critical_threshold)
    suspicious_instructions = []

    resolved_api_calls = set(api_calls)

    for ins in instructions:
        if ins['mnemonic'].lower() in suspicious_mnemonics_set:
            suspicious_instructions.append(f"{ins['address']}: {ins['mnemonic']} {ins['op_str']}")
        api_name = ins.get('api_name')
        if api_name:
            resolved_api_calls.add(api_name)

    return {
        'function_name': func.get('name', 'unknown'),
        'address': f"0x{func.get('offset', func.get('addr', 0)):x}",
        'size': func.get('size', 0),
        'score': score,
        'api_calls': list(resolved_api_calls),
        'critical': critical,
        'suspicious_instructions': suspicious_instructions,
        'disassembly': [f"{ins['address']}: {ins['mnemonic']} {ins['op_str']}" for ins in instructions]
    }


def summarize_instructions(instr_list):
    if not instr_list:
        return []
    summarized = []
    prev_instr = instr_list[0]
    count = 1

    for current_instr in instr_list[1:]:
        if current_instr.split()[1] == prev_instr.split()[1]:
            count += 1
        else:
            if count > 1:
                summarized.append(f"{count}x {prev_isntr}")
            else:
                summarized.append(prev_instr)
            prev_instr = current_instr
            count = 1

    if count > 1:
        summarized.append(f"{count}x {prev_instr}")
    else:
        summarized.append(prev_instr)

    return summarized



def main():
    parser = argparse.ArgumentParser(description="Suspicious Functions and Disassembly Summary Generator")
    parser.add_argument("binary", help="Path to binary")
    parser.add_argument("--output", default="disassembly_summary.txt", help="Output summary text file")
    args = parser.parse_args()

    if not os.path.exists(args.binary):
        print(f"[-] File not found: {args.binary}")
        sys.exit(1)

    r2 = r2pipe.open(args.binary, flags=["-2"])
    r2.cmd("aaa")

    import_map = {}
    imports = r2.cmdj("iij") or []
    for imp in imports:
        addr = imp.get("plt") or imp.get("reloc") or imp.get("vaddr") or 0
        name = imp.get("name")
        if addr and name:
            import_map[addr] = name
    print(f"[+] Extracted {len(import_map)} imports")

    suspicious_strings = extract_suspicious_strings(r2)
    print(f"[+] Suspicious strings extracted: {len(suspicious_strings)}")

    info = r2.cmdj('ij')
    arch_bits = info.get('bin', {}).get('bits', 64)

    entry_points = set()
    ep_pe = get_pe_entry_point(r2)
    if ep_pe:
        entry_points.add(ep_pe)
    entry_points |= get_symbol_entry_points(r2)
    entry_points |= get_common_start_functions(r2)

    funcs = get_functions(r2)
    func_map = {}
    for f in funcs:
        vaddr = f.get('offset') or f.get('addr')
        if vaddr is not None:
            func_map[vaddr] = f

    # Analyze entry points first (likely critical functions)
    analyzed_addrs = set()
    all_analysis = []

    for addr in sorted(entry_points):
        if addr in func_map:
            func = func_map[addr]
            instructions = disassemble_func(r2, func, arch_bits, import_map)
            analysis = analyze_function(func, instructions)
            all_analysis.append(analysis)
            analyzed_addrs.add(addr)
        else:
            print(f"[!] Entry point 0x{addr:x} not found among functions")

    # Analyzing all other functions while avoiding duplicates
    for addr, func in func_map.items():
        if addr not in analyzed_addrs:
            instructions = disassemble_func(r2, func, arch_bits, import_map)
            analysis = analyze_function(func, instructions)
            all_analysis.append(analysis)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(f"Binary analyzed: {args.binary}\nArchitecture: x{arch_bits}\n\n")

        f.write(f"Imports ({len(import_map)}):\n")
        for addr, name in sorted(import_map.items()):
            f.write(f"  0x{addr:x}: {name}\n")
        f.write("\n")

        f.write(f"Suspicious strings ({len(suspicious_strings)}):\n")
        for s in suspicious_strings:
            f.write(f"  {s['address']}: {s['string']}\n")
        f.write("\n")

        f.write(f"Total functions analyzed: {len(all_analysis)}\n\n")

        for res in all_analysis:
            if not res['critical']:
                continue
            f.write(f"Function: {res['function_name']} at {res['address']} (size: {res['size']})\n")
            f.write(f"Suspicious Score: {res['score']}\n")
            f.write("API Calls:\n")
            for call in res['api_calls']:
                f.write(f"  {call}\n")
            f.write("Suspicious Instructions:\n")
            for sinstr in res['suspicious_instructions']:
                f.write(f"  {sinstr}\n")
            f.write("Disassembly:\n")
            for line in res['disassembly']:
                f.write(f"  {line}\n")
            f.write("\n" + "-"*80 + "\n\n")

    r2.quit()
    print(f"[+] Analysis complete. Detailed summary saved to {args.output}")

if __name__ == "__main__":
    main()

