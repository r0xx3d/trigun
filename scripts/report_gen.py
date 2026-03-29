import json
import time
import re
import os
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field

from groq import Groq


@dataclass
class TriageData:
    file_type: str = "Unknown"
    md5_hash: str = "Unknown"
    sha256_hash: str = "Unknown"
    imp_hash: str = ""
    fuzzy_hash: str = ""
    imports: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    entropy: float = 0.0
    section_entropy: Dict[str, float] = field(default_factory=dict)
    section_hashes: Dict[str, Dict[str, str]] = field(default_factory=dict)  # section -> {md5, sha256}
    packer_info: List[str] = field(default_factory=list)
    compiler_info: List[str] = field(default_factory=list)
    cryptors: List[str] = field(default_factory=list)
    malware_classification: str = "Unknown"
    classification_probs: List[float] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    disassembly: str = ""
    # Hybrid Analysis dynamic analysis fields
    dynamic_verdict: str = ""
    dynamic_threat_score: str = ""
    dynamic_threat_level: str = ""
    dynamic_av_detect: str = ""
    dynamic_vx_family: str = ""
    dynamic_submit_name: str = ""
    dynamic_analysis_time: str = ""
    dynamic_environment: str = ""
    dynamic_classification_tags: List[str] = field(default_factory=list)
    dynamic_mitre: List[str] = field(default_factory=list)
    dynamic_extracted_files: List[str] = field(default_factory=list)
    dynamic_processes: List[str] = field(default_factory=list)
    dynamic_signatures: List[str] = field(default_factory=list)
    dynamic_full_json: str = ""


class MultiPassGroqAnalyzer:
    def __init__(self, api_key: str, model: str = "openai/gpt-oss-120b", max_tokens: int = 4096, temperature: float = 0.2):
        self.client = Groq(api_key=api_key)
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature

    # ---------------------------
    # Static triage parsing
    # ---------------------------
    def preprocess_trigun(self, trigun_text: str) -> TriageData:
        triage = TriageData()
        lines = trigun_text.splitlines()
        # Flexible regexes
        file_type_re = re.compile(r"File[- ]?Type\s*[:\-]\s*(.+)", re.IGNORECASE)
        md5_re = re.compile(r"MD5(?: Hash)?\s*[:\-]\s*([a-fA-F0-9]{32})")
        sha256_re = re.compile(r"(?:SHA-256|SHA256)\s*(?:Hash)?\s*[:\-]\s*([a-fA-F0-9]{64})")
        imp_hash_re = re.compile(r"IMPHash\s*[:\-]?\s*([A-Za-z0-9]+)", re.IGNORECASE)
        fuzzy_re = re.compile(r"ssdeep[^\n]*\n.*\n.*?([0-9]+:[A-Za-z0-9/+]+=?:[A-Za-z0-9/+]+=?)", re.IGNORECASE | re.DOTALL)
        entropy_line_re = re.compile(r"Entropy\s*[:\-]?\s*([\d\.]+)")
        packer_re = re.compile(r"Detecting Packers based on|Detecting Packers|Packers?\s*[:\-]\s*(.+)", re.IGNORECASE)
        cryptors_re = re.compile(r"Cryptors Detected\.\.\.\s*|\[([^\]]+)\]", re.IGNORECASE)
        section_md5_re = re.compile(r"(?:b?['\"]?)(\.\w+\\?x?\d*['\"]?)\s*MD5 hash\s*:\s*([a-fA-F0-9]{32})")
        section_sha256_re = re.compile(r"(?:b?['\"]?)(\.\w+\\?x?\d*['\"]?)\s*SHA256 hash\s*:\s*([a-fA-F0-9]{64})")
        section_entropy_re = re.compile(r"^\s*([.\w]+)\s*$")  # fallback
        ip_re = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?!$)|$)){4}\b")
        url_re = re.compile(r"https?://[^\s,]+", re.IGNORECASE)
        email_re = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.IGNORECASE)
        sha256_line_re = re.compile(r"SHA-256 Hash\s*[:\-]\s*([A-Fa-f0-9]{64})")
        classification_re = re.compile(r"Potential malware class\s*[:\-]?\s*(.+)", re.IGNORECASE)
        class_probs_re = re.compile(r"Class probabilities\s*:\s*\[([^\]]+)\]", re.IGNORECASE)

        in_imports_block = False
        current_dll = None

        in_section_entropy = False
        last_section_name = None

        for i, line in enumerate(lines):
            if triage.file_type == "Unknown":
                m = file_type_re.search(line)
                if m:
                    triage.file_type = m.group(1).strip()

            if triage.md5_hash == "Unknown":
                m = md5_re.search(line)
                if m:
                    triage.md5_hash = m.group(1).strip()

            if triage.sha256_hash == "Unknown":
                m = sha256_re.search(line)
                if m:
                    triage.sha256_hash = m.group(1).strip()

            if not triage.imp_hash:
                m = imp_hash_re.search(line)
                if m:
                    triage.imp_hash = m.group(1).strip()

            if not triage.fuzzy_hash:
                m = re.search(r"ssdeep,1\.1[^\n]*\n([0-9:\/+A-Za-z=]+)", "\n".join(lines[i:i+4]), re.IGNORECASE)
                if m:
                    triage.fuzzy_hash = m.group(1).strip()

            m = entropy_line_re.search(line)
            if m:
                try:
                    val = float(m.group(1))
                    # If global not set (==0.0) set; else it's section entropy possibly but we'll capture later
                    if triage.entropy == 0.0:
                        triage.entropy = val
                except Exception:
                    pass

            if "Section-wise entropy" in line or "Section-wise entropy:" in line or "Section-wise entropy" in (line.strip()):
                in_section_entropy = True
                last_section_name = None
                continue

            if in_section_entropy:
                sec_name_m = re.match(r"^\s*([.\w]+)\s*$", line)
                if sec_name_m:
                    last_section_name = sec_name_m.group(1).strip()
                    continue
                ent_m = re.search(r"entropy\s*:\s*([\d\.]+)", line, re.IGNORECASE)
                if ent_m and last_section_name:
                    try:
                        triage.section_entropy[last_section_name] = float(ent_m.group(1))
                    except Exception:
                        pass
                if line.strip() == "":
                    in_section_entropy = False
                    last_section_name = None

            # Section hashing (MD5/SHA256)
            m_md5 = re.search(r"(\.\w+).*MD5 hash\s*:\s*([A-Fa-f0-9]{32})", line)
            m_sha = re.search(r"(\.\w+).*SHA256 hash\s*:\s*([A-Fa-f0-9]{64})", line)

            if not m_md5:
                m_md5 = re.search(r"(^\.\w+)\s+MD5 hash\s*:\s*([a-fA-F0-9]{32})", line)
            if m_md5:
                sec = m_md5.group(1).strip()
                triage.section_hashes.setdefault(sec, {})["md5"] = m_md5.group(2).strip()

            if not m_sha:
                m_sha = re.search(r"(^\.\w+)\s+SHA256 hash\s*:\s*([a-fA-F0-9]{64})", line)
            if m_sha:
                sec = m_sha.group(1).strip()
                triage.section_hashes.setdefault(sec, {})["sha256"] = m_sha.group(2).strip()

            # Packers / compiler
            if "PEID rules based strings for compiler info" in line or "PEID rules" in line:
                window = " ".join(lines[i:i+6])
                bracketed = re.findall(r"\[([^\]]+)\]", window)
                for b in bracketed:
                    triage.compiler_info.append(b.strip())

            m_pack = packer_re.search(line)
            if m_pack:
                val = None
                if m_pack.lastindex and m_pack.group(1):
                    val = m_pack.group(1).strip()
                else:
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        val = parts[1].strip()
                if val:
                    parts = [p.strip() for p in re.split(r",|\|", val) if p.strip()]
                    triage.packer_info.extend(parts)
 

            # Cryptors
            if "Cryptors Detected" in line:
                window = " ".join(lines[i:i+3])
                bracketed = re.findall(r"\[([^\]]+)\]", window)
                for b in bracketed:
                    items = [p.strip() for p in b.split(",") if p.strip()]
                    triage.cryptors.extend(items)

            # Classification
            m_class = classification_re.search(line)
            if m_class:
                triage.malware_classification = m_class.group(1).strip()

            m_probs = class_probs_re.search(line)
            if m_probs:
                parts = [p.strip() for p in m_probs.group(1).split() if p.strip()]
                try:
                    triage.classification_probs = [float(x.rstrip(",")) if isinstance(x, str) else float(x) for x in parts]
                except Exception:
                    # numeric extraction
                    nums = re.findall(r"[-+]?[0-9]*\.?[0-9]+(?:[eE][-+]?\d+)?", m_probs.group(1))
                    triage.classification_probs = [float(n) for n in nums]

            # collecting urls, IPs, Emails
            for m in url_re.findall(line):
                if m and m not in triage.urls:
                    triage.urls.append(m.strip())
            for m in ip_re.findall(line):
                if m and m not in triage.ips:
                    triage.ips.append(m.strip())
            for m in email_re.findall(line):
                if m and m not in triage.emails:
                    triage.emails.append(m.strip())

            # Imports block in static file
            if line.strip().startswith("DLL:"):
                in_imports_block = True
                parts = line.split(":", 1)
                if len(parts) > 1:
                    current_dll = parts[1].strip()
                else:
                    current_dll = None
                continue

            if in_imports_block:
                if line.strip().startswith("*"):
                    func = line.strip().lstrip("*").strip()
                    if current_dll:
                        combined = f"{current_dll}::{func}"
                    else:
                        combined = func
                    if combined not in triage.imports:
                        triage.imports.append(combined)
                    continue
                if line.strip() == "":
                    in_imports_block = False
                    current_dll = None

        triage.imports = list(dict.fromkeys(triage.imports))
        triage.urls = list(dict.fromkeys(triage.urls))
        triage.ips = list(dict.fromkeys(triage.ips))
        triage.emails = list(dict.fromkeys(triage.emails))
        triage.packer_info = list(dict.fromkeys(triage.packer_info))
        triage.compiler_info = list(dict.fromkeys(triage.compiler_info))
        triage.cryptors = list(dict.fromkeys(triage.cryptors))

        if triage.md5_hash == "Unknown":
            m = re.search(r"([a-fA-F0-9]{32})\s*MD5", trigun_text)
            if m:
                triage.md5_hash = m.group(1)
        if triage.sha256_hash == "Unknown":
            m = re.search(r"([A-Fa-f0-9]{64}).*SHA-?256", trigun_text)
            if m:
                triage.sha256_hash = m.group(1)

        return triage

    # ---------------------------
    # Dynamic analysis parsing (Hybrid Analysis output)
    # ---------------------------
    def preprocess_dynamic(self, dynamic_text: str, triage: TriageData) -> TriageData:
        """Parse the structured text output from ha_fetch_results.sh into TriageData."""
        json_str = None
        if "Full JSON Response" in dynamic_text:
            parts = dynamic_text.split("Full JSON Response")
            search_text = parts[-1]
        else:
            search_text = dynamic_text

        match = re.search(r'([{\[].*)', search_text, re.DOTALL)
        if match:
            json_str = match.group(1).strip()
            json_str = re.sub(r'===+.*', '', json_str, flags=re.DOTALL).strip()
            json_str = re.sub(r'Full report available at:.*', '', json_str, flags=re.DOTALL).strip()

        if json_str:
            try:
                data = json.loads(json_str)
                if isinstance(data, list) and len(data) > 0:
                    data = data[0]
                
                triage.dynamic_verdict = str(data.get('verdict', ''))
                triage.dynamic_threat_score = str(data.get('threat_score', ''))
                triage.dynamic_threat_level = str(data.get('threat_level', ''))
                triage.dynamic_av_detect = str(data.get('av_detect', ''))
                triage.dynamic_vx_family = str(data.get('vx_family', ''))
                triage.dynamic_submit_name = str(data.get('submit_name', ''))
                triage.dynamic_analysis_time = str(data.get('analysis_start_time', ''))
                triage.dynamic_environment = str(data.get('environment_description', ''))
                
                tags = data.get('classification_tags', [])
                if isinstance(tags, list):
                    triage.dynamic_classification_tags = [str(t) for t in tags]
                
                for m in data.get('mitre_attcks', []):
                    if isinstance(m, dict):
                        triage.dynamic_mitre.append(f"{m.get('tactic', 'N/A')} / {m.get('technique', 'N/A')} ({m.get('attck_id', 'N/A')})")
                
                for f in data.get('extracted_files', []):
                    if isinstance(f, dict):
                         triage.dynamic_extracted_files.append(f.get('name', 'unnamed'))
                
                for p in data.get('processes', []):
                    if isinstance(p, dict):
                        triage.dynamic_processes.append(f"[PID {p.get('uid', '?')}] {p.get('name', 'unnamed')}")
                        
                for sig in data.get('signatures', []):
                    if isinstance(sig, dict):
                        name = sig.get('name', '')
                        desc = sig.get('description', '')
                        if len(desc) > 100:
                            desc = desc[:97] + "..."
                        triage.dynamic_signatures.append(f"[{sig.get('threat_level_human', 'info')}] {name}: {desc}")

                triage.dynamic_full_json = json.dumps(data)
                
            except Exception as e:
                print(f"[ERROR] Failed to parse dynamic JSON: {e}")

        # Deduplicate
        triage.dynamic_classification_tags = list(dict.fromkeys(triage.dynamic_classification_tags))
        triage.dynamic_mitre = list(dict.fromkeys(triage.dynamic_mitre))
        triage.dynamic_extracted_files = list(dict.fromkeys(triage.dynamic_extracted_files))
        triage.dynamic_processes = list(dict.fromkeys(triage.dynamic_processes))
        triage.dynamic_signatures = list(dict.fromkeys(triage.dynamic_signatures))

        return triage

    # ---------------------------
    # Disassembly parsing
    # ---------------------------
    def extract_from_disasm(self, disasm_text: str) -> Tuple[List[str], List[str], Dict]:
        """
        Extracts:
            - strings (suspicious strings block)
            - imports (from 'Imports (N):' section)
            - functions info (dict mapping function name/address -> {score, api_calls, disasm})
        """
        strings = []
        imports = []
        functions = {}

        lines = disasm_text.splitlines()
        n = len(lines)
        i = 0

        # Helper to read an indented block until blank line or separator
        def read_block(start_idx: int) -> Tuple[List[str], int]:
            out = []
            j = start_idx
            while j < n:
                ln = lines[j]
                if ln.strip() == "":
                    break
                out.append(ln.rstrip())
                j += 1
            return out, j

        # 1) Extract "Imports (N):" block(s)
        # Pattern: a line starting with "Imports (" then many lines like "  0x1000d000: CryptGenRandom"
        imp_start_re = re.compile(r"^\s*Imports\s*\(\s*\d+\s*\)\s*:", re.IGNORECASE)
        # 2) Extract "Suspicious strings (N):" block(s)
        susp_strings_re = re.compile(r"^\s*Suspicious strings\s*\(\s*\d+\s*\)\s*:", re.IGNORECASE)
        # Alternative 'Potential URLs' or 'Strings' or 'Potential' headings in other disasm variants
        alt_strings_re = re.compile(r"Potential URLS|Potential IPv4 addresses|Potential Mail addresses|Suspicious strings", re.IGNORECASE)

        while i < n:
            line = lines[i]

            # Imports block
            if imp_start_re.match(line) or line.strip().startswith("Imports (") or line.strip().lower().startswith("imports ("):
                # consume the heading and then the subsequent lines that look like imports until blank or separator
                i += 1
                while i < n and lines[i].strip() != "":
                    ln = lines[i].strip()
                    # entries often like "0x1000d000: CryptGenRandom" or "  CryptGenRandom"
                    m = re.search(r"(?::\s*)?([A-Za-z0-9_@.]+)$", ln)
                    if m:
                        impname = m.group(1).strip()
                        if impname not in imports:
                            imports.append(impname)
                    else:
                        # fallback: take the last token
                        tokens = ln.split()
                        if tokens:
                            impname = tokens[-1].strip()
                            if impname not in imports:
                                imports.append(impname)
                    i += 1
                continue

            # Suspicious strings block
            if susp_strings_re.match(line) or alt_strings_re.match(line):
                # If it's a multi-headed 'Potential URLS' section (in static), we still could capture useful strings.
                i += 1
                while i < n and lines[i].strip() != "":
                    ln = lines[i].rstrip()
                    # lines often like " 0x10010118: Ooops, your important files are encrypted..."
                    m = re.match(r"^\s*0x[0-9a-fA-F]+:\s*(.+)$", ln)
                    if m:
                        s = m.group(1).strip()
                        # Remove weird control chars
                        s = s.replace("\r", "\\r").replace("\n", "\\n")
                        if s and s not in strings:
                            strings.append(s)
                    else:
                        # sometimes long lines are just text; include them
                        clean = ln.strip()
                        if clean and clean not in strings:
                            strings.append(clean)
                    i += 1
                continue

            # Functions: look for "Function: name at 0x... (size: ...)" then "Suspicious Score: ..."
            func_header_m = re.match(r"^\s*Function:\s*(\S+)\s+at\s+(0x[0-9a-fA-F]+).*", line)
            if func_header_m:
                func_name = func_header_m.group(1).strip()
                func_addr = func_header_m.group(2).strip()
                # initialize
                cur_key = f"{func_name}@{func_addr}"
                functions[cur_key] = {"name": func_name, "addr": func_addr, "score": None, "api_calls": [], "disasm": []}
                # advance capturing until a separator (like '--------------------------------------------------------------------------------') or blank line followed by next function
                j = i + 1
                while j < n:
                    ln = lines[j]
                    # Suspicious Score line
                    m_score = re.search(r"Suspicious Score\s*[:\-]?\s*([0-9eE\.\-]+)", ln)
                    if m_score:
                        try:
                            functions[cur_key]["score"] = float(m_score.group(1))
                        except Exception:
                            functions[cur_key]["score"] = m_score.group(1)
                    # API Calls: often after header "API Calls:" then lines
                    if ln.strip().startswith("API Calls:"):
                        # read subsequent lines until blank or "Suspicious Instructions" or "Disassembly"
                        k = j + 1
                        while k < n and lines[k].strip() != "" and not lines[k].strip().startswith("Suspicious Instructions") and not lines[k].strip().startswith("Disassembly"):
                            api_ln = lines[k].strip().lstrip("-* ").strip()
                            if api_ln and api_ln not in functions[cur_key]["api_calls"]:
                                functions[cur_key]["api_calls"].append(api_ln)
                            k += 1
                        j = k
                        continue
                    # Disassembly: capture lines under "Disassembly:" until blank or separator
                    if ln.strip().startswith("Disassembly:"):
                        k = j + 1
                        disasm_block = []
                        while k < n and not re.match(r"^-{5,}", lines[k]) and lines[k].strip() != "":
                            disasm_block.append(lines[k].rstrip())
                            k += 1
                        functions[cur_key]["disasm"] = disasm_block
                        j = k
                        continue

                    # Stop condition: separator line of dashes indicates end of function section
                    if re.match(r"^-{10,}", ln):
                        break

                    j += 1
                i = j
                continue

            i += 1

        # Fallback: also try to extract any quoted strings anywhere
        quoted_strings = re.findall(r'"([^"]{3,})"', disasm_text)
        for qs in quoted_strings:
            if qs not in strings:
                strings.append(qs)

        # dedup
        imports = list(dict.fromkeys(imports))
        strings = list(dict.fromkeys(strings))

        return strings, imports, functions

    # ---------------------------
    # Helper: chunk text
    # ---------------------------
    def chunk_text(self, text: str, max_chars: int = 2500) -> List[str]:
        if not text:
            return []
        chunks = []
        i = 0
        while i < len(text):
            chunk = text[i:i + max_chars]
            chunks.append(chunk)
            i += max_chars
        return chunks

    # ---------------------------
    # Prompt construction (explicitly request cfg_dot)
    # ---------------------------
    def create_prompt(self, triage: TriageData, disasm_chunk: str, chunk_num: int, total_chunks: int) -> List[Dict[str, str]]:
        # Prepare summary strings for system/user message
        top_imports = [imp[:100] for imp in triage.imports[:50]]  # reduced to avoid context limits
        top_strings = [s[:150] for s in triage.strings[:100]] # reduced to avoid context limits

        section_hash_summary = ""
        for sec, hdict in triage.section_hashes.items():
            section_hash_summary += f"- {sec}: md5={hdict.get('md5','')}, sha256={hdict.get('sha256','')}\n"
        section_entropy_summary = ""
        for sec, ent in triage.section_entropy.items():
            section_entropy_summary += f"- {sec}: entropy={ent}\n"

        system_msg = {
            "role": "system",
            "content": (
                "You are a seasoned malware analyst. You analyze disassembly summaries "
                "that include scored suspicious functions, import maps, and extracted strings, "
                "combined with static triage context. Produce accurate technical findings targeted to DFIR teams."
            )
        }

        # user message: be explicit about desired JSON shape and cfg_dot key
        user_instructions = (
            "STATIC CONTEXT:\n"
            f"- File Type: {triage.file_type}\n"
            f"- MD5: {triage.md5_hash}\n"
            f"- SHA256: {triage.sha256_hash}\n"
            f"- IMPHash: {triage.imp_hash}\n"
            f"- Fuzzy (ssdeep): {triage.fuzzy_hash}\n"
            f"- Entropy (global): {triage.entropy}\n"
            f"Section hashes:\n{section_hash_summary}"
            f"Section entropies:\n{section_entropy_summary}"
            f"- Packers: {', '.join(triage.packer_info[:20])}\n"
            f"- Compiler/PEID info: {', '.join(triage.compiler_info[:20])}\n"
            f"- Cryptors: {', '.join(triage.cryptors[:20])}\n"
            f"- URLs found: {', '.join(triage.urls[:20])}\n"
            f"- IPs found: {', '.join(triage.ips[:20])}\n"
            f"- Emails found: {', '.join(triage.emails[:20])}\n"
            f"- Imports (sample):\n  " + "\n  ".join(top_imports) + "\n\n"
        )

        # Add dynamic analysis context if available
        if triage.dynamic_verdict:
            dynamic_ctx = (
                "DYNAMIC ANALYSIS CONTEXT (Hybrid Analysis Sandbox):\n"
                f"- Verdict: {triage.dynamic_verdict}\n"
                f"- Threat Score: {triage.dynamic_threat_score}\n"
                f"- Threat Level: {triage.dynamic_threat_level}\n"
                f"- AV Detection: {triage.dynamic_av_detect}\n"
                f"- VX Family: {triage.dynamic_vx_family}\n"
                f"- Environment: {triage.dynamic_environment}\n"
                f"- Classification Tags: {', '.join(triage.dynamic_classification_tags[:20])}\n"
                f"- MITRE Techniques (dynamic): {', '.join(triage.dynamic_mitre[:20])}\n"
                f"- Processes Observed: {', '.join(triage.dynamic_processes[:20])}\n"
                f"- Extracted Files: {', '.join(triage.dynamic_extracted_files[:10])}\n"
                f"- Dynamic API Signatures:\n  " + "\n  ".join(triage.dynamic_signatures[:30]) + "\n\n"
            )
            user_instructions += dynamic_ctx

        user_instructions += (
            f"- Strings (sample):\n  " + "\n  ".join(top_strings) + "\n\n"
            f"DISASSEMBLY SUMMARY CHUNK {chunk_num+1} of {total_chunks}:\n"
            f"{disasm_chunk}\n\n"
            "TASKS (respond strictly in JSON):\n"
            "1) Review suspicious functions and their scores, explain relevance.\n"
            "2) Analyze import maps and identify suspicious API usage and likely capabilities.\n"
            "3) Highlight suspicious strings (including ransom note text) and infer potential behaviors.\n"
            "4) Propose Indicators of Compromise (IOCs) grouped by ips, domains, urls, registry keys, files.\n"
            "5) Map behaviors or function roles to MITRE ATT&CK tactics (provide technique IDs where possible).\n"
            "RESPONSE FORMAT:\n"
            "Return a single JSON object with the following top-level keys (use empty lists/objects if no data):\n"
            " - block_findings[]  (strings describing suspicious code blocks)\n"
            " - api_behaviors[]   (strings mapping APIs to behaviors)\n"
            " - obfuscation[]     (strings describing obfuscation techniques)\n"
            " - mitre[]           (strings or objects mapping to ATT&CK IDs)\n"
            " - iocs { ips:[], domains:[], urls:[], registry:[], files:[] }\n"
            " - risk { level: 'low|medium|high', confidence: 0-1 }\n"
            "\nIMPORTANT: Respond in valid JSON only. Keep JSON keys exactly as requested.\n"
        )

        user_msg = {
            "role": "user",
            "content": user_instructions
        }

        return [system_msg, user_msg]

    # ---------------------------
    # Analysis call + robust JSON extraction
    # ---------------------------
    def analyze_chunk(self, prompt: List[Dict[str, str]]) -> Dict:
        """
        Calls the Groq chat completions and tries to robustly parse JSON responses.
        If the model returns extraneous text, attempt to extract the outermost JSON object.
        """
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=prompt,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                response_format={"type": "json_object"},
                stream=False,
            )
        except Exception as e:
            print(f"[ERROR] Groq API call failed: {e}")
            return {"error": f"Groq API call failed: {e}"}

        # The SDK sometimes returns nested objects; try to find JSON content
        content = None
        try:
            # Try direct path used previously
            content = response.choices[0].message.content
        except Exception:
            # fallback: string convert
            try:
                content = str(response)
            except Exception:
                content = None

        if not content:
            return {"error": "No content in LLM response", "raw": str(response)}

        # If content already a dict (some SDKs parse it), return it
        if isinstance(content, dict):
            return content

        # If content is string, try to parse JSON directly
        if isinstance(content, str):
            # Try direct json.loads
            try:
                parsed = json.loads(content)
                return parsed
            except Exception:
                # Try to extract a top-level JSON object from the string.
                # Find the first '{' and last '}' that appear to contain JSON.
                # Use a simple stack-based brace matching to find the biggest top-level object.
                s = content
                obj_starts = [m.start() for m in re.finditer(r"\{", s)]
                best_obj = None
                for start in obj_starts:
                    stack = 0
                    for idx in range(start, len(s)):
                        if s[idx] == "{":
                            stack += 1
                        elif s[idx] == "}":
                            stack -= 1
                            if stack == 0:
                                candidate = s[start:idx+1]
                                # try parse
                                try:
                                    parsed = json.loads(candidate)
                                    best_obj = parsed
                                    break
                                except Exception:
                                    # try to clean common LLM artifacts: trailing commas, single quotes
                                    cand2 = candidate.replace(",\n}", "\n}").replace(",\n]", "\n]")
                                    cand2 = cand2.replace("'", '"')
                                    try:
                                        parsed = json.loads(cand2)
                                        best_obj = parsed
                                        break
                                    except Exception:
                                        pass
                    if best_obj is not None:
                        break
                if best_obj is not None:
                    return best_obj

                # As another fallback, try to locate a "cfg_dot" substring and return at least that
                cfg_match = re.search(r'"cfg_dot"\s*:\s*"([^"]+)"', content, re.DOTALL)
                if cfg_match:
                    try:
                        cfg_text = cfg_match.group(1)
                        return {"cfg_dot": cfg_text}
                    except Exception:
                        return {"raw": content, "note": "cfg_dot extracted heuristically"}

                return {"error": "Invalid JSON response from LLM", "raw": content}
        # Unknown type
        return {"error": "Unsupported content type from LLM", "raw": str(content)}

    # ---------------------------
    # Merge partial LLM results
    # ---------------------------
    def merge_results(self, partials: List[Dict]) -> Dict:
        merged = {
            "block_findings": [],
            "api_behaviors": [],
            "obfuscation": [],
            "mitre": [],
            "iocs": {"ips": [], "domains": [], "urls": [], "registry": [], "files": []},
            "risk": {"level": "unknown", "confidence": 0.0},
            "cfg_dot": ""
        }
        cfg_parts = []

        for idx, part in enumerate(partials):
            if not part:
                continue
            if "error" in part:
                print(f"[WARN] Skipping part {idx} due to error: {part.get('error')}")
                continue

            for k in ["block_findings", "api_behaviors", "obfuscation", "mitre"]:
                if k in part and isinstance(part[k], list):
                    merged[k].extend(part[k])

            if "iocs" in part and isinstance(part["iocs"], dict):
                for key in merged["iocs"].keys():
                    items = part["iocs"].get(key, [])
                    if isinstance(items, list):
                        merged["iocs"][key].extend([str(i) for i in items])

            if "risk" in part and isinstance(part["risk"], dict):
                try:
                    if float(part["risk"].get("confidence", 0.0)) > float(merged["risk"].get("confidence", 0.0)):
                        merged["risk"] = part["risk"]
                except Exception:
                    pass

            # cfg_dot
            if "cfg_dot" in part and isinstance(part["cfg_dot"], str) and part["cfg_dot"].strip():
                cfg_parts.append(part["cfg_dot"].strip())

            # Some LLMs may put the DOT under a different key or inside raw text, try to find it
            if "raw" in part and isinstance(part["raw"], str):
                raw = part["raw"]
                m = re.search(r"digraph\s+[^{]*\{.*\}", raw, re.DOTALL)
                if m:
                    cfg_parts.append(m.group(0))

        # deduplicate and clean lists
        for key in merged["iocs"]:
            merged["iocs"][key] = list(dict.fromkeys(merged["iocs"][key]))

        import string
        def normalize_str(s: str) -> str:
            # lower, strip punctuation and extra spaces
            s = s.lower().translate(str.maketrans('', '', string.punctuation))
            return " ".join(s.split())

        for k in ["block_findings", "api_behaviors", "obfuscation", "mitre"]:
            cleaned = []
            normalized_seen = []
            mitre_ids_seen = set()

            for item in merged[k]:
                if isinstance(item, dict):
                    try:
                        s_val = json.dumps(item, sort_keys=True)
                    except Exception:
                        s_val = str(item)
                else:
                    s_val = str(item)
                
                if k == "mitre":
                    # Extract Txxxx or txxxx
                    m_id = re.search(r'(T\d{4}(?:\.\d{3})?)', s_val, re.IGNORECASE)
                    if m_id:
                        tid = m_id.group(1).upper()
                        if tid in mitre_ids_seen:
                            continue
                        mitre_ids_seen.add(tid)
                    else:
                        norm = normalize_str(s_val)
                        if any(norm in x or x in norm for x in normalized_seen if len(norm)>10 and len(x)>10):
                            continue
                        normalized_seen.append(norm)
                    cleaned.append(s_val)
                else:
                    norm = normalize_str(s_val)
                    # For string findings, avoid near-duplicates
                    is_dup = False
                    for seen in normalized_seen:
                        if len(norm) > 15 and len(seen) > 15 and (norm in seen or seen in norm):
                            is_dup = True
                            break
                    if not is_dup:
                        normalized_seen.append(norm)
                        cleaned.append(s_val)
            merged[k] = list(dict.fromkeys(cleaned))
 

        # Merge CFGs if any
        if cfg_parts:
            merged["cfg_dot"] = self.merge_cfg_dots(cfg_parts)

        return merged

    def merge_cfg_dots(self, cfg_parts: List[str]) -> str:
        """
        Combine multiple DOT digraph sources into a single coherent graph by extracting nodes & edges.
        This is heuristic: extracts lines with '->' as edges and other bracketed attributes as nodes.
        """
        nodes = set()
        edges = set()
        for part in cfg_parts:
            # try to find inner content
            m = re.search(r"digraph\s+\w*\s*\{(.*)\}", part, re.DOTALL)
            content = m.group(1) if m else part
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("//"):
                    continue
                # edge lines
                if "->" in line:
                    # normalize semicolon
                    ed = line.rstrip(";")
                    edges.add(ed)
                    # attempt to pull node names
                    nodes_match = re.findall(r"([A-Za-z0-9_\.\"']+)\s*->\s*([A-Za-z0-9_\.\"']+)", ed)
                    for n1, n2 in nodes_match:
                        nodes.add(n1.strip())
                        nodes.add(n2.strip())
                else:
                    # treat as node definition (e.g. a[label="x"])
                    nodes.add(line.rstrip(";"))

        combined = "digraph malware_cfg {\n"
        # include nodes as statements if they look like bare labels
        for node in sorted(nodes):
            if "->" not in node and node:
                combined += f"    {node};\n"
        for edge in sorted(edges):
            combined += f"    {edge};\n"
        combined += "}"
        return combined

    def generate_phased_dynamic_cfg_dot(self, dynamic_json: str) -> str:
        dyn_nodes = set()
        dyn_edges = set()
        
        data = {}
        if dynamic_json:
            try:
                data = json.loads(dynamic_json)
            except Exception:
                pass
                
        processes = data.get('processes', [])
        signatures = data.get('signatures', [])
        
        proc_map = {}
        for p in processes:
            uid = p.get('uid')
            name = p.get('name', 'Unknown')
            pid = p.get('pid', '')
            proc_map[uid] = {"name": name, "pid": pid, "parent": p.get('parentuid')}
            
        phases = {
            "Initial Access": [],
            "Exploitation": [],
            "Post Exploitation": [],
            "Lateral Movement": [],
            "Exfiltration": [],
            "Other": []
        }
        
        keywords = {
            "Initial Access": ["drop", "download", "fetch"],
            "Exploitation": ["execute", "exploit", "spawn", "inject", "shellcode", "bypass"],
            "Post Exploitation": [
                "persist", "registry", "service", "schedule", "privilege", 
                "stealth", "hide", "obfuscate", "credential", "password", 
                "lsass", "sam", "discovery", "enum", "info", "system", 
                "evade", "hook", "disable", "firewall", "security"
            ],
            "Lateral Movement": ["psexec", "wmi", "smb", "rdp", "winrm", "share", "admin$"],
            "Exfiltration": ["exfiltrate", "upload", "c2", "cnc", "beacon", "connect", "socket", "http", "ftp", "dns", "network"]
        }
        
        for uid, p in proc_map.items():
            label = f"{p['name']}" if not p['pid'] else f"{p['name']} (PID: {p['pid']})"
            dyn_nodes.add(f'"{uid}" [label="{label}", shape="octagon", style="filled", fillcolor="lightblue"]')
            parent = p['parent']
            if parent and parent in proc_map:
                dyn_edges.add(f'"{parent}" -> "{uid}" [color="blue", label="spawns"]')

        for sig in signatures:
            desc = sig.get('description', '')
            sig_name = sig.get('name', '')
            threat_level = sig.get('threat_level', 0)
            
            if threat_level < 1 and sig.get('origin') != "API Call":
                continue
                
            caller_uid = None
            m_uid = re.search(r"\(UID:\s*([a-fA-F0-9\-]+)\)", desc)
            if m_uid:
                caller_uid = m_uid.group(1)
            else:
                for uid, p in proc_map.items():
                    if f'"{p["name"]}"' in desc:
                        caller_uid = uid
                        break
            
            sig_id = f"sig_{hash(sig_name + desc) & 0xFFFFFFFF}"
            color = "red" if threat_level >= 2 else "orange"
            short_desc = desc[:60] + "..." if len(desc) > 60 else desc
            short_desc = short_desc.replace('"', "'").replace('\n', ' ')
            label = f"{sig_name}\\n{short_desc}"
            
            node_str = f'"{sig_id}" [label="{label}", shape="box", style="filled", fillcolor="{color}", fontcolor="white"]'
            
            text_to_check = (sig_name + " " + desc).lower()
            assigned_phase = "Other"
            for phase_name, kw_list in keywords.items():
                if any(kw in text_to_check for kw in kw_list):
                    assigned_phase = phase_name
                    break
                    
            phases[assigned_phase].append(node_str)
            
            if caller_uid and caller_uid in proc_map:
                dyn_edges.add(f'"{caller_uid}" -> "{sig_id}" [color="darkred", style="dashed"]')
                
        combined = "digraph dynamic_phased_cfg {\n"
        combined += "    rankdir=TB;\n"
        combined += "    node [fontname=\"Helvetica,Arial,sans-serif\"] ;\n"
        combined += "    edge [fontname=\"Helvetica,Arial,sans-serif\"] ;\n\n"
        
        for n in sorted(dyn_nodes):
            combined += f"    {n};\n"
        for e in sorted(dyn_edges):
            combined += f"    {e};\n"
        
        combined += "\n"
        
        phase_colors = {
            "Initial Access": "lightcyan",
            "Exploitation": "lightpink",
            "Post Exploitation": "lightyellow",
            "Lateral Movement": "thistle",
            "Exfiltration": "lightsalmon",
            "Other": "whitesmoke"
        }
        
        cluster_idx = 0
        for phase_name, node_list in phases.items():
            if not node_list:
                continue
            combined += f"    subgraph cluster_phase_{cluster_idx} {{\n"
            combined += f"        label=\"Phase: {phase_name}\";\n"
            combined += "        style=filled;\n"
            combined += f"        color={phase_colors.get(phase_name, 'gray')};\n"
            combined += "        fontcolor=black;\n"
            combined += "        fontsize=14;\n"
            combined += "        fontweight=bold;\n"
            for n in sorted(node_list):
                combined += f"        {n};\n"
            combined += "    }\n\n"
            cluster_idx += 1
            
        combined += "}"
        return combined

    # ---------------------------
    # Report generation (HTML)
    # ---------------------------
    def generate_report(self, triage: TriageData, analysis: Dict) -> str:
        def html_escape(s):
            if not s:
                return ""
            return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

        def html_list(items, max_items=500):
            if not items:
                return '<span class="muted">None</span>'
            if isinstance(items, dict):
                return '<ul>' + ''.join(f'<li><strong>{html_escape(k)}:</strong> {html_escape(v)}</li>' for k, v in items.items()) + '</ul>'
            return '<ul>' + ''.join(f'<li>{html_escape(item)}</li>' for item in items[:max_items]) + '</ul>'

        def html_table(headers, rows):
            h = ''.join(f'<th>{html_escape(h)}</th>' for h in headers)
            r = ''.join('<tr>' + ''.join(f'<td>{html_escape(c)}</td>' for c in row) + '</tr>' for row in rows)
            return f'<table><thead><tr>{h}</tr></thead><tbody>{r}</tbody></table>'

        def collapsible(title, content, open_default=False):
            o = ' open' if open_default else ''
            return f'<details{o}><summary>{html_escape(title)}</summary><div class="detail-content">{content}</div></details>'

        # Section hashes table
        sec_hash_rows = []
        for sec, hd in triage.section_hashes.items():
            sec_hash_rows.append([sec, hd.get('md5', ''), hd.get('sha256', '')])
        sec_hash_table = html_table(['Section', 'MD5', 'SHA-256'], sec_hash_rows) if sec_hash_rows else '<span class="muted">None</span>'

        # Section entropy table
        sec_ent_rows = [[sec, str(ent)] for sec, ent in triage.section_entropy.items()]
        sec_ent_table = html_table(['Section', 'Entropy'], sec_ent_rows) if sec_ent_rows else '<span class="muted">None</span>'

        # IOC tables
        iocs = analysis.get('iocs', {})
        ioc_categories = ['ips', 'domains', 'urls', 'registry', 'files']
        ioc_html = ''
        for cat in ioc_categories:
            items = iocs.get(cat, [])
            if items:
                ioc_html += f'<h4>{html_escape(cat.title())}</h4>' + html_list(items)
            else:
                ioc_html += f'<h4>{html_escape(cat.title())}</h4><span class="muted">None</span>'

        # MITRE table
        mitre_items = analysis.get('mitre', [])
        mitre_html = html_list(mitre_items) if mitre_items else '<span class="muted">None</span>'

        # Dynamic analysis section
        dynamic_html = ''
        if triage.dynamic_verdict:
            dynamic_overview_rows = [
                ['Verdict', triage.dynamic_verdict],
                ['Threat Score', triage.dynamic_threat_score],
                ['Threat Level', triage.dynamic_threat_level],
                ['AV Detection', triage.dynamic_av_detect],
                ['VX Family', triage.dynamic_vx_family],
                ['Submit Name', triage.dynamic_submit_name],
                ['Analysis Time', triage.dynamic_analysis_time],
                ['Environment', triage.dynamic_environment],
            ]
            dynamic_html = f'''
            <section>
                <h2>&#128737; Dynamic Analysis (Hybrid Analysis)</h2>
                <h3>Overview</h3>
                {html_table(['Property', 'Value'], dynamic_overview_rows)}

                <h3>Classification Tags</h3>
                {html_list(triage.dynamic_classification_tags)}

                <h3>MITRE ATT&amp;CK Techniques (Dynamic)</h3>
                {html_list(triage.dynamic_mitre)}

                <h3>Extracted Files</h3>
                {html_list(triage.dynamic_extracted_files)}

                <h3>Processes Observed</h3>
                {html_list(triage.dynamic_processes)}
            </section>
            <hr>'''

        # Risk badge
        risk = analysis.get('risk', {})
        risk_level = risk.get('level', 'unknown') if isinstance(risk, dict) else 'unknown'
        risk_conf = risk.get('confidence', 0) if isinstance(risk, dict) else 0
        risk_color = {'high': '#ff4444', 'medium': '#ffaa00', 'low': '#44cc44'}.get(risk_level, '#888')

        cfg_dot = analysis.get('cfg_dot', '').strip()
        cfg_section = f'<pre class="cfg-dot">{html_escape(cfg_dot)}</pre>' if cfg_dot else '<span class="muted">CFG dot code not available</span>'

        report = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TRIGUN Triage Report — {html_escape(triage.sha256_hash[:16])}...</title>
<style>
    :root {{
        --bg: #0d1117; --surface: #161b22; --border: #30363d;
        --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
        --accent2: #bc8cff; --danger: #ff4444; --warn: #ffaa00; --ok: #3fb950;
    }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    h1 {{ color: var(--accent); font-size: 1.8rem; margin-bottom: 0.5rem; border-bottom: 2px solid var(--accent); padding-bottom: 0.5rem; }}
    h2 {{ color: var(--accent2); font-size: 1.4rem; margin: 1.5rem 0 0.8rem; }}
    h3 {{ color: var(--accent); font-size: 1.1rem; margin: 1rem 0 0.5rem; }}
    h4 {{ color: var(--muted); font-size: 0.95rem; margin: 0.8rem 0 0.3rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    hr {{ border: none; border-top: 1px solid var(--border); margin: 1.5rem 0; }}
    .badge {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 12px; font-weight: 600; font-size: 0.85rem; text-transform: uppercase; }}
    .muted {{ color: var(--muted); font-style: italic; }}
    .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 0.5rem; margin: 0.5rem 0; }}
    .meta-item {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 0.6rem 1rem; }}
    .meta-item .label {{ color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    .meta-item .value {{ font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.85rem; word-break: break-all; color: var(--text); }}
    table {{ width: 100%; border-collapse: collapse; margin: 0.5rem 0; background: var(--surface); border-radius: 6px; overflow: hidden; }}
    th {{ background: rgba(88,166,255,0.1); color: var(--accent); text-align: left; padding: 0.6rem 1rem; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    td {{ padding: 0.5rem 1rem; border-top: 1px solid var(--border); font-size: 0.85rem; font-family: 'Cascadia Code', 'Fira Code', monospace; word-break: break-all; }}
    tr:hover td {{ background: rgba(88,166,255,0.05); }}
    ul {{ list-style: none; padding: 0; margin: 0.3rem 0; }}
    ul li {{ padding: 0.25rem 0 0.25rem 1.2rem; position: relative; font-size: 0.9rem; }}
    ul li::before {{ content: '\\25B8'; position: absolute; left: 0; color: var(--accent); }}
    details {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; margin: 0.5rem 0; }}
    summary {{ padding: 0.7rem 1rem; cursor: pointer; font-weight: 600; color: var(--accent); user-select: none; }}
    summary:hover {{ background: rgba(88,166,255,0.05); }}
    .detail-content {{ padding: 0.5rem 1rem 1rem; }}
    .cfg-dot {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.8rem; overflow-x: auto; white-space: pre-wrap; }}
    .risk-badge {{ font-size: 1.1rem; padding: 0.3rem 1rem; }}
    .section {{ margin-bottom: 1.5rem; }}
    @media (max-width: 768px) {{ body {{ padding: 1rem; }} .meta-grid {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<div class="container">
    <h1>&#128301; TRIGUN Triage Report</h1>
    <p class="muted">Generated by TRIGUN Malware Analysis Toolkit</p>
    <hr>

    <section>
        <h2>&#128196; Sample Information</h2>
        <div class="meta-grid">
            <div class="meta-item"><div class="label">File Type</div><div class="value">{html_escape(triage.file_type)}</div></div>
            <div class="meta-item"><div class="label">MD5</div><div class="value">{html_escape(triage.md5_hash)}</div></div>
            <div class="meta-item"><div class="label">SHA-256</div><div class="value">{html_escape(triage.sha256_hash)}</div></div>
            <div class="meta-item"><div class="label">IMPHash</div><div class="value">{html_escape(triage.imp_hash)}</div></div>
            <div class="meta-item"><div class="label">Fuzzy Hash (ssdeep)</div><div class="value">{html_escape(triage.fuzzy_hash)}</div></div>
            <div class="meta-item"><div class="label">Global Entropy</div><div class="value">{triage.entropy}</div></div>
            <div class="meta-item"><div class="label">Classification</div><div class="value">{html_escape(triage.malware_classification)}</div></div>
            <div class="meta-item"><div class="label">Packers</div><div class="value">{html_escape(', '.join(triage.packer_info) or 'None')}</div></div>
            <div class="meta-item"><div class="label">Compiler Info</div><div class="value">{html_escape(', '.join(triage.compiler_info) or 'None')}</div></div>
            <div class="meta-item"><div class="label">Cryptors</div><div class="value">{html_escape(', '.join(triage.cryptors) or 'None')}</div></div>
        </div>

        <h3>Section Hashes</h3>
        {sec_hash_table}

        <h3>Section-wise Entropy</h3>
        {sec_ent_table}
    </section>
    <hr>

    <section>
        <h2>&#127760; Extracted Static IOCs</h2>
        <h4>URLs</h4>
        {html_list(triage.urls)}
        <h4>IP Addresses</h4>
        {html_list(triage.ips)}
        <h4>Email Addresses</h4>
        {html_list(triage.emails)}
    </section>
    <hr>

    {dynamic_html}

    <section>
        <h2>&#129302; LLM Analysis</h2>
        <h3>Risk Assessment</h3>
        <p><span class="badge risk-badge" style="background:{risk_color};color:#fff">{html_escape(risk_level.upper())}</span> &nbsp; Confidence: <strong>{risk_conf}</strong></p>

        <h3>IOC Summary</h3>
        {ioc_html}
    </section>
    <hr>

    <section>
        <h2>&#128269; Findings</h2>
        {collapsible(f"Block Findings ({len(analysis.get('block_findings', []))})", html_list(analysis.get('block_findings')))}
        {collapsible(f"API Behaviors ({len(analysis.get('api_behaviors', []))})", html_list(analysis.get('api_behaviors')))}
        {collapsible(f"Obfuscation Techniques ({len(analysis.get('obfuscation', []))})", html_list(analysis.get('obfuscation')))}
        {collapsible(f"MITRE ATT&CK Techniques ({len(mitre_items)})", mitre_html, open_default=True)}
    </section>
    <hr>

    {collapsible(f"Imports ({len(triage.imports)})", html_list(triage.imports))}
    {collapsible(f"Extracted Strings ({len(triage.strings)})", html_list(triage.strings))}
    <hr>

    <section>
        <h2>&#128200; Control Flow Graph (CFG)</h2>
        {cfg_section}
    </section>

</div>
</body>
</html>'''
        return report

    # ---------------------------
    # High-level analyze orchestration
    # ---------------------------
    # ---------------------------
    # High-level analyze orchestration
    # ---------------------------
    def analyze(self, trigun_text: str, disasm_text: str, dynamic_text: str = "") -> str:
        print("[*] Preprocessing static triage file...")
        triage = self.preprocess_trigun(trigun_text)

        # Parse dynamic analysis if available
        if dynamic_text:
            print("[*] Preprocessing dynamic analysis file...")
            triage = self.preprocess_dynamic(dynamic_text, triage)
            print(f"[OK] Dynamic verdict: {triage.dynamic_verdict}, Threat Score: {triage.dynamic_threat_score}")

        print("[*] Extracting data from disassembly...")
        strings_disasm, imports_disasm, functions = self.extract_from_disasm(disasm_text)

        # Merge static + disasm extractions
        print(f"[DEBUG] Found {len(strings_disasm)} strings and {len(imports_disasm)} imports in disasm")
        triage.strings = list(dict.fromkeys(triage.strings + strings_disasm))
        triage.imports = list(dict.fromkeys(triage.imports + imports_disasm))
        triage.disassembly = disasm_text

        # Build disassembly chunks: prefer function-oriented chunks if functions dict large
        disasm_chunks = []
        # Define a safe maximum character limit for the disassembly chunk part of the prompt
        # We target ~6500 chars to leave space for the static context which can be ~1000+ tokens
        SAFE_CHUNK_MAX_CHARS = 2500 

        func_items = list(functions.items())
        if func_items:
            # Group functions ensuring total size per chunk summary is under SAFE_CHUNK_MAX_CHARS
            per_chunk = 10 # Start with a safe assumption
            current_chunk_text_parts = []
            current_chunk_size = 0
            
            for key, finfo in func_items:
                # Construct summary for this function
                func_summary = (
                    f"Function: {finfo.get('name')} @ {finfo.get('addr')}\n"
                    f"Suspicious Score: {finfo.get('score')}\n"
                    f"API Calls: {', '.join(finfo.get('api_calls',[]))}\n"
                    f"Disassembly:\n" 
                    + "\n".join(finfo.get('disasm', [])[:50]) # Limit disasm to 50 lines
                    + "\n---\n"
                )
                
                # Check if adding this function would exceed the limit
                if current_chunk_size + len(func_summary) > SAFE_CHUNK_MAX_CHARS and current_chunk_text_parts:
                    disasm_chunks.append("\n".join(current_chunk_text_parts))
                    current_chunk_text_parts = []
                    current_chunk_size = 0
                
                # Add the function summary
                current_chunk_text_parts.append(func_summary)
                current_chunk_size += len(func_summary)

            # Add the last chunk
            if current_chunk_text_parts:
                 disasm_chunks.append("\n".join(current_chunk_text_parts))

        else:
            # fallback: chunk raw disassembly text using the safe limit
            disasm_chunks = self.chunk_text(disasm_text, max_chars=SAFE_CHUNK_MAX_CHARS)

        partial_results = []
        print(f"Processing {len(disasm_chunks)} disassembly chunks for LLM analysis...")
        
        for idx, chunk in enumerate(disasm_chunks):
            # --------------------------------------------------------------------------
            # CRITICAL: Sleep here BEFORE the API call for the SECOND and subsequent chunks
            # --------------------------------------------------------------------------
            if idx > 0:
                print("Respecting rate limit, waiting for 65 seconds before processing next batch...")
                time.sleep(65)

            print(f"[INFO] Analyzing chunk {idx+1}/{len(disasm_chunks)} (approx {len(chunk)} chars)...")
            prompt = self.create_prompt(triage, chunk, idx, len(disasm_chunks))
            result = self.analyze_chunk(prompt)
            print(f"[INFO] Received result for chunk {idx+1}: keys = {list(result.keys())[:10]}")
            partial_results.append(result)

        print("[*] Merging partial results...")
        merged_result = self.merge_results(partial_results)

        print("[*] Generating phased dynamic CFG from 027dynamic.txt data...")
        dynamic_cfg = self.generate_phased_dynamic_cfg_dot(triage.dynamic_full_json)
        if dynamic_cfg and triage.dynamic_full_json:
            merged_result["cfg_dot"] = dynamic_cfg

        print("[*] Generating final HTML report...")
        report = self.generate_report(triage, merged_result)
        return report


# ---------------------------
# Script entrypoint
# ---------------------------
if __name__ == "__main__":
    import sys

    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        print("[WARN] GROQ_API_KEY not found in environment. Groq calls will fail without it.")

    analyzer = MultiPassGroqAnalyzer(api_key=api_key)

    # Attempt to read files from typical paths; fall back to /mnt/data (uploaded)
    possible_paths = [
        "./results/027.txt",
        "./results/027asm.txt",
        "./results/027dynamic.txt",
        "/mnt/data/027.txt",
        "/mnt/data/027asm.txt",
        "/mnt/data/027dynamic.txt",
        "027.txt",
        "027asm.txt",
        "027dynamic.txt"
    ]

    trigun_static = ""
    disasm = ""
    dynamic = ""

    # Try to find static file and asm file
    for p in possible_paths:
        if p.endswith("027.txt") and not p.endswith("asm.txt") and not p.endswith("dynamic.txt") and os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    trigun_static = f.read()
                print(f"[OK] Loaded static triage from {p}")
                break
            except Exception as e:
                print(f"[WARN] Could not read {p}: {e}")

    for p in possible_paths:
        if p.endswith("027asm.txt") and os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    disasm = f.read()
                print(f"[OK] Loaded disassembly from {p}")
                break
            except Exception as e:
                print(f"[WARN] Could not read {p}: {e}")

    for p in possible_paths:
        if p.endswith("027dynamic.txt") and os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    dynamic = f.read()
                print(f"[OK] Loaded dynamic analysis from {p}")
                break
            except Exception as e:
                print(f"[WARN] Could not read {p}: {e}")

    if not trigun_static:
        print("[ERROR] Could not locate 027.txt static triage file. Please place it in ./results or /mnt/data and retry.")
        sys.exit(1)
    if not disasm:
        print("[ERROR] Could not locate 027asm.txt disassembly file. Please place it in ./results or /mnt/data and retry.")
        sys.exit(1)
    if not dynamic:
        print("[INFO] No 027dynamic.txt found. Dynamic analysis section will be skipped.")

    triage_report = analyzer.analyze(trigun_static, disasm, dynamic)

    out_path = "./results/final_triage_report.html"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(triage_report)

    print(f"Triage report generated: {out_path}")
