# Trigun
![vash_stampede](https://github.com/user-attachments/assets/7c3be1bb-72e2-4403-951d-d5c224a278f0)

TRIGUN or triage gun is a tool developed to automate both static and dynamic windows-based malware analysis to ease the process of triaging and IOC collection.

The tool is being developed for PYTHON VERSION 3.13 and being tested on a Kali VM

To setup tool:
```
$ ./setup.sh
```

Inside venv
```
python -m pip install -r requirements.txt
export HA_API_KEY = "<hybrid analysis API key>"
export GROQ_API_KEY = "<GROQ api key>"
```


Run static analysis and populate 027.txt file and copy the job id for fetching hybrid analysis data
```
$ ./trigun.sh /path/to/sample.exe | tee -a ./scripts/results/027.txt
```

Fetch dynamic analysis data from Hybrid Analysis API using:
```
$ ./ha_fetch_results.sh <job_id> | tee -a ./scripts/results/027dynamic.txt
```

Generate disassembly data
```
$ cd scripts
$ python disassembly_analysis.py /path/to/sample.exe --output ./results/027asm.txt
```

Generate report(will take some time)
```
$ python report_gen.py
```

Final HTML based report will be generated in ./scripts/results/ directory


## Project details:
### Analysis Pipeline
* Various fingerprinting techniques utilized such as IMP Hashing, Section Hashing, Fuzzy Hashing with md5 and sha256 hashing algorithms.
* String analysis: Extract string texts such as IP Addresses, emails, urls, crypto wallet addresses, ransom notes etc.
* Packer detection using custom yara scripts.
* Cryptographic signature detection with custom yara scripts.
* Malware signature based detection with yara scripts.
* Shannon Entropy calculation of files and sections.
* Imports and Exports parsing.
* Disassembly analysis and suspicious block extraction using r2pipe and capstone.
* Integrated Hybrid Analysis API for dynamic analysis of samples(threat score, process trees, mitre mappings based on realtime execution in sandbox)
* Integrated pipeline with Groq API to use GPT-OSS 120B model to generate report and construct a CFG for malware's execution workflow using IOCs, process trees and disassembly data to help with the manual analysis process.
* Custom chunking function to send data from static, dynamic and disassembly analysis to GPT-OSS 120B in chunks respecting token limit(8000) and rate limit(60 seconds wait time before each chunk is processed)
* Triage report generation with data from static analysis, dynamic analysis and disassembly analysis.

HUGE THANKS TO ALL THE REFERRED BELOW FOR ALL THE RESOURCES, TOOLING AND TUTORIALS.

https://0xrick.github.io/win-internals/pe2/
https://www.cybertriage.com/blog/intro-to-imphash-for-dfir-fuzzy-malware-matching/
https://jieliau.medium.com/fuzzy-hashing-an-interesting-way-for-malware-analysis-99bd5091d285
https://medium.com/asecuritysite-when-bob-met-alice/malware-detection-context-triggered-piecewise-hashes-ctph-9bc4da234111
https://library.mosse-institute.com/articles/2022/05/fuzzy-hashing-import-hashing-and-section-hashing/fuzzy-hashing-import-hashing-and-section-hashing.html
https://www.geeksforgeeks.org/ethical-hacking/string-extraction/
https://faun.pub/using-regex-in-incident-response-a-powerful-tool-for-the-modern-analyst-34b62679e7cb
https://www.veeam.com/blog/yara-rules-malware-detection-analysis.html
https://medium.com/@iramjack8/malware-packers-9dcf6fa2f0e7
https://www.oreilly.com/library/view/learning-malware-analysis/9781788392501/fccf23e9-49e4-45f9-94f2-d01f3b3fafed.xhtml
https://infosecwriteups.com/intro-to-malware-detection-using-yara-eacab8373cf4
https://cocomelonc.github.io/malware/2022/11/05/malware-analysis-6.html
https://redcanary.com/blog/threat-detection/threat-hunting-entropy/
https://infosecwriteups.com/pe-import-analyzer-a-practical-guide-for-malware-analysts-and-reverse-engineers-29b8b98aeaf3
https://rioasmara.com/2021/10/17/parsing-export-function-from-pe-manually/
https://goggleheadedhacker.com/blog/post/8
https://malware.news/t/resolving-stack-strings-with-capstone-disassembler-unicorn-in-python/80701
https://console.groq.com/docs/quickstart



