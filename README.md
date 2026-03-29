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
### Static Analysis Pipeline
* Various fingerprinting techniques utilized such as IMP Hashing, Section Hashing, Fuzzy Hashing with md5 and sha256 hashing algorithms.
* String analysis: Extract string texts such as IP Addresses, emails, urls, crypto wallet addresses, ransom notes etc.
* Packer detection using custom yara scripts.
* Cryptographic signature detection with custom yara scripts.
* Malware signature based detection with yara scripts.
* Shannon Entropy calculation of files and sections.
* Imports and Exports parsing.
* Disassembly analysis and suspicious block extraction using r2pipe and capstone.
* Integrated pipeline with Groq API to use GPT-OSS 120B model to generate report and construct a CFG for malware's execution workflow to help with the manual analysis process.
* Triage report generation with data from static analysis, dynamic analysis and disassembly analysis.

HUGE THANKS TO ALL THE REFERRED BELOW FOR ALL THE RESOURCES, TOOLING AND TUTORIALS.



