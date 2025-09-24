import sys
import re
import json

def find_strings(filename, patterns, min_length=4):
    with open(filename,'rb') as f:
        content = f.read().decode('ascii','ignore')
        results = []
        ascii_regex = re.compile(r'[ -~]{' + str(min_length) + r',}')
        for pattern_name, pattern_regex in patterns.items():
            if pattern_name == 'all':
                matches = ascii_regex.findall(content)
            else:
                matches = re.findall(pattern_regex, content)
            for match in matches:
                results.append(match)
        return results
    
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python strings_analyzer.py <filename> <pattern1,pattern2,...>")
        print("Use 'all' for pattern to get all strings")
        sys.exit(1)
    filename = sys.argv[1]
    chosen_patterns = sys.argv[2].split(',')
    with open("./scripts/patterns.json","r") as f:
        all_patterns = json.load(f)
    if 'all' in chosen_patterns:
        patterns = {'all': None}
    else:
        patterns = {k: all_patterns[k] for k in chosen_patterns if k in all_patterns}
    for s in find_strings(filename,patterns):
        print(s)
