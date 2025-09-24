import sys
import yara

rules_path = sys.argv[2]

malware_rules = yara.compile(rules_path + 'windows.yar')
exe_file_path = sys.argv[1]

# detecting signatures
try:
    matches = malware_rules.match(exe_file_path)
    if matches:
        print('Known malware signature found...')
        print(matches)
except Exception as e:
    print(f'Signaturing Exception, {e}')

