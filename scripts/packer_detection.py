import pefile
import yara
import sys

rules_path = str(sys.argv[2])

peid_rules = yara.compile(rules_path + 'peid.yar')
packer_rules = yara.compile(rules_path + 'packer.yar')
crypto_rules = yara.compile(rules_path + 'crypto.yar')

exe_file_path = sys.argv[1]

# crypto signatures
try:
    matches = crypto_rules.match(exe_file_path)
    if matches:
        print('Cryptors Detected...')
        print(matches)
except Exception as e:
    print(f'Cryptor Exception, {e}')

# detecting packers
try:
    matches = packer_rules.match(exe_file_path)
    if matches:
        print('Packers Detected...')
        print(matches)
except Exception as e:
    print(f'Packer Exception, {e}')

# peid rules for compiler matching
# differentiating between compilers and packers/cryptors
#first, let's define the list of packers/cryptors we want to detect

packers = ['AHTeam', 'Armadillo', 'Stelth', 'yodas', 'ASProtect', 'ACProtect', 'PEnguinCrypt', 
 'UPX', 'Safeguard', 'VMProtect', 'Vprotect', 'WinLicense', 'Themida', 'WinZip', 'WWPACK',
 'Y0da', 'Pepack', 'Upack', 'TSULoader'
 'SVKP', 'Simple', 'StarForce', 'SeauSFX', 'RPCrypt', 'Ramnit', 
 'RLPack', 'ProCrypt', 'Petite', 'PEShield', 'Perplex',
 'PELock', 'PECompact', 'PEBundle', 'RLPack', 'NsPack', 'Neolite', 
 'Mpress', 'MEW', 'MaskPE', 'ImpRec', 'kkrunchy', 'Gentee', 'FSG', 'Epack', 
 'DAStub', 'Crunch', 'CCG', 'Boomerang', 'ASPAck', 'Obsidium','Ciphator',
 'Phoenix', 'Thoreador', 'QinYingShieldLicense', 'Stones', 'CrypKey', 'VPacker',
 'Turbo', 'codeCrypter', 'Trap', 'beria', 'YZPack', 'crypt', 'crypt', 'pack',
 'protect', 'tect'
]

try:
    matches = peid_rules.match(exe_file_path)
    if matches:
        print("Detecting Packers based on PEID ruleset")
        for match in matches:
            rule_name = match.rule
            if rule_name and any(packer.lower() in rule_name.lower() for packer in packers):
                print(rule_name)
except Exception as e:
    print(f'PEID exception, {e}')

try:
    matches = peid_rules.match(exe_file_path)
    if matches:
        print("PEID rules based strings for compiler info")
        print(matches)

except Exception as e:
    print(f'PEID exception, {e}')


