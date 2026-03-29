import math
import pefile
import sys


def shannon_entropy(data):
    possible = dict(((chr(x),0) for x in range(0,256)))

    for byte in data:
        possible[chr(byte)] += 1

    data_len = len(data)
    entropy = 0.0

    for i in possible:
        if possible[i] == 0:
            continue

        p = float(possible[i]/data_len)
        entropy -= p * math.log(p,2)
    return entropy


file = sys.argv[1]

with open(file, 'rb') as file_data:
    data = file_data.read()

print(shannon_entropy(data))

