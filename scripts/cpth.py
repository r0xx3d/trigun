import hashlib

def rolling_hash(data, window_size):
    boundaries = []
    hash_value = 0
    for char in range(len(data)):
        hash_value = ((hash_value << 1) + ord(data[char])) % window_size
        if hash_value == 0:
            boundaries.append(char + 1)
    return boundaries

def ctph_hash(data, window_size=64):
    boundaries = rolling_hash(data, window_size)
    chunks = []
    start = 0
    for end in boundaries:
        chunk = data[start:end]
        chunk_hash = hashlib.md5(chunk.encode()).hexdigest()[:8] 
        chunks.append(chunk_hash)
        start = end
    return ''.join(chunks)

def ctph_similarity(hash1, hash2):
    if not hash1 or not hash2:
      return 0.0

    matches = sum(1 for a, b in zip(hash1, hash2) if a == b)
    return (matches / max(len(hash1), len(hash2))) * 100

data1 = "This is a sample text for CTPH hashing"
data2 = "This is a sampl text for CTPH hashing"
hash1 = ctph_hash(data1)
hash2 = ctph_hash(data2)

print("First hash: " + hash1)
print("Second hash: "+ hash2)
similarity = ctph_similarity(hash1, hash2)
print(f"Similarity: {similarity:.1f}%")
