import base64

def decode_hex(cipher):
    cipher = cipher.strip()

    if "0x" in cipher:
        cipher = cipher.replace("0x",'')
        parts = cipher.split()
        try:
            d = b''
            for p in parts:
                d += bytes([int(p, 16)])
            return d
        except Exception as e:
            print(f"Hex format not good, {e}")
            return None

    cipher = cipher.lower()
    if cipher.startswith("0x"):
        cipher = cipher[2:]

    if len(cipher) % 2 != 0:
        print(f"Hex Length not good. ")
        return None

    try:
        d = bytes.fromhex(cipher)
        return d
    except Exception as err:
        print(f"Cannot Decrypt, error: {err}")
        return None


def decode_base64(cipher):
    try:
        if isinstance(cipher, str):
            cipher = cipher.strip().encode()
        return base64.b64decode(cipher, validate=True)

    except Exception as err:
        print(f"Cannot decode Base64: {err}")
        return None


def caesar_shift(text, shift):
    res = ""
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            res += chr((ord(c) - base - shift) % 26 + base)
        else:
            res += c
    return res


def decode_caesar(cipher):
    return brute_force_decode(
        cipher,
        keyspace=range(26),
        transform_fn=caesar_transform,
        name="Caesar"
    )



def get_top_results(results):
    bests = '\n'
    for i in results:
        bests += '\t' + i['text'] + '\n'
    return bests


def score_text(text):
    COMMON_EN_LETTERS = "ETAOINSHRDLU"
    score = 0
    for c in text.upper():
        if c in COMMON_EN_LETTERS:
            score += 2
        elif c.isalpha():
            score += 1
        elif c == ' ':
            score += 1
        else:
            score -= 1
    return score

def decode_binary(cipher):
    try:
        cipher = cipher.strip().replace(' ', '')

        if len(cipher) % 8 != 0:
            print("Binary length not multiple of 8")
            return None

        bytes_list = []
        for i in range(0, len(cipher), 8):
            byte = cipher[i:i+8]
            if not all(c in '01' for c in byte):
                print("Invalid binary characters")
                return None
            bytes_list.append(int(byte, 2))

        return bytes(bytes_list)

    except Exception as e:
        print(f"Cannot decode binary: {e}")
        return None


def decode_xor(cipher):
    cipher = decode_hex(cipher)
    return brute_force_decode(
        cipher,
        keyspace=range(256),
        transform_fn=xor_transform,
        name="XOR (single-byte)"
    )


def brute_force_decode(cipher, keyspace, transform_fn, name="cipher"):
    results = []

    for key in keyspace:
        try:
            decoded = transform_fn(cipher, key)
            if isinstance(decoded, bytes):
                text = decoded.decode(errors="ignore")
            else:
                text = decoded

            score = score_text(text)

            results.append({
                "key": key,
                "text": text,
                "score": score
            })
        except:
            continue

    results.sort(key=lambda x: x["score"], reverse=True)

    best = results[0]
    second = results[1]
    diff = best["score"] - second["score"]

    if diff > 15:
        confidence = "HIGH"
    elif diff > 6:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return f'''
cipher: {name}
best_key: {best["key"]}
best_text: {best["text"]}
confidence: {confidence}

top_candidates:
{get_top_results(results[:5])}
'''

def caesar_transform(text, shift):
    res = ""
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            res += chr((ord(c) - base - shift) % 26 + base)
        else:
            res += c
    return res

def xor_transform(cipher, key):
    if isinstance(cipher, str):
        cipher = cipher.encode(errors="ignore")
    return bytes(b ^ key for b in cipher)


