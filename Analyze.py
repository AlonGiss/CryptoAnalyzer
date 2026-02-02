

def auto_analyze(cipher):
    try:
        results = []

        if Analyze_Hex(cipher):
            results.append("Hex")

        if Analyze_Base64(cipher):
            results.append("Base64")

        if Analyze_Binary(cipher):
            results.append("Binary")

        if Analyze_Caesar(cipher):
            results.append("Caesar")

        if Analyze_Xor(cipher):
            results.append("XOR")

        if not results:
            return 'Cannot Give an answer'

        result = 'Possible Type of Encryption:\n'
        for i in results:
            result += f'\t{i}\n'

        return result

    except Exception as err:
        print(f'ERROR {err}')
        return 'Cannot Give an answer'

def Analyze_Base64(cipher):
    if not isinstance(cipher, str):
        return False

    cipher = cipher.strip()
    if len(cipher) < 4 or len(cipher) % 4 != 0:
        return False

    base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

    for c in cipher:
        if c not in base64_chars:
            return False

    if "=" in cipher:
        if not cipher.endswith("=") and not cipher.endswith("=="):
            return False
        if cipher.count("=") > 2:
            return False

    return True


def Analyze_Binary(cipher):
    if not isinstance(cipher, str):
        return False

    cipher = cipher.strip().replace(" ", "")
    if len(cipher) < 8 or len(cipher) % 8 != 0:
        return False

    return all(c in "01" for c in cipher)

def Analyze_Hex(cipher):
    if not isinstance(cipher, str):
        return False

    cipher = cipher.strip().lower().replace(" ", "")
    cipher = cipher.replace('0x','')
    if cipher.startswith("0x"):
        cipher = cipher[2:]

    if len(cipher) < 2 or len(cipher) % 2 != 0:
        return False

    hex_chars = "0123456789abcdef"
    return all(c in hex_chars for c in cipher)


def Analyze_Caesar(cipher):
    if not isinstance(cipher, str):
        return False

    letters = sum(c.isalpha() for c in cipher)
    if letters < 4:
        return False

    ratio = letters / len(cipher)
    return ratio > 0.6


def Analyze_Xor(cipher):
    if isinstance(cipher, str):
        cipher = cipher.encode(errors="ignore")

    if not isinstance(cipher, (bytes, bytearray)):
        return False

    if len(cipher) < 4:
        return False

    non_printable = sum(b < 32 or b > 126 for b in cipher)
    ratio = non_printable / len(cipher)

    return ratio > 0.3
