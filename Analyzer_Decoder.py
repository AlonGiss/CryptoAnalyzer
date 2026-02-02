import Utils
from Analyze import auto_analyze

type_encription = {
    '1' : 'Hex',
    '2' : 'Base64',
    '3' : 'Caesar',
    '4' : 'Xor',
    '5' : 'Binary',
    '6' : 'Analyze',
    '10' : 'Exit'
}

def main():
    while True:
        encryption = get_encryption_input()
        if encryption == 'Exit':
            break
        cipher = input("Enter Cipher: ")
        print()
        answer = decoded_encryption(encryption,cipher)
        if answer != None:
            if encryption == 'Analyze':
                print(answer)
            else:
                print(f'Decoded: {answer}')
        else:
            print(f'Cannot Decode {encryption}: {cipher}')
        print('')

def decoded_encryption(type,cipher):
    print(f'====Decoding {type}====')
    if type == 'Hex':
        return Utils.decode_hex(cipher)
    if type == 'Base64':
        return Utils.decode_base64(cipher)
    if type == 'Caesar':
        return Utils.decode_caesar(cipher)
    if type == 'Xor':
        return Utils.decode_xor(cipher)
    if type == 'Binary':
        return Utils.decode_binary(cipher)
    if type == 'Analyze':
        return auto_analyze(cipher)


def get_encryption_input():
    while True:
        print('=======MENU=======')
        print('1. Hex to text')
        print('2. Base64 to text')
        print('3. Caesar (Same Key)')
        print('4. Xor (single-byte)')
        print('5. Binary to text')
        print('6. Analyze Encryption')
        print('10. Exit')
        type = input('Choose one option: ')
        if type in type_encription:
            break
        print('Choose a valid option. \n')

    return type_encription[type]

if __name__ == '__main__':
    main()



