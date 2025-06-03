def caesar_cipher(text, shift, encrypt=True):
    shift = shift % 26
    if not encrypt:
        shift = -shift
    encrypted_text = ''
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

def vigenere_cipher(text, key, encrypt=True):
    key = key.lower()
    key_indices = [ord(char) - ord('a') for char in key]
    encrypted_text = ''
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = key_indices[key_index]
            if not encrypt:
                shift = -shift
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            encrypted_text += chr(shifted)
            key_index = (key_index + 1) % len(key)
        else:
            encrypted_text += char
    return encrypted_text

def affine_cipher(text, a, b, encrypt=True):
    def mod_inverse(a, m):
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        return -1

    m = 26
    encrypted_text = ''
    a_inv = mod_inverse(a, m)
    for char in text:
        if char.isalpha():
            if encrypt:
                enc = (a * (ord(char) - ord('a')) + b) % m
            else:
                enc = a_inv * ((ord(char) - ord('a')) - b) % m
            encrypted_text += chr(enc + ord('a'))
        else:
            encrypted_text += char
    return encrypted_text

from Crypto.Cipher import AES, DES
import base64

def aes_encrypt(plain_text, key):
    key = key.zfill(32).encode('utf-8')  
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def aes_decrypt(cipher_text, key):
    key = key.zfill(32).encode('utf-8')  
    raw_data = base64.b64decode(cipher_text)
    nonce = raw_data[:16]
    ciphertext = raw_data[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plain_text = cipher.decrypt(ciphertext).decode('utf-8')
    return plain_text

def des_encrypt(plain_text, key):
    key = key.zfill(8).encode('utf-8')  
    cipher = DES.new(key, DES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def des_decrypt(cipher_text, key):
    key = key.zfill(8).encode('utf-8')  
    raw_data = base64.b64decode(cipher_text)
    nonce = raw_data[:8]
    ciphertext = raw_data[8:]
    cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
    plain_text = cipher.decrypt(ciphertext).decode('utf-8')
    return plain_text

def xor_cipher(text, key):
    key = key * (len(text) // len(key)) + key[:len(text) % len(key)]
    return ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(text, key))
