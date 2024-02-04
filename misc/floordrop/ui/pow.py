import base64
import secrets

VERSION = 's'
MODULUS = 2**1279-1
CHALSIZE = 2**128

SOLVER_URL = 'https://goo.gle/kctf-pow'

def python_sloth_square(y, diff, p):
    for i in range(diff):
        y = pow(y ^ 1, 2, p)
    return y

def encode_number(num):
    size = (num.bit_length() // 24) * 3 + 3
    return str(base64.b64encode(num.to_bytes(size, 'big')), 'utf-8')

def decode_number(enc):
    return int.from_bytes(base64.b64decode(bytes(enc, 'utf-8')), 'big')

def decode_challenge(enc):
    dec = enc.split('.')
    if dec[0] != VERSION:
        raise Exception('Unknown challenge version')
    return list(map(decode_number, dec[1:]))

def encode_challenge(arr):
    return '.'.join([VERSION] + list(map(encode_number, arr)))

def get_challenge(diff):
    x = secrets.randbelow(CHALSIZE)
    return encode_challenge([diff, x])

def verify_challenge(chal, sol):
    [diff, x] = decode_challenge(chal)
    [y] = decode_challenge(sol)
    res = python_sloth_square(y, diff, MODULUS)
    return (x == res) or (MODULUS - x == res)