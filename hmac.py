# key  clave
# b block long 
from operator import xor
import string

from hashSha256 import generate_hash

ipad=bytearray()
opad=bytearray()

def hmac(b:int, key:bytearray, text:bytearray) -> bytearray:
    k0=key
    define_defaultValues(b)

    if key.count > b:
        #H(key) || 0
        k0= key.append(int.to_bytes(0, b - key.count, 'big'))
    elif key.count < b:
        k0= key.append(int.to_bytes(0, b - key.count, 'big'))
    
    #Step 4
    k0_4:bytearray = xor(k0,ipad)
    #Step 5/Step 6
    k0_6=generate_hash(k0_4.append(text))   
    #Step 7
    k0_7:bytearray=xor(k0,opad)

    return generate_hash(
        (k0_7.append(k0_6)))

def define_defaultValues(b:int):
    ipad= bytearray.fromhex(b'\x36'*b)
    opad= bytearray.fromhex(b'\x5C'*b)