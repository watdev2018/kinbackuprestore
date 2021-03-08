import json
import binascii
from PIL import Image
from pyzbar.pyzbar import decode
import pysodium

backup_password = 'XXXXXXXXXXXXXXXXXXX'
data = decode(Image.open('backup_qr.png'))

res = json.loads(data[0].data)

salt = binascii.unhexlify(res['salt'])
nonce_and_ciphertext = binascii.unhexlify(res['seed'])

nonce = nonce_and_ciphertext[0:pysodium.crypto_secretbox_NONCEBYTES]
ciphertext = nonce_and_ciphertext[pysodium.crypto_secretbox_NONCEBYTES:]

pwhash = pysodium.crypto_pwhash(pysodium.crypto_auth_KEYBYTES, str.encode(backup_password), salt, pysodium.crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE, pysodium.crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE)

print(pysodium.crypto_secretbox_open(ciphertext, nonce, pwhash))
