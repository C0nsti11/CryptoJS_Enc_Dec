import base64
from Crypto.Cipher import AES
from Crypto import Random

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]

class AESCipher:
    def __init__( self, key, salt=None, iv=None, password=None):
        self.key = key
        self.salt = salt
        self.iv = iv
        self.password = password

    def encrypt( self, raw ):
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        # base64.b64encode( iv + cipher.encrypt( raw ) )
        cipher_text = cipher.encrypt(raw)
        return iv, cipher_text

    def decrypt( self, enc ):
        # enc = base64.b64decode(enc)
        iv = self.iv # enc[:16]
        salt = self.salt
        password = self.password
        cipher = AES.new(self.key, AES.MODE_CBC, iv, salt, password )
        plain_text = unpad(cipher.decrypt( enc[16:] ))
        return plain_text