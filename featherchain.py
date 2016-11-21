import os, sys, hashlib
import seccure

class Key(object):
  def __init__(self):
    self.private_key = None
    self.public_key = None
    self.address = None

  def gen_private_key(self):
    limit = 1.158e77 - 1
    while True:
      result = hashlib.sha256(os.urandom(32)).digest()
      sample = int.from_bytes(result, byteorder=sys.byteorder)
      if sample < limit:
        break
    
    self.private_key = result
    return self.private_key

  def gen_public_key(self):
    if not self.private_key:
      raise ValueError("no private key")

    self.public_key = seccure.passphrase_to_pubkey(self.private_key, curve='secp256r1/nistp256').to_bytes()
    return self.public_key

  def gen_address(self):
    if not self.public_key:
      raise ValueError("no public key")

    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(self.public_key).digest())
    self.address = ripemd160.digest()
    return self.address

class Util(object):
  @staticmethod
  def bytes_to_hex(b):
    return hex(int.from_bytes(b, byteorder='little'))[2:]
