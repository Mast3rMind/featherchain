"""
Keys:
  gen private key
  gen public key
  Elliptic Curve Cryptography
  gen address
  Base58

Wallets:
  Seeded wallets

Transactions:
  gen transaction (UTXO (unspent transaction output))
    hash
    value
    inputs from address
    outputs to address (spent or unspent)

Blocks:
  The Genesis Block
  gen block
    header
      prev block header hash
      timestamp
      difficulty
      nonce
      merkle root
        gen merkle root

    block height
    header hash
    transactions

"""

import os, sys, hashlib
import seccure

class Block(object):
  class Merkle(object):
    @staticmethod
    def gen_root(transactions):
      pass

    def check_leaf(merkle_root, transaction):
      pass

class Transaction(object):
  class Record(object):
    def __init__(self, address=None, value=0, r_type="input", state=None):
      """
      r_type: input | output
      state: None | change | spent | unspent 
      """
      self.address = address
      self.value = value
      self.type = r_type
      self.state = state

  def __init__(self):
    self.hash = None
    self.inputs = []
    self.outputs = []

  def append_input(self, address, value):
    self.inputs.append(Record(address, value, "input"))
    return self

  def append_output(self, address, value, state):
    self.outputs.append(Record(address, value, "output", state))
    return self

class Wallet(object):
  def __init__(self, key=None):
    if key:
      self.key = key
    else:
      self.key = Key()
      self.key.gen_private_key()
      self.key.gen_public_key()
      self.key.gen_address()

    return self.key.address

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
