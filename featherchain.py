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

import os, sys, hashlib, time, pickle, argparse
import seccure
import asyncio

state = {
  'port': 8000,
  'peers': [],
  'blockchain': [],
  'tx_pool': set()
}

class Block(object):
  def __init__(self, prev_block=None, merkleroot=None, transactions=[]):
    if not prev_block:
      # here is the definition for genesis block    
      self.block_height = 1
      self.header_hash = hashlib.sha256(hashlib.sha256(bytes(bytearray.fromhex(hex(1479711288)[2:]))).digest()).digest()
    else:
      # here is general block creation
      self.header = {
        "prev_block_hash": prev_block.header_hash,
        "timestamp": int(time.time()),
        "merkleroot": merkleroot
      }
      header_bytes = b''
      header_bytes += self.header["prev_block_hash"]
      header_bytes += bytes(bytearray.fromhex(hex(self.header["timestamp"])[2:]))
      header_bytes += self.header["merkleroot"]

      self.header_hash = hashlib.sha256(hashlib.sha256(header_bytes).digest()).digest()
      self.transactions = transactions
      self.block_height = prev_block.block_height + 1

  def append_transaction(self, transaction):
    self.transactions.append(transaction)
    
  
  class Merkle(object):
    @staticmethod
    def gen_root(transactions):
      if len(transactions) % 2 == 1:
        transactions.append(transactions[-1])

      hash_lst = [i for i in map(lambda x: x.hash, transactions)]
      while True:
        new_hash_lst = []
        for i in range(0, len(hash_lst)):
          if i % 2 == 0:
            new_hash_lst.append(hashlib.sha256(hash_lst[i] + hash_lst[i + 1]).digest())

        hash_lst = new_hash_lst
        if len(hash_lst) == 1:
          break

        if len(hash_lst) % 2 == 1:
          hash_lst.append(hash_lst[-1])

      return hash_lst[0]

    @staticmethod
    def check_leaf(merkle_root, merkle_path):
      def merge(node):
        if len(node) == 1:
          return node[0]

        hash_left = merge(node[0]) if type(node[0]) == list else node[0]
        hash_right = merge(node[1]) if type(node[1]) == list else node[1]
        return hashlib.sha256(hash_left + hash_right)

      return merge(merkle_path) == merkle_root

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

  def __init__(self, hash=None):
    self.hash = hash
    self.inputs = []
    self.outputs = []

  def __repr__(self):
    return 'TX: ' + self.hash.hex()

  def append_input(self, address, value):
    self.inputs.append(Transaction.Record(address, value, "input"))
    return self

  def append_output(self, address, value, state):
    self.outputs.append(Transaction.Record(address, value, "output", state))
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


class Route(object):
  def do_route(self, obj):
    ({
      dict: self.r_dict,
      set: self.r_set,
      list: self.r_list,
      Transaction: self.r_tx
    })[type(obj)](obj)

  def __init__(self, obj, transport):
    self.transport = transport
    self.do_route(obj)

  def r_set(self, s):
    [self.do_route(i) for i in s]

  def r_list(self, lst):
    [self.do_route(i) for i in lst]
  
  def r_tx(self, tx):
    state['tx_pool'].add(tx)
  
  def r_dict(self, input):
    if 'ask_tx_pool' in input:
      self.transport.write(pickle.dumps(state['tx_pool']))
    
    if 'ask_blockchain' in input:
      self.transport.write(pickle.dumps(state['blockchain']))


class Network(object):
  class ServerProtocol(asyncio.Protocol): 
    def connection_made(self, transport):
      peername = transport.get_extra_info('peername') 
      print('Server -> Connection from {}'.format(peername)) 
      self.transport = transport

    def data_received(self, data):
      print('Server -> Data received length: {}'.format(len(data)))
      obj = pickle.loads(data)
      Route(obj, self.transport)
      self.transport.close()

  class ClientProtocol(asyncio.Protocol): 
    def __init__(self, message, loop):
      self.message = message
      self.loop = loop
      self.transport = None
      
    def connection_made(self, transport): 
      self.transport = transport
      transport.write(self.message) 

    def data_received(self, data):
      obj = pickle.loads(data)
      Route(obj, self.transport)

    def connection_lost(self, exc):
      pass

  def __init__(self, event_loop, serve_port):
    self.loop = event_loop
    coro_server = self.loop.create_server(Network.ServerProtocol, '0.0.0.0', serve_port) 
    server = self.loop.run_until_complete(coro_server)

  async def send(self, host, port, msg):
    try:
      await self.loop.create_connection(lambda: Network.ClientProtocol(msg, self.loop), host, port)
    except ConnectionRefusedError:
      print('Conncection refused by address: {}:{}'.format(host, port))



async def routine(network):
  # init sync
  await network.send(state['peers'][0][0], int(state['peers'][0][1]), pickle.dumps({'ask_tx_pool': 1}, 0))

  while True:
    await asyncio.sleep(10)

    print('State: {}'.format(state))

    tx = Transaction(os.urandom(32))
    state['tx_pool'].add(tx)

    for peer in state['peers']:
      await network.send(peer[0], int(peer[1]), pickle.dumps(tx, 0))


def main():
  loop = asyncio.get_event_loop()
  network = Network(loop, state['port'])
  loop.run_until_complete(routine(network))
  try:
    loop.run_forever() 
  except KeyboardInterrupt:
    pass

if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument("-port", type=int, help="set the current node port for listening")
  parser.add_argument("-remote", help="""set remote nodes address for connection.
    example: 127.0.0.1:8001,127.0.0.1:8002,...""")
  args = parser.parse_args()
  
  if not args.port:
    raise Exception('Please set -port for service listening')

  if not args.remote:
    raise Exception('Please set -remote for peer connection')

  state['port'] = args.port

  remote_addrs = [i.split(':') for i in args.remote.split(',')]
  state['peers'] = remote_addrs

  main()