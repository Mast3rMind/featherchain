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
  """ The `Block` in a block chain system """

  def __repr__(self):
    return 'Block: {}|{}'.format(self.block_height, self.header_hash.hex()) 
    
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
    """ According to the design, each block contains merkle root for SPV verification """
    
    @staticmethod
    def gen_root(transactions):
      """ Generate merkle root by merging binary tree """

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
      """ Given a merkle path, got hashed along the path, it should be equal to merkleroot """

      def merge(node):
        if len(node) == 1:
          return node[0]

        hash_left = merge(node[0]) if type(node[0]) == list else node[0]
        hash_right = merge(node[1]) if type(node[1]) == list else node[1]
        return hashlib.sha256(hash_left + hash_right)

      return merge(merkle_path) == merkle_root

class Transaction(object):
  """ The transaction definition, which could be represented as script and contract """

  class Record(object):
    """ Trading record for general transaction """
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
    self.timestamp = int(time.time() * 1000)

  def __repr__(self):
    return 'TX: ' + self.hash.hex()

  def append_input(self, address, value):
    self.inputs.append(Transaction.Record(address, value, "input"))
    return self

  def append_output(self, address, value, state):
    self.outputs.append(Transaction.Record(address, value, "output", state))
    return self

class Wallet(object):
  """ The wallet is just a key keeper """

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
  """ Methods for key and address generation """

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
  """ A routing map for network functionality """

  def do_route(self, obj):
    ({
      dict: self.r_dict,
      set: self.r_set,
      list: self.r_list,
      Block: self.r_block,
      Transaction: self.r_tx
    })[type(obj)](obj)

  def __init__(self, obj, transport):
    self.transport = transport
    self.do_route(obj)

  def r_block(self, block):
    if block.header_hash == state['blockchain'][0].header_hash:
      return None

    # can add verification for block here
    state['blockchain'].append(block)
    state['tx_pool'] = set()

  def r_set(self, s):
    [self.do_route(i) for i in s]

  def r_list(self, lst):
    [self.do_route(i) for i in lst]
  
  def r_tx(self, tx):
    # can add verification for transaction here
    state['tx_pool'].add(tx)

  def r_dict(self, input):
    msg = []
    if 'sync_tx_pool' in input:
      msg.append(state['tx_pool'])
    
    if 'sync_blockchain' in input:
      msg.append(state['blockchain'])

    if msg:
      self.transport.write(pickle.dumps(msg))


class Network(object):
  """ The network utility """

  class ServerProtocol(asyncio.Protocol): 
    def connection_made(self, transport):
      peername = transport.get_extra_info('peername') 
      print('Server -> Connection from {}'.format(peername)) 
      self.transport = transport

    def data_received(self, data):
      print('Server -> Data received length: {}'.format(len(data)))
      obj = pickle.loads(data)
      Route(obj, self.transport)

      # network spread can be added here
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
    """ Coroutine sending function for network """

    try:
      await self.loop.create_connection(lambda: Network.ClientProtocol(msg, self.loop), host, port)
    except ConnectionRefusedError:
      print('Conncection refused by address: {}:{}'.format(host, port))


async def routine(network):
  """ Definition for blockchain node daily work """

  # init sync
  await network.send(state['peers'][0][0], 
    int(state['peers'][0][1]), 
    pickle.dumps({'sync_tx_pool': 1, 'sync_blockchain': 1}, 0))

  while True:
    await asyncio.sleep(10)

    print('State: {}'.format(state))

    # randomly generate transaction for test
    tx = Transaction(os.urandom(32))
    state['tx_pool'].add(tx)
      
    # send the new transaction
    for peer in state['peers']:
      await network.send(peer[0], int(peer[1]), pickle.dumps(tx, 0))

    # randomly select block creator (should be replaced by solid consensus algorithm)
    if int.from_bytes(os.urandom(8), 'little') < 1e18:
      transactions = list(state['tx_pool']) # should sort
      merkleroot = Block.Merkle.gen_root(transactions) 
      block = Block(state['blockchain'][-1], merkleroot, transactions)
      state['blockchain'].append(block)
      state['tx_pool'] = set()

      print('============ Block Created ===========')
      for peer in state['peers']:
        await network.send(peer[0], int(peer[1]), pickle.dumps(block, 0))


def main():
  """ Using event loop from asyncio to struct the network I/O and routine funciton """

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

  # state init here
  state['port'] = args.port
  remote_addrs = [i.split(':') for i in args.remote.split(',')]
  state['peers'] = remote_addrs
  # every node should have the gensis block
  state['blockchain'] = [Block()]

  main()