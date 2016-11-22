import featherchain
import hashlib
import os
import random
import asyncio

fck = featherchain.Key()
fck.gen_private_key()
fck.gen_public_key()
fck.gen_address()

print(fck.private_key.hex())
print(fck.public_key.hex())
print(fck.address.hex())

genesis_block = featherchain.Block()

chain = [genesis_block]

for i in range(0, 5 + int(random.random() * 100)):
  transactions = [featherchain.Transaction(hashlib.sha256(os.urandom(32)).digest()) for i in range(0, 5 + int(random.random() * 100))]
  merkleroot = featherchain.Block.Merkle.gen_root(transactions)
  block = featherchain.Block(chain[-1], merkleroot, transactions)
  chain.append(block)

print(chain)


featherchain.main()