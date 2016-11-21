import featherchain

def print_b(b):
  print(featherchain.Util.bytes_to_hex(b))

fck = featherchain.Key()

fck.gen_private_key()
fck.gen_public_key()
fck.gen_address()


print_b(fck.private_key)
print_b(fck.public_key)
print_b(fck.address)