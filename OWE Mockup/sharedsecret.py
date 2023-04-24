import os
import hashlib
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import dh

# We need to load the Client's Private Key
with open('cldhprivkey.pem', 'rb') as f:
    client_private_key = load_pem_private_key(f.read(), password=None)

# Then we load the Client's Public Key
with open('cldhpubkey.pem', 'rb') as f:
    client_public_key = load_pem_public_key(f.read())
 
# Then we load the AP's Public Key 
with open('apdhpubkey.pem', 'rb') as f:
    ap_public_key = load_pem_public_key(f.read())

# Then we load the AP's Private Key
with open('apdhprivkey.pem', 'rb') as f:
    ap_private_key = load_pem_private_key(f.read(), password=None)

# Then we need to set our DH Parameters from the private keys
cl_params = client_private_key.parameters()
ap_params = ap_private_key.parameters()

# Then we can compute the shared secret for the client
cl_shared_key = client_private_key.exchange(ap_public_key)
cl_shared_secret = hashlib.sha256(cl_shared_key).digest()

# Of course shortly followed by the AP's shared secret
ap_shared_key = ap_private_key.exchange(client_public_key)
ap_shared_secret = hashlib.sha256(ap_shared_key).digest()

# Then finally we can print these to compare them, they should be identical
print("Client shared secret:", cl_shared_secret.hex())
print("AP shared secret:", ap_shared_secret.hex())

