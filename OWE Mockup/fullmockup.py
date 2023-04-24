import os
import hashlib
import hmac
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import dh

# First we undergo generation of our certs using the same DH params, in the real world these are set to a standard
os.system('openssl dhparam -out sharedparams.pem 1024 -engine threads -threads 6')
print('all finished generating shared dh parameters file')
print('-------------------------------------------')
# Computation of the keypairs
os.system('openssl genpkey -out apdhkey.pem -paramfile sharedparams.pem')
os.system('openssl genpkey -out cldhkey.pem -paramfile sharedparams.pem')
print('all finished generating key pair files')
print('-------------------------------------------')
# Computation of the private keys
os.system('openssl pkey -in apdhkey.pem  -out apdhprivkey.pem')
os.system('openssl pkey -in cldhkey.pem -out cldhprivkey.pem')
print('all finished generating private key files')
print('-------------------------------------------')
# Computation of the public keys
os.system('openssl pkey -in apdhprivkey.pem -pubout -out apdhpubkey.pem')
os.system('openssl pkey -in cldhprivkey.pem -pubout -out cldhpubkey.pem')
print('all finished generating public key files')
print('-------------------------------------------')

# Now we are going to compute the shared secret for both the access point and client
# First, we load in the client's private and public keys
with open('cldhprivkey.pem', 'rb') as f:
    client_private_key = load_pem_private_key(f.read(), password=None)
with open('cldhpubkey.pem', 'rb') as f:
    client_public_key = load_pem_public_key(f.read())
# Then we load the AP's private and public keys 
with open('apdhpubkey.pem', 'rb') as f:
    ap_public_key = load_pem_public_key(f.read())
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

# Finally we can compute the PMK and PTK using the shared secret

shared_secret_hex = cl_shared_secret.hex()
# convert shared secret to bytes
shared_secret = bytes.fromhex(shared_secret_hex)
# We can derive our PMK using the SHA256 function
pmk = hashlib.sha256(shared_secret).digest()
print("PMK:", pmk.hex())

# Some example Values for our PTK derivation process
aa = b"48:54:42:2d:47:75:65:73:74"  # Hex Representation of SSID HTBGuest
sa = b"70:61:73:73:77:6f:72:64:31:32"  # This is the salt, aka hex form of password123
ap = aa # We can set this to the same value as our aa value
label = b"OWE Key Derivation" # This is the label we need in our algorithm
context = b""
length = 64 # We define the length here of our example PTK

data = aa + sa + ap #Finally we concatenate :)

ptk = hmac.new(pmk, label + context + data, hashlib.sha256).digest()[:length]
print("PTK:", ptk.hex()) #Finally we should have produced a solid example PTK
os.system('rm *.pem') #Cert cleanup



