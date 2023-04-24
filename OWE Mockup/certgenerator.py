import os

# Temporarily Making the Two Diffie Hellman Parameter Files for the simulated AP and client
# We will add additional threads to speed up this process
# Although it is recommended to use 3072 bits in OWE, we will utilize 1024 to save our script some time.

os.system('openssl dhparam -out sharedparams.pem 1024 -engine threads -threads 6')
print('all finished generating shared dh parameters file')
print('-------------------------------------------')
os.system('clear')

# Now we are going to compute the key pairs
os.system('openssl genpkey -out apdhkey.pem -paramfile sharedparams.pem')
os.system('openssl genpkey -out cldhkey.pem -paramfile sharedparams.pem')
print('all finished generating key pair files')
print('-------------------------------------------')

# Then we can compute the private keys for both the AP and the client
os.system('openssl pkey -in apdhkey.pem  -out apdhprivkey.pem')
os.system('openssl pkey -in cldhkey.pem -out cldhprivkey.pem')
print('all finished generating private key files')
print('-------------------------------------------')

# Then we can compute the public keys for the AP and the client
os.system('openssl pkey -in apdhprivkey.pem -pubout -out apdhpubkey.pem')
os.system('openssl pkey -in cldhprivkey.pem -pubout -out cldhpubkey.pem')
print('all finished generating public key files')
print('-------------------------------------------')


