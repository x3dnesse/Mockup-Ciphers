import hashlib
import hmac

# We can get this shared secret from our previous script
shared_secret_hex = 'b967b0650b01fa19596a019687851d3da0e8e864246478832f9331bc6fba3cce'

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
