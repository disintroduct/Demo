from fastecdsa import keys, curve
import time

"""The reason there are two ways to generate a keypair is that generating the public key requires
a point multiplication, which can be expensive. That means sometimes you may want to delay
generating the public key until it is actually needed."""

t1 = time.time()
# generate a keypair (i.e. both keys) for curve P256
priv_key, pub_key = keys.gen_keypair(curve.P256)
t2 = time.time()
print(priv_key, pub_key)
# generate a private key for curve P256
priv_key = keys.gen_private_key(curve.P256)
t3 = time.time()
# get the public key corresponding to the private key we just generated
pub_key = keys.get_public_key(priv_key, curve.P256)
t4 = time.time()
print(t2-t1, t3-t2, t4-t3)
print(priv_key, pub_key)