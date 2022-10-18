"""
The local client implements linear homomorphic hash.
"""
from email.mime import base
from fastecdsa import keys, curve
from fastecdsa.curve import P256
from fastecdsa.point import Point
import numpy as np

import time

"""The reason there are two ways to generate a keypair is that generating the public key requires
a point multiplication, which can be expensive. That means sometimes you may want to delay
generating the public key until it is actually needed."""

def generate_keypair():
    # generate a keypair (i.e. both keys) for curve P256
    priv_key, pub_key = keys.gen_keypair(curve.P256)
    return(priv_key, pub_key)


def generate_key_split():
    # generate a private key for curve P256
    priv_key = keys.gen_private_key(curve.P256)
    # get the public key corresponding to the private key we just generated
    pub_key = keys.get_public_key(priv_key, curve.P256)
    return(priv_key, pub_key)


def HH(gradient:float, Magnification_factor:int, Curve):
    Base = Curve.G
    Maged_grad = Magnification_factor * np.sum(gradient)
    h = int(gradient[0])
    return int(Maged_grad) * Base


def show_curve_detail(Curve):
    print("a:",Curve.a, "b:", Curve.b, "p:",Curve.p, "q:", Curve.q, "G:", Curve.G, Curve.gx)


if __name__ == "__main__":
    grad = np.random.random(2^12)
    print(grad)
    t1 = time.time()
    print(HH(grad, 1000000000, P256))
    t2 = time.time()
    print(t2-t1)
    print(int(np.sum(grad)*100000000)*P256.G)