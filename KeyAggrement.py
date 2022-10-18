"""
The local client implements key aggrement.
"""
from email.mime import base
from fastecdsa import keys, curve
from fastecdsa.curve import P256
from fastecdsa.point import Point
import numpy as np
import hashlib
import time


def keyaggrement(pri_key, pub_key):
    return (pri_key*pub_key).x


def HashKey(Symmetric_Key:str):
    return hashlib.sha256(Symmetric_Key)

if __name__ == "__main__":
    pri_key, pub_key = keys.gen_keypair(P256)
    Base = P256.G.x
    print(Base, str(Base))
    a = str(Base).encode("utf-8")
    print(HashKey(a))
    # b, c = HashKey(a)
    # print(b.encode("utf-8"), c)
