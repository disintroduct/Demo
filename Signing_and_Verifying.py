from fastecdsa import curve, ecdsa, keys
from hashlib import sha384, sha256


def sign(msg:str, private_key, SHA):
    r, s = ecdsa.sign(msg, private_key, hashfunc=SHA)
    return ((r, s))

def verifying(msg:str, public_key, SHA, commitmet):
    valid = ecdsa.verify(commitmet, msg, public_key)
    return valid

def test():
    m = "a message to sign via ECDSA"  # some message

    ''' use default curve and hash function (P256 and SHA2) '''
    private_key = keys.gen_private_key(curve.P256)
    public_key = keys.get_public_key(private_key, curve.P256)
    # standard signature, returns two integers
    r, s = ecdsa.sign(m, private_key)
    # should return True as the signature we just generated is valid.
    valid = ecdsa.verify((r, s), m, public_key)

    ''' specify a different hash function to use with ECDSA '''
    r, s = ecdsa.sign(m, private_key, hashfunc=sha384)
    valid = ecdsa.verify((r, s), m, public_key, hashfunc=sha384)

    ''' specify a different curve to use with ECDSA '''
    private_key = keys.gen_private_key(curve.P224)
    public_key = keys.get_public_key(private_key, curve.P224)
    r, s = ecdsa.sign(m, private_key, curve=curve.P224)
    valid = ecdsa.verify((r, s), m, public_key, curve=curve.P224)

    ''' using SHA3 via pysha3>=1.0b1 package '''
    import sha3  # pip install [--user] pysha3==1.0b1
    from hashlib import sha3_256
    private_key, public_key = keys.gen_keypair(curve.P256)
    r, s = ecdsa.sign(m, private_key, hashfunc=sha3_256)
    valid = ecdsa.verify((r, s), m, public_key, hashfunc=sha3_256)

if __name__ == "__main__":
    Base = curve.P256.G
    print(str(Base))