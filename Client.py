import hashlib
import LHH
import Signing_and_Verifying
import Symmetric_encry
import KeyAggrement
import time
import numpy as np
from fastecdsa import curve
# from options import args_parser


if __name__ == "__main__":

    client_number = 1000
    vector_dimension = 2^12
    Magnification_factor = 10^6

    # key aggrement for per client
    private_key_i, public_key_i = LHH.generate_keypair()
    private_key_j, public_key_j = LHH.generate_keypair()
    t1 = time.time()
    for j in range(client_number-1):
        AES_ij = KeyAggrement.keyaggrement(private_key_i, public_key_j)
        # Hash the symmetric key
        AES_ij = str(AES_ij).encode("utf-8")
        AES_ij = KeyAggrement.HashKey(AES_ij)
    t2 = time.time()
    print("key aggrement: ", (t2-t1)*1000)
    print("Outgoing communication: ", 4*2)
    print("Received: ", (4*2+1)*client_number, '\n')# (j, pub_key_j)
    # print(AES_ij)


    # Hash the symmetric key
    keys = public_key_i.x
    Hash = hashlib.sha256()
    Hash.update(str(keys).encode('utf-8'))
    keys = Hash.hexdigest()
    key = keys[:32] 


    # generate the split mask and encrypt the mask
    mash_vector = np.random.random(vector_dimension)
    iv = '1234567887654321'
    # key = AES_ij.hexdigest()
    # print(key[:32])
    for i in range(vector_dimension):
        data = str(mash_vector[i])
        # Encrypt local mask
        data_en = Symmetric_encry.AES_en(key, data, iv)
        # print(data)
        # Decrypt other client's mask
        data_de = Symmetric_encry.AES_de(key, data_en, iv)
        # print(data)
    t3 = time.time()
    print("Symmetric encryption: ", (t3-t2)*1000)
    print("Outgoing communication: ", (len(data_en)+1)*(client_number-1))
    print("Receieved: ", (len(data_en)+1)*(client_number-1), '\n')

    # HH the gradient
    grad = np.random.random(vector_dimension)
    # print(grad)
    t4 = time.time()
    h_i = LHH.HH(grad, Magnification_factor, curve.P256)
    t5 = time.time()
    print("HH: ", (t5-t4)*1000)
    # print(int(np.sum(grad)*100000000)*curve.P256.G)

    # sign the hash value
    r, s = Signing_and_Verifying.sign(str(h_i), private_key_i, hashlib.sha256)
    t6 = time.time()
    print("Sign: ", (t6-t5)*1000)
    print("Outgoing communication: ", 4*8)
    print("Receieved: ", (4*8)*(client_number-1))

    sum = h_i
    # verify
    for i in range(client_number-1):
        valid = Signing_and_Verifying.verifying(str(h_i), public_key_i, hashlib.sha256, (r, s))
        sum += h_i
    h_sum = LHH.HH(grad, Magnification_factor, curve.P256)
    t7 = time.time()
    print("Verify: ", (t7-t6)*1000)