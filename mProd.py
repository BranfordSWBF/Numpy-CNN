import time
import random
import pickle
import threading
import seal
import numpy as np
from seal import ChooserEvaluator, \
	Ciphertext, \
	Decryptor, \
	Encryptor, \
	EncryptionParameters, \
	Evaluator, \
	IntegerEncoder, \
	FractionalEncoder, \
	KeyGenerator, \
	MemoryPoolHandle, \
	Plaintext, \
	SEALContext, \
	EvaluationKeys, \
	GaloisKeys, \
	PolyCRTBuilder, \
	ChooserEncoder, \
	ChooserEvaluator, \
	ChooserPoly

parms = EncryptionParameters()
parms.set_poly_modulus("1x^4096 + 1")
parms.set_coeff_modulus(seal.coeff_modulus_128(4096))
# Note that 40961 is a prime number and 2*4096 divides 40960.
parms.set_plain_modulus(40961)
context = SEALContext(parms)

keygen = KeyGenerator(context)
public_key = keygen.public_key()
secret_key = keygen.secret_key()

def inner_product(cypher1, cypher2):
	# We also set up an Encryptor, Evaluator, and Decryptor here.
	evaluator = Evaluator(context)
	decryptor = Decryptor(context, secret_key)

	for i in range(len(cypher1)):
		evaluator.multiply(cypher1[i], cypher2[i])

	encrypted_result = Ciphertext()
	evaluator.add_many(cypher1, encrypted_result)

	return encrypted_result

def matrixProduct(m1, m2):
    m1_r, m1_c, m2_c, m2_r = len(m1), len(m1[0]), len(m2), len(m2[0])
    prod = [[0] * m2_c for i in range(m1_r)]
    print(m1_r, m1_c, m2_r, m2_c)
    assert m1_c == m2_r
    for i in range(m1_r):
        for j in range(m2_c):
            prod[i][j] = inner_product(m1[i], m2[j])
    return prod

# taking too long rn, need to use batch encryption; flatten then reshape
def encryptMatrix(m):
    r, c = len(m), len(m[0])
    flattened = np.ravel(m)
    crtbuilder = PolyCRTBuilder(context)
    plain_matrix = Plaintext()
    crtbuilder.compose(flattened, plain_matrix)
    cm = Ciphertext()
    encryptor.encrypt(plain_matrix, cm)
    # cm = [[0] * len(m[0]) for i in range(len(m))]
    # for i in range(len(m)):
    #     for j in range(len(m[0])):
    #         cm[i][j] = Ciphertext(parms)
    #         encryptor.encrypt(encoder.encode(m[i][j]), cm[i][j])
    print(cm)
    np.reshape(cm, (r, c))
    return cm

# v1 = [3.1, 4.159, 2.65, 3.5897, 9.3, 2.3, 8.46, 2.64, 3.383, 2.795]
# v2 = [0.1, 0.05, 0.05, 0.2, 0.05, 0.3, 0.1, 0.025, 0.075, 0.05]

encryptor = Encryptor(context, public_key)
encoder = FractionalEncoder(context.plain_modulus(), context.poly_modulus(), 64, 32, 3)


def decryptMatrix(cm):
    r, c = len(cm), len(cm[0])
    m = [[0] * c for i in range(r)]
    decryptor = Decryptor(context, secret_key)
    plain_result = Plaintext()
    for i in range(r):
        for j in range(c):
            decryptor.decrypt(cm[i][j], plain_result)
            m[i][j] = encoder.decode(plain_result)
    return m

# m1 = [[1,3,2],[4,3,1]]
# m2 = [[2,2,1]]
# cm1, cm2 = encryptMatrix(m1), encryptMatrix(m2)
# cm = matrixProduct(cm1, cm2)
# print(decryptMatrix(cm))

# need to multiply encrypted matrix by encrypted vector