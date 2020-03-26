
import time
import random
import pickle
import threading
import seal
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

def print_matrix(matrix):
    print("")

    # We're not going to print every column of the matrix (there are 2048). Instead
    # print this many slots from beginning and end of the matrix.
    print_size = 4
    current_line = "    ["
    for i in range(print_size):
        current_line += ((str)(matrix[i]) + ", ")
    current_line += ("..., ")
    for i in range(row_size - print_size, row_size):
        current_line += ((str)(matrix[i]))
        if i != row_size-1: current_line += ", "
        else: current_line += "]"
    print(current_line)

    current_line = "    ["
    for i in range(row_size, row_size + print_size):
        current_line += ((str)(matrix[i]) + ", ")
    current_line += ("..., ")
    for i in range(2*row_size - print_size, 2*row_size):
        current_line += ((str)(matrix[i]))
        if i != 2*row_size-1: current_line += ", "
        else: current_line += "]"
    print(current_line)
    print("")

parms = EncryptionParameters()

parms.set_poly_modulus("1x^4096 + 1")
parms.set_coeff_modulus(seal.coeff_modulus_128(4096))

# Note that 40961 is a prime number and 2*4096 divides 40960.
parms.set_plain_modulus(40961)

context = SEALContext(parms)
keygen = KeyGenerator(context)
public_key = keygen.public_key()
secret_key = keygen.secret_key()
gal_keys = GaloisKeys()
keygen.generate_galois_keys(30, gal_keys)

# Since we are going to do some multiplications we will also relinearize.
ev_keys = EvaluationKeys()
keygen.generate_evaluation_keys(30, ev_keys)

# We also set up an Encryptor, Evaluator, and Decryptor here.
encryptor = Encryptor(context, public_key)
evaluator = Evaluator(context)
decryptor = Decryptor(context, secret_key)

# Batching is done through an instance of the PolyCRTBuilder class so need
# to start by constructing one.
crtbuilder = PolyCRTBuilder(context)
slot_count = (int)(crtbuilder.slot_count())
row_size = (int)(slot_count / 2)

pod_matrix = [1,2,3,4,8,-4,3,2]
plain_matrix = Plaintext()
crtbuilder.compose(pod_matrix, plain_matrix)
encrypted_matrix = Ciphertext()
print("Encrypting: ")
encryptor.encrypt(plain_matrix, encrypted_matrix)

# the multiplication resolves the problem of having extraneous 0's in the middle after rotation
pod_vector = [7,3,5,1] * (2048//4)
plain_vector = Plaintext()
crtbuilder.compose(pod_vector, plain_vector)
encrypted_vector = Ciphertext()
encryptor.encrypt(plain_vector, encrypted_vector)
# evaluator.multiply(encrypted_matrix, encrypted_vector)

# plain_result = Plaintext()
# decryptor.decrypt(encrypted_matrix, plain_result)
# crtbuilder.decompose(plain_result)
# pod_result = [plain_result.coeff_at(i) for i in range(plain_result.coeff_count())]
# print_matrix(pod_result)

import copy

# length needs to be a power of 2
def rotateAdd(ct, length, lowerbound=1):
    res = Plaintext()
    while length > lowerbound:
        length //= 2
        oldCt = copy.deepcopy(ct)
        evaluator.rotate_rows(ct, length, gal_keys)
        evaluator.add(ct, oldCt)
        print(length)
    decryptor.decrypt(ct, res)
    crtbuilder.decompose(res)
    #print_matrix([res.coeff_at(i) for i in range(res.coeff_count())])
    return [res.coeff_at(i) for i in range(lowerbound)]

# print(rotateAdd(encrypted_matrix, 8))

def sumDiagProducts(diagMatrix, ct_vector):
    template = [0] * len(diagMatrix[0])
    plain_matrix = Plaintext()
    crtbuilder.compose(template, plain_matrix)
    accumulated = Ciphertext()
    encryptor.encrypt(plain_matrix, accumulated)
    for i, row in enumerate(diagMatrix):
        print("_____________________________")
        print(i, row)
        temp = copy.deepcopy(ct_vector)
        # the last number needs to wrap around! 
        evaluator.rotate_rows(temp, i, gal_keys)

        decryptor.decrypt(temp, plain_matrix)
        crtbuilder.decompose(plain_matrix)
        print_matrix([plain_matrix.coeff_at(i) for i in range(plain_matrix.coeff_count())])

        encodedRow = Plaintext()
        crtbuilder.compose(row, encodedRow)
        evaluator.multiply_plain(temp, encodedRow)
        evaluator.add(accumulated, temp)
        decryptor.decrypt(accumulated, plain_matrix)
        crtbuilder.decompose(plain_matrix)
        print([plain_matrix.coeff_at(i) for i in range(4)])
    return accumulated

# akin to gazelle hybrid method
def extractDiagonals(rectMatrix):
    n_o, n_i = len(rectMatrix), len(rectMatrix[0])
    diagonals = [[0] * n_i for i in range(n_o)]
    for i in range(n_o):
        x = 0
        for j in range(i, i + n_i):
            diagonals[i][x] = rectMatrix[x % n_o][j % n_i]
            x += 1
    return diagonals

M = [[1,2,3,4],[5,5,5,5]]
_M = extractDiagonals(M)
s = sumDiagProducts(_M, encrypted_vector)
print(rotateAdd(s, 4, 2))


#print_matrix(M)
#print(getCRTchunks(M))
#print(extractDiagonals(M))


