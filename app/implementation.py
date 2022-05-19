import random

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def multiplicative_inverse(e, phi):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_phi = phi

    while e > 0:
        temp1 = temp_phi//e
        temp2 = temp_phi - temp1 * e
        temp_phi = e
        e = temp2

        x = x2 - temp1 * x1
        y = d - temp1 * y1

        x2 = x1
        x1 = x
        d = y1
        y1 = y

    if temp_phi == 1:
        return d + phi

def generate_key_pair(p, q):
    n = p * q
    
    phi = (p-1) * (q-1)

    e = random.randrange(1, phi)

    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    d = multiplicative_inverse(e, phi)

    return (e, d, n)


def encrypt(pk, plaintext):
    key, n = pk
    cipher = [str(pow(ord(char), key, n)) for char in plaintext]
    return ','.join(cipher)


def decrypt(pk, ciphertext):
    key, n = pk
    ciphertext = ciphertext.split(',')
    aux = [str(pow(int(char), key, n)) for char in ciphertext]
    plain = [chr(int(char2)) for char2 in aux]
    return ''.join(plain)

def generate_p_and_q():
    prime_list = []
    x = 3
    y = 999
    for n in range(x, y):
        is_prime = True

        for num in range(2, n):
            if n % num == 0:
                is_prime = False

        if is_prime:
            prime_list.append(n)
    
    p = random.choice(prime_list)
    prime_list.remove(p)
    q = random.choice(prime_list)

    return (p,q)