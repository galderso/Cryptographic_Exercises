#Grant alderson
#citations: https://www.geeksforgeeks.org/python-convert-string-to-bytes/
#https://www.geeksforgeeks.org/random-getrandbits-in-python/
#https://www.geeksforgeeks.org/python-pow-function/

#https://www.tutorialspoint.com/python/python_random_getrandbits_method.htm#:~:text=The%20Python%20random.getrandbits%20()%20method%20generates%20a%20non-negative
import random
import hashlib
from Crypto.Cipher import AES
from binascii import unhexlify
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import math
#fast modular exponentiation
def fast(b,e,n):
    #print("enter fast")

    product =1
    binary = bin(e)[2:]
    reversed_binary = binary[::-1]

    for i in reversed_binary:
        if i == '1':
            product=product *b%n
        b=b*b%n

    return product



#Primality testing using the Miller-Rabin algorithm
def prime(p,k=5):
    #print("enter prime")
    if p<2 or p%2 == 0:
        return False
    if p in (2, 3):
        return True
    s=0
    d=p-1
    while d%2 == 0:#d is odd
        s+=1
        d//=2


    for _ in range(k):
        a = random.randint(2, p-2)
        x = pow(a, d, p)

        if x in [1, p - 1]:#x= {1,-1}mod p
            continue

        for _ in range(s-1):#if at any iteration x=-1 mod p continue outer
            x =pow(x, 2,p)
            if x==p-1:
                break
        else:
            return False
    return True



#The extended Euclidean algorithm

def extended(a,b):# r-1 and r-2
    a0=1
    a1=0
    b0=0
    b1=1
    while b!=0:
        quotient= a//b
        a3=a
        a=b
        b=a3%b

        a4 =a0
        a0 =a1
        a1 = a4-quotient*a1
        b2=b0
        b0 =b1
        b1 = b2-quotient*b1

    return a, a0, b0



#deffie hellman 
def hellman():
    #print("enter hellman")
    #generate 1024 size random prime number
    p=createprime()
    g=5
    print("p=",p)

    #generate private keys
    alice =random.randint(2,p-2)
    print("private=",alice)


    #public keys using fast modulr
    alice_public=fast(g,alice,p)
    print("public=",alice_public)

    #enter g^b
    g_b = int(input("Enter g^b: "))


    #create shared key
    shared_dh_key = fast(g_b, alice, p)
    print("shared key:",shared_dh_key)
    shared_dh_key_bytes = shared_dh_key.to_bytes((shared_dh_key.bit_length() + 7) // 8, 'big') 
    hashed_key = hashlib.sha256(shared_dh_key_bytes).digest()
    #print("hashed key", hashed_key)
    #key


    iv = input("Enter IV: ")
    cipher_text = input("Enter Cipher text: ")
    cipher_text = unhexlify(cipher_text)
    iv = unhexlify(iv)

    AES_key = hashed_key[:16]
    cipher = AES.new(AES_key, AES.MODE_CBC, iv)
    plaintext_padded = cipher.decrypt(cipher_text)
    plaintext = unpad(plaintext_padded, AES.block_size)
    print("Decrypted message: ", plaintext.decode('ascii'))




#create prime
def createprime():
    #print("enter createprime")
    while True:

        prime_candidate = random.getrandbits(1024) | (1<<1023)|1# generate random 1024 bits that are odd

        if prime(prime_candidate):#prime?
            if prime((prime_candidate-1)// 2):#strong prime?
                return prime_candidate
        
def RSA():
    p=createprime()
    q=createprime()
    #print("finished primes")
    print("p= ",p)    
    print("q= ",q)

    n=p*q
    eu=(p-1)*(q-1)
    e=65537


    print("n= ",n)
    print("eulers= ",eu)

    _, d, _ = extended(e, eu)#use extended
    print("d= ",d)

    m = input("Enter message: ")
    m_bytes=int.from_bytes(m.encode('utf-8'),byteorder='big')
    encryption=pow(m_bytes,e,n)
    print("encrypted= ",encryption)

    m2 = int(input("Enter message: "))
    decryption=pow(m2,d,n)
    m_message=decryption.to_bytes((decryption.bit_length()+7)// 8,byteorder='big').decode('utf-8')
    print("decryption= ",m_message)

#RSA()
hellman()