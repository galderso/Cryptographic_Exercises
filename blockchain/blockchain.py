import hashlib
while True:
    q=input("Enter quote: ")
    quote=q.encode('ascii')

    nonce=int(input("Enter nonce: "))
    nonce_bytes=nonce.to_bytes((nonce.bit_length()+ 7) // 8, byteorder='big')

    previous_hash=input("Enter previous: ")
    previous_hash_bytes = bytes.fromhex(previous_hash)


    target=1 << (256-24)

    
    nonce=0
    while True:
        nonce_bytes=nonce.to_bytes((nonce.bit_length()+7)// 8,byteorder='big')
        concatenated=previous_hash_bytes+nonce_bytes+quote
        
        block_hash=hashlib.sha256(concatenated).hexdigest()
        if int(block_hash,16) < target:
            break
        
        nonce+=1


    print("Valid Nonce: ",nonce)
    print("Hash: ",block_hash)
