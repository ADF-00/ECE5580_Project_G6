
cr_constants = [0x00000000000000f0,
                0x00000000000000e1,
                0x00000000000000d2,
                0x00000000000000c3,
                0x00000000000000b4,
                0x00000000000000a5,
                0x0000000000000096,
                0x0000000000000087,
                0x0000000000000078,
                0x0000000000000069,
                0x000000000000005a,
                0x000000000000004b]

mask = 0xffffffffffffffff


key_size = 128
block_size = 128
pa = 12
pb = 8

def ROR(x, n):
    temp1 = x >> n
    temp2 = x << (64 - n)
    temp2 = temp2 & mask
    return temp1 | temp2


def pc(i, x2):
    #print("pc")
    return x2 ^^ cr_constants[i]

def ps(x0,x1,x2,x3,x4):
    #line1
    x0 = x0 ^^ x4
    x4 = x4 ^^ x3
    x2 = x2 ^^ x1
    #line2
    t0 = x0
    t1 = x1
    t2 = x2
    t3 = x3
    t4 = x4
    #line3
    t0 = t0 ^^ mask
    t1 = t1 ^^ mask
    t2 = t2 ^^ mask
    t3 = t3 ^^ mask
    t4 = t4 ^^ mask
    #line4
    t0 = t0 & x1
    t1 = t1 & x2
    t2 = t2 & x3
    t3 = t3 & x4
    t4 = t4 & x0
    #line5
    x0 = x0 ^^ t1
    x1 = x1 ^^ t2
    x2 = x2 ^^ t3
    x3 = x3 ^^ t4
    x4 = x4 ^^ t0
    #line6
    x1 = x1 ^^ x0
    x0 = x0 ^^ x4
    x3 = x3 ^^ x2
    x2 = x2 ^^ mask
    #print("ps")
    return x0,x1,x2,x3,x4

def pl(x0,x1,x2,x3,x4):

    t1 = ROR(x0, 19)#x0 >> 19
    t2 = ROR(x0, 28)#x0 >> 28
    x0 = (x0 ^^ t1) ^^ t2

    t1 = ROR(x1 ,61)#x1 >> 61
    t2 = ROR(x1 ,39)#x1 >> 39
    x1 = (x1 ^^ t1) ^^ t2

    t1 = ROR(x2 ,1)#x2 >> 1
    t2 = ROR(x2 ,6)#x2 >> 6
    x2 = (x2 ^^ t1) ^^ t2

    t1 = ROR(x3 ,10)#x3 >> 10
    t2 = ROR(x3 ,17)#x3 >> 17
    x3 = (x3 ^^ t1) ^^ t2

    t1 = ROR(x4 ,7)#x4 >> 7
    t2 = ROR(x4 ,41)#x4 >> 41
    x4 = (x4 ^^ t1) ^^ t2
    #print("pl")
    return x0,x1,x2,x3,x4

def permutate(p, rounds):
    temp = hex(p)
    x0 = temp[0:18]   #dividing them into words
    x1 = temp[18:34]
    x2 = temp[34:50]
    x3 = temp[50:66]
    x4 = temp[66:82]

    x0 = ZZ(x0)         #converting them to int
    x1 = ZZ('0x' + x1)
    x2 = ZZ('0x' + x2)
    x3 = ZZ('0x' + x3)
    x4 = ZZ('0x' + x4)

    for round_count in range(rounds):   #doing the actual permutations
        if rounds == pb:
            x2 = pc(round_count + 4, x2)
        elif rounds == pa:
            x2 = pc(round_count, x2)
        x0,x1,x2,x3,x4 = ps(x0,x1,x2,x3,x4)
        x0,x1,x2,x3,x4 = pl(x0,x1,x2,x3,x4)
    
    return format(x0, '#016x')[2:] + format(x1, '#016x')[2:] + format(x2, '#016x')[2:] + format(x3, '#016x')[2:] + format(x4, '#016x')[2:]


def str_to_hex(string):
    new_hex = ""
    for i in range(len(string)):
        new_hex += hex(ord(string[i]))[2:]
    return new_hex

def hex_to_str(string):
    byte_string = bytes.fromhex(string)
    new_str = byte_string.decode("ASCII")
    return new_str


#The Initilization

def init(key, nonce):
    IV =  "0x80800c0800000000" + str(hex(key))[2:] + str(hex(nonce))[2:]
    S = ZZ('0x'+ permutate(ZZ(IV), pa)) ^^ key 
    return S

#Asociated Data Encryption --------------------------------------------------------------------------------------

def process_associated(Associated, S):

    if Associated is not None:#If associated data
        bit_count = len(hex(Associated)[2:]) * 4

        Associated_Block_Count = (bit_count / block_size).ceil()
        
        padding_needed = (Associated_Block_Count * block_size) - bit_count
        #print(padding_needed)
        if padding_needed != 0:#if uneven, add padding
            Associated = Associated << 1
            Associated += 1 #apend 1 bit
            Associated = Associated << padding_needed - 1 #append rest of 0s


        for i in range(Associated_Block_Count):

            temp = hex(S)[2:]               #prep sr and sc
            Sr = temp[:block_size/4]
            Sc = temp[block_size/4:]

            Current_Block = ZZ('0x' + hex(Associated)[2:][i*block_size/4:(i+1)*block_size/4]) #grab current A block

            Sr = ZZ('0x' + Sr) ^^ Current_Block #Actual Processing
            temp2 = ZZ('0x' + hex(Sr)[2:] + Aso_Sc)
            
            S = permutate(temp2, pb)
            S = ZZ('0x' + S)


    S = S ^^ 1 #Domain Seperation Constant
    return S


#Plaintext Encryption ------------------------------------------------------------------------------------------
def encrpytion(plaintext, S):
    plaintext = str_to_hex(plaintext)

    bit_count = len(plaintext) * 4
    Encryption_Block_Count = (bit_count / block_size).ceil()
    padding_needed = (Encryption_Block_Count * block_size) - bit_count

    #print("plain")
    #print(plaintext)

    plaintext = ZZ('0x' + plaintext)
    if padding_needed != 0:#if uneven, add padding
        plaintext = plaintext << 1
        plaintext += 1 #apend 1 bit
        plaintext = plaintext << padding_needed - 1 #append rest of 0s

    ciphertext = ""
    plaintext = hex(plaintext)
    for i in range(Encryption_Block_Count):

        temp = hex(S)[2:]               #prep sr and sc
        Sr = temp[:block_size/4]
        Sc = temp[block_size/4:]

        Current_Block = ZZ('0x' + plaintext[2:][i*block_size/4:(i+1)*block_size/4]) #grab current plaintext block

        cipher_block = hex(ZZ('0x' + Sr) ^^ Current_Block)[2:]
        ciphertext += cipher_block
        if i != Encryption_Block_Count-1:
            temp2 = ZZ('0x' + cipher_block + Sc)
            S = permutate(temp2,pb)
            S = ZZ('0x' + S)
            
        else:
            S = ZZ('0x' + cipher_block + Sc)
            ciphertext = ciphertext[0:(bit_count/4)]#truncate at the last one
    
    return S, ciphertext



#Ciphertext Decryption ------------------------------------------------------------------------------------------
def decryption(ciphertext, S):
    bit_count = len(ciphertext) * 4
    Decryption_Block_Count = (bit_count / block_size).ceil()
    extra_length = (Decryption_Block_Count * block_size) - bit_count


    plaintext = ""
    for i in range(Decryption_Block_Count):

        temp = hex(S)[2:]               #prep sr and sc
        Sr = temp[:block_size/4]
        Sc = temp[block_size/4:]

        Current_Block = ZZ('0x' + ciphertext[i*block_size/4:(i+1)*block_size/4]) #grab current ciphertext block

        if i == Decryption_Block_Count-1:#do something different for the last one
            Srtemp = Sr[:(block_size-extra_length) / 4]
            plain_block = (ZZ('0x' + Srtemp) ^^ Current_Block)
            plaintext += hex(plain_block)[2:]

            if extra_length != 0:#if uneven, add padding
                plain_block = plain_block << 1
                plain_block += 1 #apend 1 bit
                plain_block = plain_block << extra_length - 1 #append rest of 0s
            
            S = ZZ('0x' + Sr) ^^ plain_block
            S = ZZ(hex(S) + Sc)
            break

        plain_block = hex(ZZ('0x' + Sr) ^^ Current_Block)[2:]
        
        while (len(plain_block) < len(Sr)):#for xor shortening, need to put more often mabye
            plain_block = '0' + plain_block
        
        plaintext += plain_block

        temp2 = ZZ(hex(Current_Block) + Sc)
        S = permutate(temp2,pb)
        S = ZZ('0x' + S)
    return S, plaintext



#Finalization
def finalization(key, S):
    temp = key
    temp = temp << (64) #append rest of 0s

    S = S ^^ temp
    S = permutate(S, pa)
    Tag = ZZ('0x' + S[48:]) ^^ key
    return Tag
    #print(hex(Tag)[2:])


    #Stest = Stest ^^ temp
    #Stest = permutate(Stest, pa)
    #Tag = ZZ('0x' + Stest[48:]) ^^ key
    #print(hex(Tag)[2:])


def encrypt(key, nonce, associated, plaintext):
    
    state = init(key, nonce)
    state = process_associated(associated, state)
    state, ciphertext = encrpytion(plaintext, state)

    tag = finalization(key, state)
    return ciphertext#, tag


def decrypt(key, nonce, associated, ciphertext):

    state = init(key, nonce)
    state = process_associated(associated, state)
    state, plaintext = decryption(ciphertext, state)

    tag = finalization(key, state)
    return plaintext


if __name__ == "__main__":
    #These 3 values communicatd in some other way between parties
    key = 0x55555555555555555555555555555555
    nonce = 0x11111111111111111111111111111111
    associated = 0x121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212
    
    #Plaintext only known and used by encryptor
    plaintext = "Lorem ipsum dolor sit amet"

    print("----------PLAINTEXT:")
    print(plaintext)
    print(str_to_hex(plaintext))

    #Encrypting
    ciphertext = encrypt(key, nonce, associated, plaintext)

    #Ciphertext as seen in transit
    print("-----------CIPHERTEXT: ")
    print(ciphertext)

    #Decrypting
    resulting_plaintext = decrypt(key, nonce, associated, ciphertext)

    #Plaintext the decryptor results in
    print("----------RESULTING PLAINTEXT:")
    print(hex_to_str(resulting_plaintext))
    print(resulting_plaintext)


