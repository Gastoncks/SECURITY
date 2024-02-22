#!/usr/bin/env python3


help_txt = """
 provisioning = prend un fichier en clair (nvm_en_clair.txt)"
           puis chiffre et authentifie et stocke le résultat dans deux fichiers:
           nvm.txt qui represente la NVM protégée ainsi que la signature qui permettra d'authentifier
 secure boot  = prend la NVM protégée, vérifie son authenticité, la déchiffre puis copie cette donnée dans la mémoire de travail 
 du processeur Hôte, puis ordonne au processeur Hote de commencer ses opérations
 """

import sys
from Crypto.Cipher import AES
from Crypto.Hash import SHA3_256
from hashlib import sha512

def usage():
  if len (sys.argv) != 2:
      print ("erreur, l'usage est : "+sys.argv[0] + " <numero du scenario>")
      exit(1)

usage()

plaintext = b"totototototototo"
plaintext2 = b"tatatatatatatata"
print (type(plaintext))
key = b"Sixteen byte yey"

def chiffrement(plaintext,key):
  object  = AES.new(key, AES.MODE_ECB)
  ciphertext = object.encrypt(plaintext)
  return ciphertext

def dechiffrement(ciphertext,key):
   object  = AES.new(key, AES.MODE_ECB)
   plaintext =  object.decrypt(ciphertext)
   return plaintext

def hashage(plaintext):
   h_obj = SHA3_256.new()
   h_obj.update(plaintext)
   return h_obj.hexdigest()

def gen_keypair():
    from Crypto.PublicKey import RSA
    keyPair = RSA.generate(2048)
    print(f"Public key:  (n={hex(keyPair.n)}, e={hex(keyPair.e)})")
    print ("\n")
    print(f"Private key: (n={hex(keyPair.n)}, d={hex(keyPair.d)})")
    return keyPair

def signature(keypair, plaintext):
    hash = int.from_bytes(sha512(plaintext).digest(), byteorder='big')
    signature = pow(hash, keypair.d, keypair.n)
    return signature

def verif_signature(keypair, signature, plaintext):
    hash = int.from_bytes(sha512(plaintext).digest(), byteorder='big')
    hashFromSignature = pow(signature, keypair.e, keypair.n)
    return hash, hashFromSignature


scenario = int(sys.argv[1])

if (scenario == 0):  #on faire seulement un chiffrement de la nvm
    print ("protection:  chiffrement seulement")
    print (plaintext)

    ciphertext = chiffrement(plaintext,key)
    print("ciphertext: ", ciphertext)

    plaintext_sboot = dechiffrement(ciphertext,key)
    print("plaintext:  ",plaintext_sboot)
    
    if plaintext_sboot == plaintext:
       print ("succès")
    else:
        print ("échec!!")
        exit(1)

elif  (scenario ==1):  #on fait seulement une intégrité
    print ("protection:  intégrité seulement")
    print (plaintext)

    hexdigest = hashage(plaintext)
    print("Hexdigest :",hexdigest)

    plaintext_sboot = plaintext
    hexdigest_sboot = hashage(plaintext_sboot)
    print("Hexdigest Sboot:",hexdigest_sboot)

    if hexdigest == hexdigest_sboot:
        print("succées")
    else:
        print("échec...")
        exit(1)

elif  (scenario ==2):  #on fait seulement un chiffrement  + intégrité
    print ("protection:  chiffrement et intégrité")
    print(plaintext)

    hexdigest = hashage(plaintext)
    print("hexdigest :",hexdigest)

    ciphertext = chiffrement(plaintext,key)
    print("ciphertext: ", ciphertext)

    plaintext_sboot = dechiffrement(ciphertext,key)
    print("plaintext sboot:  ",plaintext_sboot)

    hexdigest_sboot = hashage(plaintext_sboot)
    print("hexdigest sboot :",hexdigest_sboot)

    if hexdigest == hexdigest_sboot and plaintext == plaintext_sboot:
        print("succées")
    elif hexdigest != hexdigest_sboot and plaintext == plaintext_sboot:
        print("échéc... probléme de hashage")
        exit(2)
    elif hexdigest != hexdigest_sboot and plaintext != plaintext_sboot:
        print("échec total...")
        exit(1)
       
elif  (scenario ==3):  #on fait une signature avec un algo asymétrique (candidats : rsa)
    print ("protection:  signature RSA")
    keypair = gen_keypair()
    print ("\n")

    signature_value = signature(keypair)
    hash, hashFromSignature = verif_signature(keypair, signature_value)
    print("Signature valid:", hash == hashFromSignature)

elif  (scenario == 4):  #on fait une signature avec un algo asymétrique RSA + un chiffrement
    print ("protection:  signature RSA  + chiffrement")
    keypair = gen_keypair()
    print("plaintext :", plaintext)
    print("\n")

    signature_value = signature(keypair, plaintext)
    print("Signature:", hex(signature_value))
    print("\n")

    ciphertext = chiffrement(plaintext,key)
    print("ciphertext: ", ciphertext)
    plaintext_sboot = dechiffrement(ciphertext,key)
    print("plaintext sboot:  ",plaintext_sboot)
    print("\n")

    hash, hashFromSignature = verif_signature(keypair, signature_value, plaintext_sboot)

    if plaintext == plaintext_sboot and hash == hashFromSignature:
        print("succées!")
    elif plaintext == plaintext_sboot and hash != hashFromSignature:
        print("échec...problème de signature")
        exit(1)
    else:
        print("échec total...")
        exit(1)

elif (scenario == 5): #on fait une signature avec un algo asymétrique ECDSA
    print("protection:  signature ECDSA")

    

    
