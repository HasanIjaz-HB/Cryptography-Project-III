import math
import timeit
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, SHA256, HMAC
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import hashlib, hmac, binascii
import json
import math
import timeit
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Hash import HMAC, SHA256
import random
import re
import json
API_URL = 'http://cryptlygos.pythonanywhere.com'

stuID =  24775
stuID_B = 23699

def key_generation(n,P):
     sA = random.randrange(0,n-1)
     QA = sA*P
     return sA,QA
 
def signature_generation(n,m,P,sA):
    k = random.randrange(1, n-2)
    R = k*P
    r = R.x % n
    temp = m + r.to_bytes((r.bit_length() + 7) // 8,byteorder= 'big')
    h = SHA3_256.new(temp)
    h = int.from_bytes(h.digest(), byteorder='big') % n
    s = (sA*h + k) % n
    return(h,s)


#testarray for id 18007
test=["The world is full of lonely people afraid to make the first move.",
      "I don’t like sand. It’s all coarse, and rough, and irritating. And it gets everywhere.",
      "Hate is baggage. Life’s too short to be pissed off all the time. It’s just not worth it.",
      "Well, sir, it’s this rug I have, it really tied the room together.",
      "Love is like taking a dump, Butters. Sometimes it works itself out. But sometimes, you need to give it a nice hard slimy push."]    

#create a long term key
curve = Curve.get_curve('secp256k1')
n = curve.order
P = curve.generator

#sA_l,QA_l=key_generation(n, P);
sA_l = 47739507727097583103574014533029612368096643715089728534014772436197620809295 #long term key
QA_l = sA_l*P
lkey=QA_l
lpkey=sA_l
print('sA_l:',sA_l)
print('QA_l:',QA_l)
m = str(stuID)
m = str.encode(m)
h,s = signature_generation(n, m, P, sA_l)

####Register Long Term Key

#s, h = SignGen(str(stuID).encode(), curve, sCli_long)
mes = {'ID':stuID, 'H': h, 'S': s, 'LKEY.X': lkey.x, 'LKEY.Y': lkey.y}
response = requests.put('{}/{}'.format(API_URL, "RegLongRqst"), json = mes)
print(response.json())
print("Please enter your code:")
#code is 466773
code = int(input())

mes = {'ID':stuID, 'CODE': code}
response = requests.put('{}/{}'.format(API_URL, "RegLong"), json = mes)
print(response.json())


#Check Status
mes = {'ID_A':stuID, 'H': h, 'S': s}
response = requests.get('{}/{}'.format(API_URL, "Status"), json = mes)
print("Status ", response.json())
    
arraysA = []
arrayQA = []

for i in range(0,10):
    sA,QA  = key_generation(n, P) 
    mes = (str(QA.x)+str(QA.y)).encode()
    arraysA.append(sA)
    arrayQA.append(QA)
    hx, sx = signature_generation(n,mes,P,sA_l)
    #Send Ephemeral keys
    mes = {'ID': stuID, 'KEYID': i , 'QAI.X': QA.x, 'QAI.Y': QA.y, 'Si': sx, 'Hi': hx}
    response = requests.put('{}/{}'.format(API_URL, "SendKey"), json = mes)
    print(response.json())




### Get key of the Student B
mes = {'ID_A': stuID, 'ID_B':stuID_B, 'S': s, 'H': h}
response = requests.get('{}/{}'.format(API_URL, "ReqKey"), json = mes)
res = response.json()
print(res)
i = res['i']
j = res['j']
QBj = Point(res['QBJ.X'] , res['QBJ.Y'], curve)

#mesg to send
mesg = "You can dance, you can jive"
print("This is my message:", mesg)
#calculations from pdf
T = arraysA[i]*QBj
U = str(T.x)+str(T.y)+"NoNeedT oRunAndHide"
U = str.encode(U)
K_ENC = SHA3_256.new(U)
K_ENC = K_ENC.digest()
K_MAC = SHA3_256.new(K_ENC)
K_MAC = K_MAC.digest()

# Encyption
cipher = AES.new(K_ENC, AES.MODE_CTR)
ctext = str.encode(mesg)
print("ctext:",ctext)

#hmac calculation is missing

ctext = cipher.nonce + cipher.encrypt(ctext) + hmac


msg = int.from_bytes(ctext, byteorder="big")

### Send message to student B
mes = {'ID_A': stuID, 'ID_B':stuID_B, 'I': i, 'J':j, 'MSG': msg}
response = requests.put('{}/{}'.format(API_URL, "SendMsg"), json = mes)
print(response.json())

## Get your message
mes = {'ID_A': stuID, 'S': s, 'H': h}
response = requests.get('{}/{}'.format(API_URL, "ReqMsg_PH3"), json = mes)
print(response.json())
if(response.ok): ## Decrypt message
    res = response.json()
    mes = res['MSG']
    i = res['KEYID']
    print("KEYID:",i)
    QBj = Point(res['QBJ.X'] , res['QBJ.Y'], curve)
    sa_m = arraysA[i]
    print("sA for this message:",sa_m)
    mes = mes.to_bytes((mes.bit_length()+7)//8, byteorder='big')
    print("msg:", mes)
    T = sa_m * QBj
    print("T:",T)
    U = str(T.x)+str(T.y)+"NoNeedT oRunAndHide"
    print("U:",U)
    U = str.encode(U)
    print("U_encode:",U)
    K_ENC = SHA3_256.new(U)
    K_ENC = K_ENC.digest()
    print("kenc:",K_ENC)
    K_MAC = SHA3_256.new(K_ENC)
    K_MAC = K_MAC.digest()
    print("k_mac:",K_MAC)
    
    #decrypt
    print("message:",mes)
    cipher = AES.new(K_ENC, AES.MODE_CTR,  nonce=mes[:8])
    dtext = cipher.decrypt(mes[8:-32]).decode()
    print("ciphertext:", dtext) 
    
    
    #calculate hmac
    
    print("hmac:",hmac)
        
    
    
    
    
    
    
    
    
#####Reset Ephemeral Keys
# =============================================================================
# s, h = SignGen("18007".encode(), curve, sCli_long)
# mes = {'ID': stuID, 'S': s, 'H': h}
# print(mes)
# response = requests.get('{}/{}'.format(API_URL, "RstEKey"), json = mes)
# print(response.json())
# 
# 
# #####Reset Long Term Key
# mes = {'ID': stuID}
# response = requests.get('{}/{}'.format(API_URL, "RstLongRqst"), json = mes)
# print(response.json())
# code = int(input())
# 
# mes = {'ID': stuID ,'CODE': code}
# response = requests.get('{}/{}'.format(API_URL, "RstLong"), json = mes)
# print(response.json())
# ============================================================================