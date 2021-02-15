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
API_URL = 'http://cryptlygos.pythonanywhere.com'

stuID =  24775
stuID_B = 18007

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

arraysA = [112184962276357808309568989833684271625049885675934630372866963801085964072493, 33584358211224784840202436168184815276628420769928064070743091943999268712786, 40726025470150288236659679056057720728221590797096143441172221355007043466450, 101381661083810846279577444932520014627629962066304212964928490092267766004985, 100594443061284668939798088235910436479618491421149817836807710501808402577492, 103568589245276105481949302052504652358633223871875756153798369465269147623829, 100051855146607783942326414928800209257532033065159727699014006828344258666423, 105040970101702829213395228783284792201809442061444673860747455870055614779455, 90156357612886126425473480757697158114559706965764952860166983492293539640483, 635398702918226938233284394615151078835074431754073593651417155565356312859]
arrayQAx = [82130022647859882453134084051369598210823951790545515364285068773611035505062, 51140706821905322921805595227209017018799214209971934540801379729473715539128, 49432472692951339492988178726505370500642699982361951313863393202596519914764, 36018325104317080292711623581486586963933141534504250517355266336334872881775, 76692236566180327558062509272400907882990103538569245665502423108051513335006, 69244633031946208542865994268283620303066389860002324026838412654858935857089, 60912054363237728725479112436389557995283036613828053875989391141033721671154, 9777050861158665235931399469284756599748691198285459487242387650264524106086, 71550389124668400681353157799625559428935445146334133779133788925648770731366, 95236147036073182418341514866602126427742987229922482216352098259662503571995]
arrayQAy = [99978483075519520341321215838600373635619019340293769668813125239291817052190, 109176970583477354468613775592241268156447296020122447619846616252849971527226, 41332704556124677749576587514370939479369122228554359024467723589101993498497, 111937169526343050247843961739629074374183481131752761679441414840787470387010, 31521753310428267762560716570334134560699001095409851645874368613812130826067, 83285583670825079302361649195684356772932386767124262353380806840970324007896, 66326982281265332508620837991901241925785044086964866582111351960359855191393, 5717418184376653044842346172847011511487124169152806246338268537374033277405, 34439977629883966899844059601494016249411403363018406998878545235430372004112, 45115106056023629667663131952612957462385127590246861803653084571856409210418]


for i in range(0,10):
    #sA,QA  = key_generation(n, P) 
    QA = arraysA[i]*P
    mes = (str(QA.x)+str(QA.y)).encode()
    # arraysA.append(sA)
    # arrayQAx.append(QA.x)
    # arrayQAy.append(QA.y)
    hx, sx = signature_generation(n,mes,P,sA_l)
    #Send Ephemeral keys
    mes = {'ID': stuID, 'KEYID': i , 'QAI.X': QA.x, 'QAI.Y': QA.y, 'Si': sx, 'Hi': hx}
    response = requests.put('{}/{}'.format(API_URL, "SendKey"), json = mes)
    print(response.json())


### Get key of the Student B
m = str(stuID_B)
m = str.encode(m)
h1,s1 = signature_generation(n, m, P, sA_l)
mes = {'ID_A': stuID, 'ID_B':stuID_B, 'S': s1, 'H': h1}

response = requests.get('{}/{}'.format(API_URL, "ReqKey"), json = mes)
res = response.json()
print(res)
i = int(res['i'])
j = res['j']
QBj = Point(res['QBJ.x'] , res['QBJ.y'], curve)


#mesg to send
#mesg = "You can dance, you can jive"
#print("This is my message:", mesg)

for i in range(len(test)):
    mesg = test[i]
    print("This is my message:", mesg)
    #calculations from pdf
    T = arraysA[i]*QBj
    U = str(T.x)+str(T.y)+"NoNeedToRunAndHide"
    U = str.encode(U)
    K_ENC = SHA3_256.new(U)
    K_ENC = K_ENC.digest()
    K_MAC = SHA3_256.new(K_ENC)
    K_MAC = K_MAC.digest()

    # Encyption
    cipher = AES.new(K_ENC, AES.MODE_CTR)
    ctext=str.encode(mesg)
    ctext=cipher.encrypt(ctext)

    #hmac calculation 
    hmac=HMAC.new(K_MAC,digestmod=SHA256)
    hmac=hmac.update(ctext)
    hmac=hmac.digest()
    msg = cipher.nonce + ctext + hmac
    msg = int.from_bytes(msg, byteorder="big")

    ### Send message to student B
    mes = {'ID_A': stuID, 'ID_B':stuID_B, 'I': i, 'J':j, 'MSG': msg}
    response = requests.put('{}/{}'.format(API_URL, "SendMsg"), json = mes)
    print(response.json())

'''
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
    U = str(T.x)+str(T.y)+"NoNeedToRunAndHide"
    print("U:",U)
    U = str.encode(U)
    print("U_encode:",U)
    K_ENC = SHA3_256.new(U)
    K_ENC = K_ENC.digest()
    print("kenc:",K_ENC)
    K_MAC = SHA3_256.new(K_ENC)
    K_MAC = K_MAC.digest()
    print("k_mac:",K_MAC)
    
    #decrypted msg
    print("message:",mes)
    cipher = AES.new(K_ENC, AES.MODE_CTR, nonce=mes[0:8])
    dtext = cipher.decrypt(mes[8:-32]).decode()
    #dtext = str(dtext)
    print("ciphertext:", dtext) 
    
    #hmac calculation
    temp = mes[8:len(mes)-32]
    hmac2=HMAC.new(K_MAC,digestmod=SHA256)
    hmac2=hmac2.update(temp)
    hmac2=hmac2.digest()
    print("hmac:",hmac2)
    
 

''' 
         

#####Reset Ephemeral Keys
'''
#s, h = SignGen("18007".encode(), curve, sCli_long)
mes = {'ID': stuID, 'S': s, 'H': h}
print(mes)
response = requests.get('{}/{}'.format(API_URL, "RstEKey"), json = mes)
print(response.json())

'''

'''
#####Reset Long Term Key
mes = {'ID': stuID}
response = requests.get('{}/{}'.format(API_URL, "RstLongRqst"), json = mes)
print(response.json())
code = int(input())

mes = {'ID': stuID ,'CODE': code}
response = requests.get('{}/{}'.format(API_URL, "RstLong"), json = mes)
print(response.json())

'''