#!/usr/bin/python
# -*- encoding: utf-8 -*-
# Example barebones file encryption application using envelope encryption from Alibaba Cloud's KMS.
# This script assumes a user has already generated a CMK and has access to the ID of the CMK in order to use it.
import sys
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from credentials import ACCESS_KEY_ID, ACCESS_KEY_SECRET, REGION, CMK_ID 
from aliyunsdkcore.client import AcsClient
from aliyunsdkkms.request.v20160120 import EncryptRequest, GenerateDataKeyRequest
    
# Instantiate an AliCloud client object
CLIENT = AcsClient(ACCESS_KEY_ID, ACCESS_KEY_SECRET, REGION)

# Generate Data Keys and perform local file encryption using a Data Key.
# Data Keys are created using Alibaba Cloud's GenerateDataKey API, which returns a plaintext and encrypted copy of a Data Key. 
# Returns ciphertext, an encrypted copy of the Data Key and the encryption context
def envelope_encrypt(cmk_id, plainText):
    request = GenerateDataKeyRequest.GenerateDataKeyRequest()
    
    # Set parameters for CMK ID, JSON format, connection over TLS and key specification 
    request.set_KeyId(cmk_id)
    request.set_KeySpec('AES_256')
    request.set_accept_format('json')
    request.set_protocol_type('https')
    request.set_NumberOfBytes(32)

    # Set the encryption context as a parameter. This does not need to be secret.   
    # e.g. i'm using the author, publication year and publisher to create the encryption context
    context = '{"author":"lewis carrol", "year":"1865", "publisher":"project gutenberg"}'   
    request.set_EncryptionContext(context)

    # Call the Alibaba Cloud GenerateDataKey API  
    # Response stored in mutable object which can later be zero'd
    response = [CLIENT.do_action_with_exception(request)]

    # Parse the Alibaba Cloud API's JSON response and get the plaintext version of the Data Key
    # The Data Key also requires base64 decoding
    data_key = b64decode(json.loads(response[0])['Plaintext'])

    # Instantiate an AES cipher object (using Galois Counter Mode (GCM) as the cipher) and perform encryption of plaintext data. Base64 encode the result
    cipher = AES.new(data_key, AES.MODE_GCM)
    cipherText, tag = cipher.encrypt_and_digest(plainText)

    # Parse the Alibaba Cloud API's JSON response and get the encryted version of the Data Key
    encrypted_data_key = json.loads(response[0])['CiphertextBlob']

    # Clear the response variable
    response[0] = 0

    return [b64encode(cipherText), encrypted_data_key, b64encode(cipher.nonce), b64encode(tag), context]

# Main
def main():

    # Get user input. Filepaths for plaintext data and where to write ciphertext output
    plaintext_filepath = sys.argv[1]
    ciphertext_filepath = sys.argv[2]

    # Open the plaintext data file and perform envelope encryption of its contents
    # Write ciphertext to chosen output filepath
    # Write encryption context to seperate file
    with open(plaintext_filepath, 'r') as fin:
        plainText = fin.read()
        encrypted_obj = envelope_encrypt(CMK_ID, plainText)
        
        # Write the ciphertext and encrypted Data Key to output file
        with open(ciphertext_filepath, 'w') as fout:
            fout.write(encrypted_obj[0])    # Ciphertext
            fout.write('*---*')
            fout.write(encrypted_obj[1])    # Encrypted Data Key
            fout.write('*---*')
            fout.write(encrypted_obj[2])    # Nonce
            fout.write('*---*')
            fout.write(encrypted_obj[3])    # Message Authentication Code (MAC) Tag
            fout.write('*---*')
            fout.write(encrypted_obj[4])    # Encryption Context (stored in plaintext)

if __name__ == '__main__':
    main() 
