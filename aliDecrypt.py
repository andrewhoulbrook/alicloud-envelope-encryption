#!/usr/bin/python
# -*- encoding: utf-8 -*-
# Example barebones file decryption application using envelope encryption from Alibaba Cloud's KMS
# This script assumes a user has already generated a CMK and has access to the ID of the CMK in order to use it
import sys
import json
from base64 import b64decode
from Crypto.Cipher import AES
from credentials import ACCESS_KEY_ID, ACCESS_KEY_SECRET, REGION, CMK_ID 
from aliyunsdkcore.client import AcsClient
from aliyunsdkkms.request.v20160120 import DecryptRequest
    
# Instantiate an AliCloud client object
CLIENT = AcsClient(ACCESS_KEY_ID, ACCESS_KEY_SECRET, REGION)

# Decrypt Data Keys with Alibaba Cloud. Perform local file decryption using a plaintext Data Key
# Returns plaintext data
def envelope_decrypt(cipherText, encrypted_data_key, nonce, tag, context):

    try:

        # Call the Alibaba Cloud Decrypt API for decryption, passing in the encryption context
        # This decrypts data using the *Master Key* (CMK)
        request = DecryptRequest.DecryptRequest()
        
        # Set parameters for JSON format, connection over TLS and associated encryption context 
        request.set_accept_format('json')
        request.set_protocol_type('https')
        request.set_EncryptionContext(context)

        # Set the ciphertext to decrypt
        request.set_CiphertextBlob(encrypted_data_key)

        # Call the Alibaba Cloud Decrypt API and parses the JSON response for the plaintext Data Key. 
        # Response also requires base64 decoding
        # Plaintext data key stored in mutable object which can later be zero'd
        response = [CLIENT.do_action_with_exception(request)]
        data_key = [b64decode(json.loads(response[0])['Plaintext'])]

        # Instantiate an AES cipher object (using Galois Counter Mode (GCM) as the block cipher) and perform decryption of ciphertext data, using nonce and MAC tag parameters 
        cipher = AES.new(data_key[0], AES.MODE_EAX, nonce=nonce)
        plainText = cipher.decrypt_and_verify(cipherText, tag)

        # Clear the Data Key variables
        data_key[0] = 0
        response[0] = 0

        return plainText  
    
    except ValueError as err:
        print("ERROR: Incorrect Decryption - {}".format(err))
        sys.exit(1)

# Main
def main():

    # Get user input. Filepaths for ciphertext data and where to write plaintext output
    ciphertext_filepath = sys.argv[1]
    plaintext_filepath = sys.argv[2]

    # Open the ciphertext data file and perform envelope decryption of its contents
    # Write plaintext to chosen output filepath
    with open(ciphertext_filepath, 'rb') as fin:
        filedata = fin.read().split('*---*')
        cipherText = filedata[0]
        encrypted_data_key = filedata[1]
        nonce = filedata[2]
        tag = filedata[3]
        encryption_context = filedata[4]

        # Write the plaintext to output file
        # Call envelope decrypt function passing base64 decoded ciphertext, encrypted data key, nonce, MAC tag and encryption context. 
        with open(plaintext_filepath, 'w') as fout:
            fout.write(envelope_decrypt(b64decode(cipherText), encrypted_data_key, b64decode(nonce), b64decode(tag), encryption_context))

if __name__ == '__main__':
    main() 