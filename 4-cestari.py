import json
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC
from Crypto.Hash import SHAKE128
from Crypto.Signature import eddsa
from Crypto.Protocol.DH import key_agreement
from getpass import getpass


#
# CUSTOM ERRORS
#
class DSSEncError(Exception):
    '''General error executing DSS Encryption script'''

class ReadProcessingError(DSSEncError):
    '''Error preprocessing data read from file'''
# this is pubkey of the server it implements autentication of the server
ca_pk = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAw7LeJPefPraYOphyfgQio1JsjdV1E+kdYxehGslK4Ws=\n-----END PUBLIC KEY-----'
#
# VALIDATION FUNCTION
#
 
# Function that validates ciphertext file length
# Parameters:
# - data: byte string to check
# - c_len: length in bytes the key must have
def check_c_len(data, c_len):
    if len(data) >= c_len:
        return data
    else:
        message = 'Error: the cipher text must be at least '
        message += str(c_len) + ' bytes long.'
        raise ReadProcessingError(message)

# Function that imports and validates a certificate
# Parameters:
# - data: byte string to check and import
def import_cert(data):
    error_msg = 'Certificate format not valid: '
    try:
        # Decode as string and import as json
        cert = json.loads(data)
        # Get values to sign
        info = [cert['id'], cert['pubk']]
        if 'sig' in cert:
            info += [b64decode(cert['sig'])]
    except ValueError:
        error_msg += 'encoding error.'
        raise ReadProcessingError(error_msg)
    except TypeError:
        error_msg += 'invalid data.'
        raise ReadProcessingError(error_msg)
    except KeyError as e:
        # Certificate does not have 'id' or 'pubk' fields
        error_msg += f'{e} field not found.'
        raise ReadProcessingError(error_msg)
    return info

#
# INPUT / OUTPUT FUNCTION
#
 
# Function that reads files
# Parameters:
# - subject: what the file should contain
# - error: error message to show when aborting
# - default: name of file to open if not specified
# - process: function to call on data,
#   reading is not considered complete unless
#   this function is called successfully.
#   Should raise ReadProcessingError on errors
# Returns data read (and processed) and name of file read
def read_file(subject, error, default='', process=lambda data: data):
    # Prepare string to print, including default choice
    prompt = f'Insert path to {subject} file'
    if default != '':
        prompt += f' ({default})' 
    prompt += ':\n'
    # Try until file is correctly read or user aborts
    while True:
        # Read choice, use default if empty
        in_filename = input(prompt)
        if in_filename  == '':
            in_filename  = default
        # Read and process data
        try:
            with open(in_filename, 'rb') as in_file:
                data = in_file.read()
            return process(data), in_filename
        except (IOError, ReadProcessingError) as e:
            print(f'Error while reading {subject}:\n{e}')
            # Let user abort reading file
            c = input('q to quit, anything else to try again: ')
            if c.lower() == 'q':
                # Abort
                raise DSSEncError(error)

# Function to write data to a file
# Parameters:
# - prompt: text to inform the user of what the code expects
# - data: the data to write into the file
# - cert_
def write_file(prompt, data):
    while True:
        path = input(prompt)  # Output file path
        try:
            with open(path, 'wb') as out_file:    
                out_file.write(data)  # Write data as bytes
            return 'Data successfully written in file "' + path + '".'
        except IOError as e:
            print('Error: Cannot write file "' + path + '": ' + str(e))
        choice = input('(q to abort, anything else to try again) ')
        if choice == 'q':
            raise DSSEncError('Output aborted')

#
# SYMMETRIC ENCRYPTION FUNCTION
#
 
# Function to symmetrically encrypt the message
# - Read the file and check if it contains at least one byte
# - Generate a random 32-byte key
# - Encrypt with AES mode OCB and authenticate
def encrypt_sync(key):
    # Ask the user for the path of the binary file to be encrypted
    settings = {
    'subject': 'plain text',
    'error': 'Error while reading plain text file',
    }
    plain_text, _ = read_file(**settings)
    cipher = AES.new(key, AES.MODE_OCB)
    # Encrypt the plain text and obtain the ciphertext, tag, and nonce
    ciphertext, tag = cipher.encrypt_and_digest(plain_text)
    nonce = cipher.nonce
    # Concatenate tag, nonce, and ciphertext to form the encrypted result
    result = tag + nonce + ciphertext
    return result

# Function to symmetrically decrypt the message
# - Message: contains the tag, nonce, and ciphertext to decrypt
# - key: contains the key which was used to encrypt
def decrypt_sync(message, key):
    # Extract components from the binary data
    tag = message[:16]
    nonce = message[16:31]
    ciphertext = message[31:]
    # Initialize decryption cipher
    cipher_dec = AES.new(key, AES.MODE_OCB, nonce)
    try:
        # Attempt to decrypt the ciphertext and verify the authenticity
        plain_text = cipher_dec.decrypt_and_verify(ciphertext, tag)
        return plain_text
    except ValueError:            
            # Raise a custom exception indicating the timer has expired
            err_msg = 'Something went wrong during the symmetric decrypt,'
            err_msg += '\nPlease try again'
            raise DSSEncError(err_msg)

# Function passord
# - Boolean to chek the key
def get_pwd(generate):
    # Request made to the user
    prompt="Insert password: "
    while True:
            # Prompt
            password = getpass(prompt)
            # Check the pwd length minimum 8 
            if len(password) >= 8 or not generate:
                # Return the password
                break
            else:
                # Else ask the user if he wants to re-enter 
                # a new password or wants to exit
                print('\nThe password you entered is not long enough.'
                        '\nTry one that is at least 8 characters long.')
                choice = input('Press "q" to abort, anything else to try again: ')
                if choice.lower() == 'q':
                    # If the user wants to quit, raise the error
                    raise DSSEncError('Input aborted')
    return password

#
# Generating cert, key
#
def gen_key():
    sk = ECC.generate(curve='Ed25519')
    pk = sk.public_key()
    return sk, pk

def gen_cert():
    sk, pk = gen_key()
    cert = {
        'id':'StefanoCestari',
        'pubk': pk.export_key(format='PEM'),
        'sig':''
    }
    cert_json=json.dumps(cert)
    print(write_file("Write the path where you want to save the certificate: ", cert_json.encode('utf-8')))
    print("Go to the CA and get your certificate signed")
    pwd = get_pwd(True)
    wrapped_key = sk.export_key(
        format='PEM', 
        passphrase=pwd,
        protection='scryptAndAES256-GCM',
        prot_params={'iteration_count':2**20}
        )
    print(write_file("Write the path where you want to save the secret key: ", wrapped_key.encode('utf-8')))


#
# Read and verify cert, key
#

# Function that verifies a signature
# Parameters:
# - msg: byte string to verify
# - sig: byte string containing the signature to be checked
# - pub_key: imported public key
# Raises an exception if the signature does not verify
# against msg and pub_key
def ver_sig(msg, sig, pub_key):
    # Initialise verifying
    verifier = eddsa.new(pub_key, 'rfc8032')
    # Verify
    try:
        verifier.verify(msg, sig)
    except ValueError as e:
        print(e)
        raise DSSEncError('Invalid signature!')


#function modified to verify cert

def read_cert():
    while True:
        settings = {
        'subject': "certificate",
        'error': 'Error while reading the certificate file',
        'process': import_cert
        }
        # Read the certificate and use import_cert to get an object
        certificate, _ = read_file(**settings)
        # Concatenate the id with the key and convert them into bits
        id_pubk =(certificate[0]+certificate[1]).encode('utf-8')
        sig = certificate[2]
        # Import the public key of the CA
        ca_ECC_pk = ECC.import_key(ca_pk)
        try:
            # Verify the certificate and return the pk
            ver_sig(id_pubk, sig, ca_ECC_pk)
            return ECC.import_key(certificate[1])
        except DSSEncError:
            # Otherwise, inform the user and ask if they want to abort
            print("Error during certificate validation, try with another certificate or get it validated by the CA")
            c = input('q to quit, anything else to try again: ')
            if c.lower() == 'q':
                # Abort
                raise DSSEncError()

def ver_secret_key(key):
    pwd = getpass("Insert password: ")
    try:
        sk = ECC.import_key(key, pwd)
        print(sk)
    except(ValueError, IndexError, TypeError):
        err_msg ='The given key cannot be parsed (possibly because the pass phrase is wrong).'
        raise ReadProcessingError(err_msg)
    if not sk.has_private():
        # if it does not respect the previous parameters 
        # raise the error whit a castom message 
        err_msg = "The selected file doesn't contains secret key"
        err_msg+="\nPlease try whit another file."
        raise ReadProcessingError(err_msg)
    return sk

def ver_public_key(key):
    if len(key) > 143:
        try:
            return ECC.import_key(key[:112]), key[112:]
        except(ValueError, IndexError, TypeError):
            err_msg ='File selected does not contain a valid key'
            raise ReadProcessingError(err_msg)
    else:
        err_msg ='File not ciphered try another file'
        raise ReadProcessingError(err_msg)


#
#   Hash shake128
#
            
def kdf(value):
        return SHAKE128.new(value).read(16)

#
#  Core funtions
#

def encrypt():
    pk = read_cert()  # Pub key in teh certificate loaded
    # ephimeral keys
    ske, pke = gen_key() 
    # Diffie hellman
    session_key = key_agreement(static_priv=ske, static_pub=pk, kdf=kdf)
    ct = encrypt_sync(session_key)  # Encrypt with session keys
    # Preparing file.PEM
    file_content = pke.export_key(format='PEM').encode("utf-8") + ct 
    # Writing  CT to a specific pat
    print(write_file("Enter path/name for cipher text file: ", file_content)) 



def decrypt():
    settings = {
        'subject': "encrypted ",
        'error': 'Error importing encrypted file',
        'process': ver_public_key
    }
    obj, _ = read_file(**settings)
    pke, ciphertext = obj
    #
    settings = {
        'subject': "secret key ",
        'error': 'Error During the read of the secret key',
        'process': ver_secret_key
    }
    # Content of Enc File
    sk, _ = read_file(**settings)
    # key agreement DH
    session_key = key_agreement(static_priv=sk, static_pub=pke, kdf=kdf) 
    # Decrypt CT
    plaintext = decrypt_sync(ciphertext, session_key)  
    # Write  decrypted PT
    print(write_file("Enter the path to save the plain text: ", plaintext))  


#
# Main
#

prompt = '''What do you want to do?
1) Encrypt file
2) Decrypt file
3) Generate the certificate 
0) Quit
'''
prompt_pwd="Insert assword: "
while True:
    choice = input(prompt)
    try:
        if choice == '1':
            encrypt()
        elif choice == '2':
            decrypt()
        elif choice=='3':
            gen_cert()
        elif choice == '0':
            break
        else:
            print("Invalid input")
    except DSSEncError as e:
        print(e)
