#!/usr/bin/python3
# --Digital Signature--

# import cryptography modules
from Crypto.Signature import eddsa
from Crypto.PublicKey import ECC
from getpass import getpass
from os.path import isfile
from base64 import b64encode, b64decode
import json

# custom errors


class DSSErrorr(Exception):
    '''Error executing DSS script'''

class ReadProcessingError(DSSErrorr):
    '''Error preprocessing data read from file'''


#
# INPUT/OUTPUT functions
#


# funtion that reads files
# parameters:
# - subject: what the file should contain
# - error: error message to show when aborting
# - default: name of file to open if not specified
# - process: function to call on data,
#       reading is not considered complete unless
#       this function is called successfully.
#       Should raise ReadProcessingError on errors
# returns data read (and processed) and name of file read


def read_file(subject, error, default='', process=lambda data: data):
    #prepare string to print, including default choice
    prompt = f'Insert path to {subject} file'
    if default != '':
        prompt += f' ({default})' 
    prompt += ':\n'
    #try until file is correctly read or user aborts
    while True:
        #read choice, use default if empty
        in_filename = input(prompt)
        if in_filename  == '':
            in_filename  = default
        #read and process data
        try:
            with open(in_filename, 'rb') as in_file:
                data = in_file.read()
            return process(data), in_filename
        except (IOError, ReadProcessingError) as e:
            print(f'Error while reading {subject}:\n{e}')
            #let user abort reading file
            c = input('q to quit, anything else to try again: ')
            if c.lower() == 'q':
                #abort
                raise DSSErrorr(error)

# function to write on file
# parameters:
# - data: what to write to file
# - subject: description of what the file will contain
# - error: error message to show when aborting
# - default: name of file to open if not specified
# returns name of file written


def write_file(data, subject, error, default=''):  
    #try until file is correctly written or user aborts
    while True:
        # prepare string to print, including default choice
        prompt = f'Insert path to file where to save {subject}'
        if default != '':
            prompt += f' ({default})' 
        prompt += ':\n'
        # read choice, use default if empty
        out_filename = input(prompt)
        if out_filename  == '':
            out_filename  = default
        try:
            # warn before overwriting
            if isfile(out_filename):
                prompt = 'File exists, overwrite? '
                prompt += '(n to cancel, anything else to continue)\n'
                overwrite = input(prompt)
                if overwrite.lower() == 'n':
                    continue
            # write data
            with open(out_filename, 'wb') as out_file:
                out_file.write(data)
            return out_filename
        except IOError as e:
            print(f'Error while saving {subject}: {e}')
            # let user abort writing file
            c = input('q to quit, anything else to try again: ')
            if c.lower() == 'q':
                # abort
                raise DSSErrorr(error)



#
# VALIDATION FUNCTIONS
#


# function that validates a file's minimum length
# parameters:
# data: byte string to check
# min_len: minimum length in bytes the file must have


def check_len(data, min_len):
    if len(data) >= min_len:
        return data
    else:
        message = f'Error: the file must be at least {min_len} bytes long.'
        raise ReadProcessingError(message)



# function that imports and validates an ECC key
# parameters:
# - data: byte string to check and import
# - private: boolean that tells if the key should be a private key


def import_key(data, is_private):
    passphrase = None
    if is_private:
        # aquire passphrase
        passphrase = getpass("Insert password to unlock the private key:")
    # import key
    try:
        key = ECC.import_key(data, passphrase=passphrase)
    except ValueError as e:
        # error message
        message = f'Error while importing the key: {e}'
        if is_private:
            message += '\nPlease check that the password is correct.'
        raise ReadProcessingError(message)
    # check size
    if key.curve not in ('ed25519', 'Ed25519'):
        message = f'Error: wrong curve ({key.curve}), should be "ed25519"'
        raise ReadProcessingError(message)
    # check type
    if is_private and (not key.has_private()):
        raise ReadProcessingError('Error: this is not a private key!')
    
    return key



# function that imports and validates a certificate
# parameters:
# - data: byte string to check and import


def import_cert(data):
    error_msg = 'Certificate format not valid: '
    try:
        #decode as string and import as json
        cert = json.loads(data)
        #get values to sign
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
        #certificate does not have 'id' or 'pubk' fields
        error_msg += f'{e} field not found.'
        raise ReadProcessingError(error_msg)
    return info



#
# SUPPORT FUNCTIONS
#

# function that acquires a non-empty passphrase
# for private key protection

def get_passphrase():
    prompt = "Insert password for the private key:"
    while True:
        pw = getpass(prompt)
        if pw != '':
            return pw
        else:
            prompt = "please enter a non-empty password:"



# function that imports a key from file
# parameters:
# - private: boolean that tells if the key is private
# returns the imported key

def read_key(is_private):
    # prepare settings
    settings = {
        'error': 'Key import aborted.',
        'process': lambda data: import_key(data, is_private)
    }
    if is_private:
        settings['subject'] = 'private key'
        settings['default'] = 'ECC_sk.pem'
    else:
        settings['subject'] = 'public key'
        settings['default'] = 'ECC_pk.pem'

    key, _ = read_file(**settings)
    return key



# function that prepares certificate data for signing


def cert_sig_enc(info):
    return info[0].encode('utf-8') + info[1].encode('utf-8')



#
# GENERATE KEYS
#


def gen_keys():
    # generate key pair
    key = ECC.generate(curve = 'ed25519')
    print('Keys generated!')
    # export private key
    # acquire passphrase
    passphrase = get_passphrase()
    #define export settings
    export_settings = {
        'format': 'PEM',
        'passphrase': passphrase,
        'protection': 'scryptAndAES128-GCM',
        'prot_params': {
            'iteration_count': 2**20
        }
    }
    # export
    private_key = key.export_key(**export_settings)
    # save on file
    settings = {
        'data': private_key.encode(),
        'subject': 'private key',
        'error': 'Output aborted.',
        'default': 'ECC_sk.pem'
    }
    print(f'Private key correctly written in "{write_file(**settings)}"')
    # export public key
    public_key = key.public_key().export_key(format = 'PEM')
    # save on file
    prompt = 'Insert identity to save as a certificate, '
    prompt +='leave blank and press ENTER to save as pubkey\n'
    id_string = input(prompt)
    if id_string == '':
        settings = {
            'data': public_key.encode(),
            'subject': 'public key',
            'default': 'ECC_pk.pem'
        }
    else:
        # create and encode certificate
        cert = {
            'id': id_string,
            'pubk': public_key
        }
        cert_encoded = json.dumps(cert).encode()
        settings = {
            'data': cert_encoded,
            'subject': 'certificate',
            'default': id_string + '.cert'
        }
    
    #complete export settings and write file
    name = settings['subject'].capitalize()
    settings['error'] = name + ' not saved: aborted.'
    print(f'{name} correctly written in "{write_file(**settings)}"')



#
# SIGN
#


# function that computes a signature
# parameters:
# - msg: byte string to sign
# - pr_key: imported private key
# - encode: boolean that determines output type:
#   - True: b64-utf8 encoded string
#   - False: bytes (default)
# returns the signature


def get_sig(msg, pr_key, encode = False):
    #initialise signing
    signer = eddsa.new(pr_key, 'rfc8032')
    #sign
    sig = signer.sign(msg)
    #encode and return signature
    if encode:
        sig = b64encode(sig).decode('utf-8')
    return sig



# function that signs a file


def sign():
    # read private key to use
    sk = read_key(is_private = True)

    # read file to sign, no validation
    settings = {
        'subject': 'data to sign',
        'error': 'Signing aborted.'
    }
    data, in_file = read_file(**settings)

    #sign
    signature = get_sig(data, sk)
    # output 
    settings = {
        'data': signature + data,
        'subject': 'signed data',
        'error': 'Output aborted.',
        'default': in_file + '.sig'
    }
    print(f'Signed data correctly written in "{write_file(**settings)}"')



# function that signs a certificate, completing it


def sign_cert():
    error = 'Signing aborted.'
    # read private key to use
    sk = read_key(is_private = True)

    # read certificate to sign
    settings = {
        'subject': 'certificate to sign',
        'error': error,
        'process': import_cert
    }
    info, in_file = read_file(**settings)

    print('Certificate data:')
    print('ID: ' + info[0])
    print('Public Key:\n' + info[1])
    print('\nConfirm and sign?')
    c = input('(y to proceed, anything else to cancel): ')
    if c.lower() != 'y':
        raise DSSErrorr(error)
    #sign certificate
    signature = get_sig(cert_sig_enc(info), sk, True)
    #generate a complete certificate
    cert = {
        'id': info[0],
        'pubk': info[1],
        'sig': signature
    }
    #write complete certificate, default overwrites old cert
    settings = {
        'data': json.dumps(cert).encode(),
        'subject': 'signed certificate',
        'error': 'Certificate update aborted.',
        'default': in_file
    }
    print(f'Signed certificate correctly written in "{write_file(**settings)}"')


#
# VERIFY
#


# function that verifies a signature
# parameters:
# - msg: byte string to verify
# - sig: byte string containing the signature to be checked
# - pub_key: imported public key
# raises an exception if the signature does not verify
# against msg and pub_key


def ver_sig(msg, sig, pub_key):
     #initialise verifying
    verifier = eddsa.new(pub_key, 'rfc8032')
    #verify
    try:
        verifier.verify(msg, sig)
    except ValueError:
        raise DSSErrorr('Invalid signature!')



# function that verifies a signed file


def verify():
    # read public key to use
    pk = read_key(is_private = False)

    # read signed file to verify, validating length
    sig_len = 64
    settings = {
        'subject': 'signed',
        'error': 'Verifying aborted.',
        'process': lambda data: check_len(data, sig_len)
    }
    data, in_file = read_file(**settings)

    # check signature
    ver_sig(data[sig_len:], data[:sig_len], pk)
    # if there are no errors the signature is valid
    prompt = 'Signature is valid!\nExport content?'
    prompt += ' (y to confirm, anything else to cancel) '
    c = input(prompt)
    if c.lower() == 'y':
        # try to deduce original filename
        if in_file[-4:] == '.sig':
            default = in_file[:-4]
        else:
            default = in_file + '.ok'
        
        export_settings = {
            'data': data[sig_len:],
            'subject': 'content data',
            'error': 'Data export aborted',
            'default': default
        }
        print(f'Data correctly written in "{write_file(**export_settings)}"')


# function that verifies a certificate


def verify_cert():
    # read public key to use
    pk = read_key(is_private = False)

    # read certificate to verify
    settings = {
        'subject': 'certificate to verify',
        'error': 'Verification aborted.',
        'process': import_cert
    }
    info, _ = read_file(**settings)
    if len(info) < 3:
        #'sig' field is missing
        print('The Certificate is not signed!')
        return
    #verify signature of certificate against public key
    try:
        ver_sig(cert_sig_enc(info), info[2], pk)
        print('OK: the certificate is valid.')
    except ValueError:
        print('The certificate is not valid!')
    return



#
# MAIN
#


main_prompt = '''What do you want to do?
1 -> generate and save keys
2 -> sign a file
3 -> verify a signed file
4 -> sign a certificate
5 -> verify a certificate
0 -> quit
 -> '''
while True:
    #get user's choice and call appropriate function
    #errors are captured and printed out
    #invalid choices are ignored
    choice = input(main_prompt)
    try:
        if choice == '1':
                gen_keys()
        elif choice == '2':
                sign()
        elif choice == '3':
                verify()
        elif choice == '4':
                sign_cert()
        elif choice == '5':
                verify_cert()
        elif choice == '0':
            exit()
    except DSSErrorr as e:
            print(e)