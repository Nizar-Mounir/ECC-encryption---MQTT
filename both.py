#import libraries
from tinyec import registry
import secrets

curve = registry.get_curve('brainpoolP256r1')

def compress_point(point):
    return hex(point.x) + hex(point.y % 2)[2:]


def ecc_calc_encryption_keys(pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    sharedECCKey = pubKey * ciphertextPrivKey
    return (sharedECCKey, ciphertextPubKey)

def ecc_calc_decryption_key(privKey, ciphertextPubKey):
    sharedECCKey = ciphertextPubKey * privKey
    return sharedECCKey


def ecc_encrypt(message, pubKey):
    # Convert the message to bytes
    message_bytes = message.encode()

    # Generate a random key pair for encryption
    (encryptKey, ciphertextPubKey) = ecc_calc_encryption_keys(pubKey)

    # Encrypt the message using the shared ECC encryption key
    encrypted = bytearray()
    shared_key = compress_point(encryptKey)
    for byte in message_bytes:
        encrypted_byte = byte ^ int(shared_key, 16) % 256  # Limit to byte range
        encrypted.append(encrypted_byte)

    return (encrypted, ciphertextPubKey)

def ecc_decrypt(encrypted, privKey, ciphertextPubKey):
    # Retrieve the shared ECC decryption key
    decryptKey = ecc_calc_decryption_key(privKey, ciphertextPubKey)

    decrypted = bytearray()
    shared_key = compress_point(decryptKey)
    for byte in encrypted:
        decrypted_byte = byte ^ int(shared_key, 16) % 256  # Limit to byte range
        decrypted.append(decrypted_byte)

    # Convert the decrypted bytes back to string
    decrypted_message = decrypted.decode()
    return decrypted_message



privKey = secrets.randbelow(curve.field.n)
pubKey = privKey * curve.g

# Encrypt and decrypt "Hello, World!" string
message = "Hello, World!"

encrypted_message, ciphertextPubKey = ecc_encrypt(message, pubKey)
print("Encrypted:", encrypted_message)

decrypted_message = ecc_decrypt(encrypted_message, privKey, ciphertextPubKey)
print("Decrypted:", decrypted_message)
