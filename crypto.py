import numpy as np

import aes
import ecdh

def crypto_pkcs7CalculatePaddedSize(data_size):
  """Computes output size after PKCS7 padding (RFC2315) in order to respect AES standard 
  chunk size (16 bytes).

  :param data_size: Data size for PKCS7 padding
  :type data_size: int
  :return: Length of padded data
  :rtype: int
  """
  return data_size + (aes.AES_CHUNK_SIZE - data_size % aes.AES_CHUNK_SIZE)

def crypto_pkcs7CalculateUnpaddedSize(data):
  """Computes unpadded size of an array with PKCS7 padding (RFC2315) in order to respect AES standard 
  chunk size (16 bytes).

  :param data: Numpy padded array
  :type data: Numpy array
  :return: Length of unpadded data
  :rtype: int
  """
  padding = data[-1]
  if padding > aes.AES_CHUNK_SIZE or padding < 1: 
    return len(data)
  
  return len(data) - padding

def crypto_pkcs7pad(data):
  """Performs padding from input data in order to respect AES standard 
  chunk size (16 bytes) according to PKCS7 padding from RFC2315.
  Note: this implemention is not allined with C one; mind that C function takes
  a C-like string as input with the last character that is '/0', for this reason
  the padding result is different comparing the two languages.

  :param data: input Numpy array
  :type data: Numpy array of uint8
  :return: padded data as Numpy array
  :rtype: uint8 Numpy array
  """
  padded_size = crypto_pkcs7CalculatePaddedSize(len(data))
  padding = padded_size - len(data)
  
  out = np.zeros((padded_size), dtype=np.uint8)

  out[0:len(data)] = data[0:len(data)]
  out[len(data):] = padding
  
  return out

def crypto_pkcs7unpad(data):
  """Performs unpadding of a PKCS7 (RFC2315) padded input array according to AES standard 
  chunk size (16 bytes).

  :param data: _description_
  :type data: _type_
  :param data_size: _description_
  :type data_size: _type_
  :return: _description_
  :rtype: _type_
  """
  unpadded_size = crypto_pkcs7CalculateUnpaddedSize(data)
  padding = len(data) - unpadded_size 
  out = np.empty((unpadded_size), dtype=np.uint8) 

  if (data[unpadded_size: len(data)] != padding).any():
    return 0
  out[0:unpadded_size] = data[0:unpadded_size]
  
  return out

def crypto_aesEncrypt(data, key, key_size):
  """Encrypts data using key with certain key size (128, 192 or 256 bits) 
  applying AES algorithm.

  :param data: input data (already padded data)
  :type data: Numpy array of uint8
  :param key: AES key 
  :type key: Numpy array of uint8
  :param key_size: size of AES key (128, 192 or 256 bits)
  :type key_size: int
  :return: encrypted data
  :rtype: Numpy array of uint8
  """
  key_schedule = np.zeros((60), dtype=np.uint32)
  out = np.zeros((len(data)), dtype=np.uint8)
  pos = 0
  rest = len(data)
  key_schedule = aes.aes_key_setup(key, key_size)

  while rest > 0:
    enc_buf = aes.aes_encrypt(data, pos, key_schedule, key_size)
    out[pos: pos + aes.AES_CHUNK_SIZE] = enc_buf[0: aes.AES_CHUNK_SIZE]
    rest -= aes.AES_CHUNK_SIZE
    pos += aes.AES_CHUNK_SIZE
  
  return out

def crypto_aesDecrypt(encrypted_data, key, key_size):
  """Decrypts data using key with certain key size (128, 192 or 256 bits) 
  applying AES algorithm.

  :param encrypted_data: cipher data array
  :type encrypted_data: Numpy array of uint8
  :param key: AES key
  :type key: Numpy array of uint8
  :param key_size: size of AES key (128, 192 or 256 bits)
  :type key_size: int
  :return: decrypted data
  :rtype: Numpy array of uint8
  """
  key_schedule = np.empty((60), dtype=np.uint32)
  out = np.empty((len(encrypted_data)), dtype=np.uint8)
  pos = 0
  rest = len(encrypted_data)
  key_schedule = aes.aes_key_setup(key, key_size)

  while rest > 0:         
      dec_buf = aes.aes_decrypt(encrypted_data, pos, key_schedule, key_size)
      out[pos: pos + aes.AES_CHUNK_SIZE] = dec_buf[0: aes.AES_CHUNK_SIZE]
      rest -= aes.AES_CHUNK_SIZE
      pos += aes.AES_CHUNK_SIZE
  
  return out 

def crypto_sign(prv_key, pub_key, data):
  """Computes the digital signature of input data using ECDH algorithm. 
  The private key is integer value chosen by the local user to multiply the generator point of ECC.
  The public key is the point generate by the remote user multipling the generator point of ECC by 
  its secret integer value.
  The signature is computed applying AES encryption to the input data with the ashared key computed
  multiplying the private and public key in ECC domain using ECDH Diffie - Hellman algoritm.

  :param prv_key: local private key as Numpy array of 24 unsigned integer values
  :type prv_key: Numpy array of uint8
  :param pub_key: remote public key as Numpy array of 48 unsigned integer values
  :type pub_key: Numpy array of uint8
  :param data: input data to be signed
  :type data: Numpy array of uint8
  :return: digitale signature
  :rtype: Numpy array of uint8
  """
  shared_secret = ecdh.ecdh_shared_secret(prv_key, pub_key)

  padded_data = crypto_pkcs7pad(data) 
  encrypted_data = crypto_aesEncrypt(padded_data, shared_secret, ecdh.ECDH_SHARED_KEY_SIZE_FOR_AES)
  
  return encrypted_data

def crypto_unsign(prv_key, pub_key, signature):
  """Verifies the digital signature of input data using ECDH algorithm. 
  The private key is integer value chosen by the local user to multiply the generator point of ECC.
  The public key is the point generate by the remote user multipling the generator point of ECC by 
  its secret integer value.
  The signature is computed applying AES encryption to the input data with the ashared key computed
  multiplying the private and public key in ECC domain using ECDH Diffie - Hellman algoritm.

  :param prv_key: local private key as Numpy array of 24 unsigned integer values
  :type prv_key: Numpy array of uint8
  :param pub_key: remote public key as Numpy array of 48 unsigned integer values
  :type pub_key: Numpy array of uint8
  :param signature: signature to be verified
  :type signature: Numpy array of uint8
  :return: decrypted data to be verified
  :rtype: Numpy array of uint8
  """
  shared_secret = ecdh.ecdh_shared_secret(prv_key, pub_key)
  
  decrypted_data = crypto_aesDecrypt(signature, shared_secret, ecdh.ECDH_SHARED_KEY_SIZE_FOR_AES)
  ret = crypto_pkcs7unpad(decrypted_data)

  return ret
