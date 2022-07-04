import numpy as np

#import optim

import time_test

timeW = time_test.TimeWatch()

# NIST B-163 Elliptic curve sect163r2
polynomial = [ 0x000000c9, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000008 ]
coeff_b    = [ 0x4a3205fd, 0x512f7874, 0x1481eb10, 0xb8c953ca, 0x0a601907, 0x00000002 ]
base_x     = [ 0xe8343e36, 0xd4994637, 0xa0991168, 0x86a2d57e, 0xf0eba162, 0x00000003 ]
base_y     = [ 0x797324f1, 0xb11c5c0c, 0xa2cdd545, 0x71a0094f, 0xd51fbc6c, 0x00000000 ]
base_order = [ 0xa4234c33, 0x77e70c12, 0x000292fe, 0x00000000, 0x00000000, 0x00000004 ]

CURVE_DEGREE = 163
ECC_PRV_KEY_SIZE = 24
ECC_PUB_KEY_SIZE = (2 * ECC_PRV_KEY_SIZE)
BITVEC_MARGIN = 3
BITVEC_NBITS = (CURVE_DEGREE + BITVEC_MARGIN)
BITVEC_NWORDS = int(((BITVEC_NBITS + 31) / 32))
BITVEC_NBYTES = (4 * BITVEC_NWORDS)
ECDH_SHARED_KEY_SIZE_FOR_AES = 256

'''  Elliptic Curve Diffie-Hellman key exchange protocol.'''

def print_arr(arr):
  buf = "["
  for i in np.arange(len(arr)):
    buf += str(arr[i]) 
    if i < len(arr)-1:
      buf += ":"
  buf += "]"
  print(buf)

# NOTE: private should contain random data a-priori! 
def ecdh_generate_keys(private_key_8):
  """Generates ECDH public key starting from random private key (local secret).
  The public key can be sent to the remote host to generate the shared secret.
  It uses NIST K-163 elliptic curve.

  :param private_key_8: input private key (usually randomly chosen)
  :type private_key_8: Numpy array of uint8
  :return: ECDH public key
  :rtype: Numpy array of uint8
  """
  public_key_8 = np.zeros((ECC_PRV_KEY_SIZE*2), dtype=np.uint8)
  public_key = to_32bit_arr(public_key_8)
  private_key = to_32bit_arr(private_key_8)
  # Get copy of "base" point 'G' 
  out = Halfbitvec(public_key)
  gf2point_copy(out.first, out.second, base_x, base_y)
  out.merge()
  # Abort key generation if random number is too small
  if bitvec_degree(private_key) < (int(CURVE_DEGREE / 2)):
    return 0
  else:
    # Clear bits > CURVE_DEGREE in highest word to satisfy constraint 1 <= exp < n.
    nbits = bitvec_degree(base_order)

    for i in np.arange((nbits - 1), (BITVEC_NWORDS * 32)):
      bitvec_clr_bit(private_key, i)

    # Multiply base-point with scalar (private-key) errore forse in riga 615 della versione in JS da comunicare a Giuseppe
    #print("start gf2point_mul in ecdh.py...")
    gf2point_mul(out.first, out.second, private_key)
    #print("end gf2point_mul in ecdh.py...")
    out.merge()

    public_key_8 = np.copy(to_8bit_arr(public_key))
    private_key_8 = np.copy(to_8bit_arr(private_key))

    return public_key_8

def ecdh_shared_secret(private_key_8, others_pub_8):
  """Computes the shared secret applyinh ECDH Elliptic Curve Diffie-Hellman algorithm.
  It multiplies the local private key with the remote public key, obtaining the
  shared secret key among local and remote users.
  It uses NIST K-163 elliptic curve.

  :param private_key_8: local private key
  :type private_key_8: Numpy array of uint8
  :param others_pub_8: remote public key
  :type others_pub_8: Numpy array of uint8
  :return: shared secret key
  :rtype: Numpy array of uint8
  """
  others_pub_32 = to_32bit_arr(others_pub_8)
  private_key_32 = to_32bit_arr(private_key_8)
  output_8 = np.zeros((ECC_PUB_KEY_SIZE), dtype=np.uint8)
  output_32 = to_32bit_arr(output_8)

  out = Halfbitvec(others_pub_32)
  #Do some basic validation of other party's public key
  if not gf2point_is_zero(out.first, out.second) and gf2point_on_curve(out.first, out.second):
    # Copy other side's public key to output
    for i in np.arange(BITVEC_NBYTES * 2):
      output_8[i] = others_pub_8[i]

    # Multiply other side's public key with own private key 
    out = Halfbitvec(to_32bit_arr(others_pub_8))
    gf2point_mul(out.first, out.second, private_key_32)
    out.merge()

    # copy_arr(to_8bit_arr(output), output_8)
    output_8[:] = to_8bit_arr(out.bigarr)[:]
    return output_8
  else:
    return None

def custom_assert(condition):
  if not condition:
    raise Exception("assert failed")

class Halfbitvec:
  def __init__(self, bigarr):
    self.bigarr = bigarr
    half = int(len(bigarr)/2)
    self.first = bigarr[0:half]
    self.second = bigarr[half:]
    custom_assert(len(self.first) == half)
    custom_assert(len(self.second) == half)  
  
  def merge(self):
    l = len(self.first)
    self.bigarr[0:l] = self.first
    self.bigarr[l:] = self.second

def to_8bit(src32):
    bytes = [0, 0, 0, 0]
    bytes[0] = src32 & 0xFF  
    bytes[1] = (src32 >> 8) & 0xFF
    bytes[2] = (src32 >> 16) & 0xFF
    bytes[3] = (src32 >> 24) & 0xFF
    return bytes

def to_32bit(arr8):
    result = 0
    result += (arr8[0] << 0)
    result += (arr8[1] << 8)
    result += (arr8[2] << 16)
    result += (arr8[3] << 24)
    return result

def to_8bit_arr(arr32):
    arr8 = np.empty((len(arr32)*4), dtype=np.uint8)
    for i in np.arange(len(arr32)):
        n8 = to_8bit(arr32[i])
        for y in np.arange(3, -1, -1):
            arr8[(i * 4) + y] = n8[y]
    return arr8

def to_32bit_arr(arr8):
    arr32 = np.empty( (int(len(arr8)/4)), dtype=np.uint32)
    for i in np.arange(len(arr32)):
        src8 = arr8[i * 4: (i * 4 + 4)]
        assert len(src8) == 4
        n32 = to_32bit(src8)
        arr32[i] = n32
    return arr32

def cast_to_uint8array(uint32array):
  return uint32array.astype(np.uint8)

def cast_to_uint32array(uint8array):
  return uint8array.astype(np.uint32)

class Ptr:
  def __init__(self, arr):
    self.arr = arr
    self.pos = 0
  
  def set(self, pos, value):
    self.arr[pos] = value

  def get(self, pos=None):
    if pos is None:
      return self.arr[self.pos]
    return self.arr[pos]

  def inc(self, v=None):
    if self.pos >= len(self.arr)-1:
      raise Exception("Out Of Range")
    self.pos = self.pos + 1
    if self.v is None:
      return self.get(self.pos)
    else:
      self.set(self.pos, v)

  def dec(self, v=None):
    if self.pos <= 0: 
      raise Exception("Out of range")
    self.pos = self.pos - 1
    if v is None:
      return self.get(self.pos)
    else:
      self.set(self.pos, v)

  def move(self, pos):
    newpos = pos
    if newpos > len(self.arr) - 1: 
      raise Exception("Out of range")
    if newpos < 0:
      raise Exception("Out of range")

    self.pos = newpos

  def end(self):
    self.pos = len(self.arr) - 1

def ptr(arr):
  return Ptr(arr)
  
def newbitvec():
  return np.empty((BITVEC_NWORDS), np.uint32)

def bitvec_get_bit(x, idx):
  return ((x[int(idx / 32)] >> (idx & 31) & 1))

def bitvec_clr_bit(x, idx):
  index = int(idx / 32)
  src = (x[index])
  logical_and = (idx & 31)
  left_shift = (1 << logical_and)
  right = (~(left_shift))
  dst = (src & right)
  x[index] = dst

def bitvec_copy(x, y):
  # for i in np.arange(BITVEC_NWORDS):
  #   x[i] = y[i]
  x[:] = y[:]

def bitvec_swap(x, y):
  tmp = newbitvec()
  # tmp = np.copy(x)
  # x = np.copy(y)
  # y = np.copy(tmp)
  # return x, y
  bitvec_copy(tmp, x)
  bitvec_copy(x, y)
  bitvec_copy(y, tmp)

# fast version of equality test 
def bitvec_equal(x, y):
  # for i in np.arange(BITVEC_NWORDS):
  #     if x[i] != y[i]:
  #       return 0
  # return 1
  return (x == y).all()

def bitvec_set_zero(x):
  # for i in np.arange(BITVEC_NWORDS):
  #   x[i] = 0
  x[:] = 0

# fast implementation 
def bitvec_is_zero(x):
  # for i in np.arange(BITVEC_NWORDS):
  #   if x[i] != 0:
  #     return (i == BITVEC_NWORDS)
  # return (i == (BITVEC_NWORDS-1))
  return (x == 0).all()

# return the number of the highest one-bit + 1 
def bitvec_degree(x):
  i = BITVEC_NWORDS * 32

  # Start at the back of the vector (MSB) 
  px = ptr(x)
  px.move(BITVEC_NWORDS-1)
  
  # Skip empty / zero words 
  while ((i > 0) and (px.get() == 0)):
    if px.pos > 0:
      px.dec()
    i -= 32
  
  # Run through rest if count is not multiple of bitsize of DTYPE 
  if (i != 0):
    u32mask = (1 << 31)
    while ((px.get() & u32mask) == 0):
      u32mask >>= 1
      i = i - 1
  return i

# left-shift by 'count' digits */
def bitvec_lshift(x, y, nbits): 
  nwords = int((nbits / 32))
  i = 0
  # Shift whole words first if nwords > 0 
  for i in np.arange(nwords):
    # Zero-initialize from least-significant word until offset reached
    x[i] = 0
  j = 0
  # Copy to x output 
  while (i < BITVEC_NWORDS):
    x[i] = y[j]
    i += 1
    j += 1

  # Shift the rest if count was not multiple of bitsize of DTYPE 
  nbits &= 31
  if nbits != 0:
    # Left shift rest 
    for i in np.arange(BITVEC_NWORDS - 1, 0, -1):
      src = to_uint32(x[i])
      left = to_uint32(src << nbits)
      src2 = to_uint32(x[i - 1])
      right = to_uint32(src2 / np.power(2, 32 - nbits))
      or_ = to_uint32(left | right)
      x[i] = or_
      #x[i]  = (to_uint32(x[i] << nbits)) | (to_uint32(x[i - 1] >> (32 - nbits)));
    x[0] <<= nbits

_cast_uint32arr = np.empty((1), dtype=np.uint32)

def to_uint32(n):
  _cast_uint32arr[0] = n
  return _cast_uint32arr[0]

'''
Code that does arithmetic on bit-vectors in the Galois Field GF(2^CURVE_DEGREE).
'''

def gf2field_set_one(x):
  # Set first word to one 
  x[0] = 1
  #.. and the rest to zero
  x[1:] = 0
  # for i in np.arange(1, BITVEC_NWORDS):
  #   x[i] = 0

# fastest check if x == 1 
def gf2field_is_one(x):
  # Check if first word == 1
  if x[0] != 1:
    return False
  # ...and if rest of words == 0 
  for i in np.arange(1, BITVEC_NWORDS):
    if x[i] != 0:
      return False
  return True

# Galois field(2^m) addition is modulo 2, so XOR is used instead - 'z := a + b'
def gf2field_add(z, x, y):
  # for i in np.arange(BITVEC_NWORDS):
  #   z[i] = x[i] ^ y[i]
  z[:] = x[:] ^ y[:]

# increment element
def gf2field_inc(x):
  x[0] ^= 1

# field multiplication 'z := (x * y)' 
def gf2field_mul(z, x, y):
  #tmp = newbitvec()
  assert (z != y).any()
  tmp = np.copy(x)
  #bitvec_copy(tmp, x)

  # LSB set? Then start with x
  if bitvec_get_bit(y, 0) != 0:
    z[:] = x[:] #bitvec_copy(z, x) #tmp = np.copy(x)
  else:  #.. or else start with zero 
    z[:] = 0 #bitvec_set_zero(z)

  # Then add 2^i * x for the rest */
  for i in np.arange(1, CURVE_DEGREE):
    #lshift 1 - doubling the value of tmp */
    bitvec_lshift(tmp, tmp, 1)

    # Modulo reduction polynomial if degree(tmp) > CURVE_DEGREE */
    if bitvec_get_bit(tmp, CURVE_DEGREE):
      gf2field_add(tmp, tmp, polynomial)

    # Add 2^i * tmp if this factor in y is non-zero
    if bitvec_get_bit(y, i):
      gf2field_add(z, z, tmp)

# field inversion 'z := 1/x'
def gf2field_inv(z, x):
  
  u = np.zeros((BITVEC_NWORDS), np.uint32)
  v = np.zeros((BITVEC_NWORDS), np.uint32)
  g = np.zeros((BITVEC_NWORDS), np.uint32)
  h = np.zeros((BITVEC_NWORDS), np.uint32)
  
  u = np.copy(x) # bitvec_copy(u, x) 
  v = np.copy(polynomial) # bitvec_copy(v, polynomial)  

  # bitvec_set_zero(g)
  gf2field_set_one(z)
  
  while not gf2field_is_one(u):
    i = bitvec_degree(u) - bitvec_degree(v)

    if i < 0:
      u, v = v, u # bitvec_swap(u, v)
      bitvec_swap(g, z)
      i = -i

    bitvec_lshift(h, v, i)
    gf2field_add(u, u, h)
    bitvec_lshift(h, g, i)
    gf2field_add(z, z, h)
  
'''
   The following code takes care of Galois-Field arithmetic. 
   Elliptic curve points are represented  by pairs (x,y) of bitvec_t. 
   It is assumed that curve coefficient 'a' is {0,1}
   This is the case for all NIST binary curves.
   Coefficient 'b' is given in 'coeff_b'.
   '(base_x, base_y)' is a point that generates a large prime order group.
'''
def gf2point_copy(x1, y1, x2, y2):
  x1[:] = x2[:] #bitvec_copy(x1, x2) # x1 = np.copy(x2) 
  y1[:] = y2[:] #bitvec_copy(y1, y2) # y1 = np.copy(y2) 

def gf2point_set_zero(x, y):
  bitvec_set_zero(x)
  bitvec_set_zero(y)

def gf2point_is_zero(x, y):
  return bitvec_is_zero(x) and bitvec_is_zero(y)

# double the point (x,y) 
def gf2point_double(x, y):
  #timeW.start()
  # if P = O (zero or infinity): 2 * P = P 
  if bitvec_is_zero(x):
    bitvec_set_zero(y)
  else:
    l = newbitvec()
    gf2field_inv(l, x)
    gf2field_mul(l, l, y)
    l[:] = l[:] ^ x[:] # gf2field_add(l, l, x)
    gf2field_mul(y, x, x)
    gf2field_mul(x, l, l)
    gf2field_inc(l)
    x[:] = x[:] ^ l[:] #gf2field_add(x, x, l)
    gf2field_mul(l, l, x)
    y[:] = y[:] ^ l[:] #gf2field_add(y, y, l)
  #timeW.stop()

# add two points together (x1, y1) := (x1, y1) + (x2, y2) 
def gf2point_add(x1, y1, x2, y2):
  timeW.start()
  if not gf2point_is_zero(x2, y2):
    if gf2point_is_zero(x1, y1):
      gf2point_copy(x1, y1, x2, y2)
      #x1 = np.copy(x2)
      #y1 = np.copy(y2)
      #return x1, y1
    else:
      if bitvec_equal(x1, x2):# (x1 == x2).all(): 
        if bitvec_equal(y1, y2): # (y1 == y2).all(): 
          gf2point_double(x1, y1)
        else:
          gf2point_set_zero(x1, y1)
      else:
        # Arithmetic with temporary variables
        a = newbitvec()
        b = newbitvec()
        c = newbitvec()
        d = newbitvec()

        gf2field_add(a, y1, y2)
        gf2field_add(b, x1, x2)
        gf2field_inv(c, b)
        gf2field_mul(c, c, a)
        gf2field_mul(d, c, c)
        gf2field_add(d, d, c)
        gf2field_add(d, d, b)
        gf2field_inc(d)
        gf2field_add(x1, x1, d)
        gf2field_mul(a, x1, c)
        gf2field_add(a, a, d)
        gf2field_add(y1, y1, a)
        bitvec_copy(x1, d) # x1 = np.copy(d) 
  timeW.stop()

# point multiplication via double-and-add algorithm
def gf2point_mul(x, y, exp):

  tmpx = newbitvec()
  tmpy = newbitvec()
  nbits = bitvec_degree(exp)
  
  bit_vect = np.unpackbits(to_8bit_arr(exp)) #new

  gf2point_set_zero(tmpx, tmpy)
  print("nbits: ", nbits)
  for i in np.arange(nbits-1, -1, -1):
    gf2point_double(tmpx, tmpy)
    if bitvec_get_bit(exp, i):
      gf2point_add(tmpx, tmpy, x, y)
  #tmpx, tmpy = _double_and_add_recursive(nbits-1, exp, x, y, tmpx, tmpy)
  #tmpx, tmpy = optim.double_and_add(x, y, exp)
  gf2point_copy(x, y, tmpx, tmpy)

#tentativo non riuscito di migliorare le performance con la ricorsione
def _double_and_add_recursive(idxbit, exp, x, y, tmpx, tmpy):
  if idxbit == -1:
    return tmpx, tmpy
  else:
    gf2point_double(tmpx, tmpy)
    if bitvec_get_bit(exp, idxbit):
      gf2point_add(tmpx, tmpy, x, y)
    idxbit = idxbit - 1
    return _double_and_add_recursive(idxbit, exp, x, y, tmpx, tmpy)

# check if y^2 + x*y = x^3 + a*x^2 + coeff_b holds 
def gf2point_on_curve(x, y):
  a = newbitvec()
  b = newbitvec()

  if gf2point_is_zero(x, y):
    return 1
  else:
    gf2field_mul(a, x, x)
    gf2field_mul(b, a, x)
    gf2field_add(a, a, b)
    gf2field_add(a, a, coeff_b)
    gf2field_mul(b, y, y)
    gf2field_add(a, a, b)
    gf2field_mul(b, x, y)
    return (a == b).all() # bitvec_equal(a, b)

def _gf2point_mul(x, y, exp):
  
  x,y = mulp(8, 201, 163, [x,y], exp)

# Encapsulates mulf() in order to enable flat coordinates (x, y)
def mulp(p, q, n, p1, c):
    """Multiply point p by c using fast multiplication"""
    return from_projective(mulf(p, q, n, to_projective(p1), c), n)

def mulf(p, q, n, jp1, c):
    """Multiply point jp1 by c in projective coordinates"""
    sb = _signed_bin(c)
    res = None
    jp0 = neg(jp1, n)  # additive inverse of jp1 to be used fot bit -1
    for s in sb:
        res = doublef(p, q, n, res)
        if s:
            res = addf(p, q, n, res, jp1) if s > 0 else \
                addf(p, q, n, res, jp0)
    return res

def _signed_bin(n):
    """Transform n into an optimized signed binary representation"""
    r = []
    while n > 1:
        if n & 1:
            cp = _gbd(n + 1)
            cn = _gbd(n - 1)
            if cp > cn:         # -1 leaves more zeroes -> subtract -1 (= +1)
                r.append(-1)
                n += 1
            else:               # +1 leaves more zeroes -> subtract +1 (= -1)
                r.append(+1)
                n -= 1
        else:
            r.append(0)         # be glad about one more zero
        n >>= 1
    r.append(n)
    return r[::-1]

# this method allows _signed_bin() to choose between 1 and -1. It will select
# the sign which leaves the higher number of zeroes in the binary
# representation (the higher GDB).
def _gbd(n):
    """Compute second greatest base-2 divisor"""
    i = 1
    if n <= 0: return 0
    while not n % i:
        i <<= 1
    return i >> 2

def neg(p, n):
    """Compute the inverse point to p in any coordinate system"""
    return (p[0], (n - p[1]) % n) + p[2:] if p else None

# explicit point doubling using redundant coordinates
def doublef(p, q, n, jp):
    """Double jp in projective (jacobian) coordinates"""
    if not jp:
        return None
    x1, y1, z1, z1p2, z1p3 = jp

    y1p2 = (y1 * y1) % n
    a = (4 * x1 * y1p2) % n
    b = (3 * x1 * x1 - p * z1p3 * z1) % n
    x3 = (b * b - 2 * a) % n
    y3 = (b * (a - x3) - 8 * y1p2 * y1p2) % n
    z3 = (2 * y1 * z1) % n
    z3p2 = (z3 * z3) % n

    return x3, y3, z3, z3p2, (z3p2 * z3) % n

# faster addition: redundancy in projective coordinates eliminates
# expensive inversions mod n.
def addf(p, q, n, jp1, jp2):
    """Add jp1 and jp2 in projective (jacobian) coordinates."""
    if jp1 and jp2:

        x1, y1, z1, z1s, z1c = jp1
        x2, y2, z2, z2s, z2c = jp2

        s1 = (y1 * z2c) % n
        s2 = (y2 * z1c) % n

        u1 = (x1 * z2s) % n
        u2 = (x2 * z1s) % n

        if (u1 - u2) % n:

            h = (u2 - u1) % n
            r = (s2 - s1) % n

            hs = (h * h) % n
            hc = (hs * h) % n

            x3 = (-hc - 2 * u1 * hs + r * r) % n
            y3 = (-s1 * hc + r * (u1 * hs - x3)) % n
            z3 = (z1 * z2 * h) % n

            z3s = (z3 * z3) % n
            z3c = (z3s * z3) % n

            return x3, y3, z3, z3s, z3c

        else:
            if (s1 + s2) % n:
                return doublef(p, q, n, jp1)
            else:
                return None
    else:
        return jp1 if jp1 else jp2

def to_projective(p):
    """Transform point p given as (x, y) to projective coordinates"""
    if p:
        return (p[0], p[1], 1, 1, 1)
    else:
        return None     # Identity point (0)


def from_projective(jp, n):
    """Transform a point from projective coordinates to (x, y) mod n"""
    if jp:
        return (jp[0] * inv(jp[3], n)) % n, (jp[1] * inv(jp[4], n)) % n
    else:
        return None     # Identity point (0)