from ecpy.curves import Curve, Point
from Crypto.Hash import keccak


def get_public_key(private_key: int) -> int:
    '''
    Use Elliptic Curve Cryptography (ECC) to get the equivalent public key given a 
    private key. Note that this DOES NOT prepend the 0x04 to the resulting key.

    The elliptic curve formula over a finite field is: 

    (a) y**2 mod p = x**3 + a*x + b mod p

    where p is the size of the field. P must be prime or a prime power 
    (see finite fields / Galois fields).

    Ethereum has set values for a, b, and p (defined by NIST), which are:

    a = 0
    b = 7
    p = 115792089237316195423570985008687907853269984665640564039457584007908834671663

    With the values above, we have the simplified curve:

    (b) y**2 mod p = x**3 + 7 mod p

    This particular curve is called `secp256k1`

    Points in the curve can be added together by following a very specific set
    of rules. See the ethereum book for the rules.

    Once we have addition, we define multiplication as just successive
    addition operations. Then follow this algorithm to get
    a public key:

    1. Get a point G that lies in the curve (b).
    2. Get the public key by multiplying the private key by G (using ECC multiplication) 
        - The public key will be an x,y point on the curve
    3. Concat x and y points and returns as the pubkey 

    The point G, called a generator point, is also defined by the ethereum 
    standard as:

    gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    g = (gx,gy)

    See:

    https://github.com/ethereumbook/ethereumbook/blob/develop/04keys-addresses.asciidoc
    https://github.com/nakov/Practical-Cryptography-for-Developers-Book/blob/master/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc.md
    https://hackernoon.com/how-to-build-a-minimalistic-ethereum-wallet-in-python-part-1-rr4j32dp
    https://www.cs.uaf.edu/2015/spring/cs463/lecture/02_23_ECC_impl.html
    https://en.bitcoin.it/wiki/Secp256k1
    https://www.graui.de/code/elliptic2/
    https://en.wikipedia.org/wiki/Finite_field
    '''
   
    # ECPy gives the curve directly to us.
    # All we have to do is to get the generator point on that curve
    # and multiply by the private key to get the public one.
    #
    # That can also be done by the library, but we make it explicit here
    # to show the process.
    curve = Curve.get_curve('secp256k1')
    g = Point(
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
        curve
    )
    public_key = private_key * g 

    # Concat x and y of the public key to get the final key.
    #
    # Note that this is probably done more efficiently with bit shifting.
    # Doing here with strings for readability.
    #
    # The [2:] is needed to remove the 0x in front of the string.
    pub_x = hex(public_key.x)[2:]
    pub_y = hex(public_key.y)[2:]
    return int(pub_x + pub_y, 16)

def get_ethereum_address(public_key: int) -> int:
    '''
    Extracts an ethereum address from a public key by hashing the public key with
    Keccak-256, and then keeping only the last 20 bytes.

    Note that Keccak-256 is the hashing standard for ethereum, NOT SHA3.
    Quite often, when you see SHA3 they are actually refering to Keccak-256.
    See the ethereum book chapter 4 to know how to tell the difference.
    
    The digest size (the size of the hash) is defined as 256 bits as per standard 
    (hence keccak 256).
    '''
    pub_key_hash = keccak.new(digest_bits=256)
    pub_key_hash.update(public_key.to_bytes(64, 'big')) # public keys are 64 bytes
    hash_bytes = pub_key_hash.digest()[-20:] # keeps last 20 bytes
    return int.from_bytes(hash_bytes, 'big')
