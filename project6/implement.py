
import hashlib, secrets
from typing import List, Tuple, Set
from ecdsa import curves, ellipticcurve, numbertheory
from phe import paillier

Curve = curves.NIST256p
G = Curve.generator
n = Curve.order
Fp = Curve.curve.p()
a = Curve.curve.a()
b = Curve.curve.b()

def tonelli_shanks(n_, p):
    assert 0 <= n_ < p
    if n_ == 0: return 0
    if p % 4 == 3: return pow(n_, (p+1)//4, p)
  
    q, s = p-1, 0
    while q % 2 == 0:
        q //= 2; s += 1

    z = 2
    while pow(z, (p-1)//2, p) != p-1: z += 1
    c = pow(z, q, p)
    r = pow(n_, (q+1)//2, p)
    t = pow(n_, q, p)
    m = s
    while t != 1:
        i, t2 = 1, pow(t, 2, p)
        while i < m and t2 != 1:
            t2 = pow(t2, 2, p); i += 1
        b_ = pow(c, 1 << (m - i - 1), p)
        r = (r * b_) % p
        t = (t * b_ * b_) % p
        c = (b_ * b_) % p
        m = i
    return r

def point_compress(P: ellipticcurve.Point) -> bytes:
    x = int(P.x()); y = int(P.y())
    prefix = 0x03 if (y & 1) else 0x02
    return bytes([prefix]) + x.to_bytes(32, 'big')

def point_decompress(data: bytes) -> ellipticcurve.Point:
    assert len(data) == 33 and data[0] in (2,3)
    x = int.from_bytes(data[1:], 'big')
    rhs = (pow(x, 3, Fp) + a * x + b) % Fp  # y^2
    y = tonelli_shanks(rhs, Fp)
    if (y & 1) != (data[0] & 1): y = Fp - y
    return ellipticcurve.Point(Curve.curve, x, y)


def H_to_point(identifier: str) -> ellipticcurve.Point:
    h = hashlib.sha256(identifier.encode('utf-8')).digest()
    s = int.from_bytes(h, 'big') % n
    if s == 0: s = 1
    return s * G  # P = s·G

def rand_scalar() -> int:
    return secrets.randbelow(n-1) + 1


class P1: 
    def __init__(self, V: List[str], pk):
        self.V = V
        self.k1 = rand_scalar()
        self.pk = pk
        self.Z: Set[bytes] = set()  

  
    def round1(self) -> List[bytes]:
        out = []
        for v in self.V:
            P = H_to_point(v)
            A = self.k1 * P
            out.append(point_compress(A))
        return out

 
    def recv_round2_Z(self, Z_list: List[bytes]):
        self.Z = set(Z_list)


    def round3_sum_cipher(self, pairs_from_P2: List[Tuple[bytes, paillier.EncryptedNumber]]) -> paillier.EncryptedNumber:
      
        for hwk2_bytes, enc_tj in pairs_from_P2:
            hwk2 = point_decompress(hwk2_bytes)
            hwk1k2 = self.k1 * hwk2
            tag = point_compress(hwk1k2)
            if tag in self.Z:
                csum = csum + enc_tj  
      
        csum = csum + self.pk.encrypt(0)
        return csum

class P2:  
    def __init__(self, W: List[Tuple[str, int]]):
        self.W = W
        self.k2 = rand_scalar()
        self.pk, self.sk = paillier.generate_paillier_keypair()

   
    def get_public_key(self): return self.pk


    def round2(self, from_P1_list: List[bytes]) -> Tuple[List[bytes], List[Tuple[bytes, paillier.EncryptedNumber]]]:
        Z = []
        for a_bytes in from_P1_list:
            A = point_decompress(a_bytes)      
            B = self.k2 * A                   
            Z.append(point_compress(B))
        pairs = []
        for w, t in self.W:
            P = H_to_point(w)
            hwk2 = self.k2 * P                 
            pairs.append((point_compress(hwk2), self.pk.encrypt(int(t))))
        return Z, pairs

    
    def output_sum(self, csum: paillier.EncryptedNumber) -> int:
        return self.sk.decrypt(csum)

if __name__ == "__main__":
  
    V = ["alice", "bob", "charlie", "dave"]
    W = [("eve", 5), ("bob", 7), ("charlie", 11), ("frank", 3)]

    P2_party = P2(W)
    P1_party = P1(V, P2_party.get_public_key())

  
    msg1 = P1_party.round1()

    
    Z, pairs = P2_party.round2(msg1)
    P1_party.recv_round2_Z(Z)

   
    csum = P1_party.round3_sum_cipher(pairs)

   
    SJ = P2_party.output_sum(csum)
    print("Intersection:", set(V).intersection({w for w, _ in W}))
    print("Sum over intersection t_j (by P2):", SJ)
   
