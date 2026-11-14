"""Independent affine secp256k1 oracle for offline review; not constant-time."""
P=2**256-2**32-977
N=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
G=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
def add(a,b):
 if a is None:return b
 if b is None:return a
 x,y=a;u,v=b
 if x==u and (y+v)%P==0:return None
 slope=((3*x*x)*pow(2*y,-1,P) if a==b else (v-y)*pow((u-x)%P,-1,P))%P
 xx=(slope*slope-x-u)%P
 return xx,(slope*(x-xx)-y)%P
def mul(k,q):
 if k<0:return mul(-k,(q[0],(-q[1])%P))
 out=None
 while k:
  if k&1:out=add(out,q)
  q=add(q,q);k>>=1
 return out
def recover(digest,signature):
 assert len(digest)==32 and len(signature)==65
 rec=signature[0];r=int.from_bytes(signature[1:33],'big');s=int.from_bytes(signature[33:],'big')
 assert 0<=rec<=3 and 0<r<N and 0<s<=N//2
 x=r+(rec>>1)*N;assert x<P
 y=pow((x*x*x+7)%P,(P+1)//4,P);assert y*y%P==(x*x*x+7)%P
 if y&1 != rec&1:y=P-y
 R=x,y;assert mul(N,R) is None
 q=mul(pow(r,-1,N),add(mul(s,R),mul(-int.from_bytes(digest,'big'),G)))
 assert q is not None
 return q
def branch_vector():
 z=2;s=1
 for r in range(1,100):
  x=N+r;v=(x*x*x+7)%P;y=pow(v,(P+1)//4,P)
  if y*y%P==v:
   rec=2|(y&1);sig=bytes([rec])+r.to_bytes(32,'big')+s.to_bytes(32,'big')
   digest=z.to_bytes(32,'big');return digest,sig,recover(digest,sig)
 raise AssertionError('No point found')
def verify(digest,signature,q):
 try:recovered=recover(digest,signature)
 except (AssertionError,ValueError):return False
 r=int.from_bytes(signature[1:33],'big');s=int.from_bytes(signature[33:],'big');z=int.from_bytes(digest,'big')
 x=add(mul(z*pow(s,-1,N)%N,G),mul(r*pow(s,-1,N)%N,q))
 return recovered==q and x is not None and x[0]%N==r
if __name__=='__main__':
 from cryptography.hazmat.primitives.asymmetric import ec,utils
 from cryptography.hazmat.primitives import hashes
 digest,sig,q=branch_vector();r=int.from_bytes(sig[1:33],'big');s=int.from_bytes(sig[33:],'big')
 public=ec.EllipticCurvePublicNumbers(q[0],q[1],ec.SECP256K1()).public_key()
 public.verify(utils.encode_dss_signature(r,s),digest,ec.ECDSA(utils.Prehashed(hashes.SHA256())))
 assert verify(digest,sig,q) and not verify(digest,bytes([sig[0]^1])+sig[1:],q)
 print('Oracle controls PASS: x=r+n branch independently verifies with cryptography; recovery-id mutation rejected; no private key output.')
