from hashlib import sha256
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
from secp256k1_oracle import *
key=SigningKey.from_secret_exponent(7,curve=SECP256k1,hashfunc=sha256)
digest=sha256(b"offline compact signature review").digest()
sig=key.sign_digest_recoverable_compact(digest)
pub=key.verifying_key
print("Offline signature / generated test key")
print("Encoded length:",len(sig),"bytes")
print("Recovery id:",sig[0])
print("Low-S:",int.from_bytes(sig[33:],"big")<=SECP256k1.order//2)
print("Bound-key verification:",pub.verify_digest_recoverable_compact(sig,digest))
recovered=VerifyingKey.from_recoverable_compact_signature(sig,digest)
print("Recovered key matches:",recovered.to_string()==pub.to_string())
print("Classic verification:",pub.verify_digest(sig[1:],digest))
for name,bad,changed in [("Changed recovery id",bytes([sig[0]^1])+sig[1:],digest),("Changed digest",sig,sha256(b"changed").digest()),("Short signature",sig[:-1],digest)]:
 try:
  pub.verify_digest_recoverable_compact(bad,changed)
 except BadSignatureError:
  print(name+": rejected")
 else:
  raise AssertionError(name+" was accepted")
print("All demonstrated checks passed.")
