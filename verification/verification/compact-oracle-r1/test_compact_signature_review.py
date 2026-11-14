"""Independent secp256k1 compact signature acceptance, not a roundtrip oracle."""
import hashlib,hmac
import pytest
from ecdsa import SigningKey,VerifyingKey,SECP256k1,NIST256p,BadSignatureError,BadDigestError
from ecdsa.util import sigencode_der,sigdecode_der
from secp256k1_oracle import N,P,G,add,mul,recover,verify,branch_vector

def deterministic_nonce(secret,digest):
    x=secret.to_bytes(32,'big');h=(int.from_bytes(digest,'big')%N).to_bytes(32,'big');v=b'\x01'*32;k=b'\0'*32
    H=lambda key,data:hmac.new(key,data,hashlib.sha256).digest()
    k=H(k,v+b'\0'+x+h);v=H(k,v);k=H(k,v+b'\x01'+x+h);v=H(k,v)
    while True:
        v=H(k,v);candidate=int.from_bytes(v,'big')
        if 1<=candidate<N:return candidate
        k=H(k,v+b'\0');v=H(k,v)

def expected_signature(secret,digest):
    k=deterministic_nonce(secret,digest);point=mul(k,G);r=point[0]%N;s=(pow(k,-1,N)*(int.from_bytes(digest,'big')+r*secret))%N
    rec=(2 if point[0]>=N else 0)|(point[1]&1);flipped=s>N//2
    if flipped:s=N-s;rec^=1
    return bytes([rec])+r.to_bytes(32,'big')+s.to_bytes(32,'big'),flipped

def key_for(point):return VerifyingKey.from_string(point[0].to_bytes(32,'big')+point[1].to_bytes(32,'big'),curve=SECP256k1)

@pytest.mark.parametrize('secret',[1,7,17])
@pytest.mark.parametrize('number',[0,2,N,N+1,2**256-1])
def test_independent_rfc6979_low_s_and_recovery_binding(secret,number):
    digest=number.to_bytes(32,'big');sk=SigningKey.from_secret_exponent(secret,curve=SECP256k1,hashfunc=hashlib.sha256)
    actual=sk.sign_digest_recoverable_compact(digest,hashfunc=hashlib.sha256);expected,flipped=expected_signature(secret,digest)
    assert actual==expected
    assert actual==sk.sign_digest_recoverable_compact(digest,hashfunc=hashlib.sha256)
    assert verify(digest,actual,mul(secret,G)) and recover(digest,actual)==mul(secret,G)
    vk=sk.verifying_key;assert vk.verify_digest_recoverable_compact(actual,digest)
    assert vk.verify_digest(actual[1:],digest)
    recovered=VerifyingKey.from_recoverable_compact_signature(actual,digest)
    assert recovered.to_string()==vk.to_string()
    for rec in range(4):
        if rec!=actual[0]:
            with pytest.raises(BadSignatureError):vk.verify_digest_recoverable_compact(bytes([rec])+actual[1:],digest)

@pytest.mark.parametrize('parity',[0,1])
def test_x_r_plus_n_branch_independent_vector(parity):
    digest,sig,point=branch_vector();sig=bytes([2|parity])+sig[1:];point=recover(digest,sig);vk=key_for(point)
    assert verify(digest,sig,point)
    assert vk.verify_digest(sig[1:],digest)
    assert vk.verify_digest_recoverable_compact(sig,digest)
    assert VerifyingKey.from_recoverable_compact_signature(sig,digest).to_string()==vk.to_string()
    from cryptography.hazmat.primitives.asymmetric import ec,utils
    from cryptography.hazmat.primitives import hashes
    r=int.from_bytes(sig[1:33],'big');s=int.from_bytes(sig[33:],'big')
    ec.EllipticCurvePublicNumbers(point[0],point[1],ec.SECP256K1()).public_key().verify(utils.encode_dss_signature(r,s),digest,ec.ECDSA(utils.Prehashed(hashes.SHA256())))

@pytest.mark.parametrize('length',[0,1,31,33,64])
def test_digest_exact_length_all_three_entries(length):
    sk=SigningKey.from_secret_exponent(7,curve=SECP256k1);vk=sk.verifying_key;sig=expected_signature(7,b'\0'*32)[0]
    with pytest.raises(BadDigestError):sk.sign_digest_recoverable_compact(b'\0'*length)
    with pytest.raises(BadDigestError):vk.verify_digest_recoverable_compact(sig,b'\0'*length)
    with pytest.raises(BadDigestError):VerifyingKey.from_recoverable_compact_signature(sig,b'\0'*length)

@pytest.mark.parametrize('length',[0,1,64,66,130])
def test_signature_exact_length(length):
    vk=SigningKey.from_secret_exponent(7,curve=SECP256k1).verifying_key
    with pytest.raises(BadSignatureError):vk.verify_digest_recoverable_compact(b'\0'*length,b'\0'*32)
    with pytest.raises(BadSignatureError):VerifyingKey.from_recoverable_compact_signature(b'\0'*length,b'\0'*32)

@pytest.mark.parametrize('r,s,rec',[(0,1,0),(N,1,0),(1,0,0),(1,N,0),(1,N//2+1,0),(1,1,4),(1,1,255),(P-N,1,2)])
def test_scalar_and_recovery_range(r,s,rec):
    sig=bytes([rec])+r.to_bytes(32,'big')+s.to_bytes(32,'big')
    with pytest.raises(BadSignatureError):VerifyingKey.from_recoverable_compact_signature(sig,b'\0'*32)

def test_non_curve_ephemeral_x_rejected():
    r=next(x for x in range(1,100) if pow((x**3+7)%P,(P-1)//2,P)!=1)
    sig=b'\0'+r.to_bytes(32,'big')+(1).to_bytes(32,'big')
    with pytest.raises(BadSignatureError):VerifyingKey.from_recoverable_compact_signature(sig,b'\0'*32)

def test_recovered_infinity_rejected():
    # R=G, e=1, s=1 => sR-eG is infinity.
    sig=bytes([G[1]&1])+(G[0]%N).to_bytes(32,'big')+(1).to_bytes(32,'big')
    with pytest.raises(BadSignatureError):VerifyingKey.from_recoverable_compact_signature(sig,(1).to_bytes(32,'big'))

def test_high_s_with_parity_flip_rejected_but_classic_still_valid():
    digest=hashlib.sha256(b'offline review').digest();sig=expected_signature(7,digest)[0];vk=key_for(mul(7,G));s=int.from_bytes(sig[33:],'big')
    high=bytes([sig[0]^1])+sig[1:33]+(N-s).to_bytes(32,'big')
    assert vk.verify_digest(high[1:],digest)
    with pytest.raises(BadSignatureError):vk.verify_digest_recoverable_compact(high,digest)
    with pytest.raises(BadSignatureError):VerifyingKey.from_recoverable_compact_signature(high,digest)

def test_old_formats_recovery_and_other_curve_compatibility():
    digest=hashlib.sha256(b'old API').digest();sk=SigningKey.from_secret_exponent(17,curve=SECP256k1,hashfunc=hashlib.sha256);vk=sk.verifying_key
    raw=sk.sign_digest_deterministic(digest,hashfunc=hashlib.sha256);assert vk.verify_digest(raw,digest)
    der=sk.sign_digest_deterministic(digest,hashfunc=hashlib.sha256,sigencode=sigencode_der);assert vk.verify_digest(der,digest,sigdecode=sigdecode_der)
    assert vk.to_string() in [k.to_string() for k in VerifyingKey.from_public_key_recovery_with_digest(raw,digest,curve=SECP256k1)]
    other=SigningKey.from_secret_exponent(17,curve=NIST256p);old=other.sign_digest_deterministic(digest);assert other.verifying_key.verify_digest(old,digest)
    with pytest.raises(ValueError):other.sign_digest_recoverable_compact(digest)
    with pytest.raises(ValueError):other.verifying_key.verify_digest_recoverable_compact(expected_signature(17,digest)[0],digest)

def test_changed_digest_and_non_bytes_input_rejected():
    digest=hashlib.sha256(b'original').digest();sig=expected_signature(7,digest)[0];vk=key_for(mul(7,G))
    with pytest.raises(BadSignatureError):vk.verify_digest_recoverable_compact(sig,hashlib.sha256(b'changed').digest())
    with pytest.raises((TypeError,ValueError)):VerifyingKey.from_recoverable_compact_signature('x'*65,digest)
    with pytest.raises((TypeError,ValueError)):SigningKey.from_secret_exponent(7,curve=SECP256k1).sign_digest_recoverable_compact('x'*32)

def test_control_vectors_cover_actual_s_flip():
    results=[expected_signature(7,x.to_bytes(32,'big'))[1] for x in range(1,12)]
    assert any(results) and not all(results)
