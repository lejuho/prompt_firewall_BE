from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
import base64

# 1) 키 생성
private_key = ec.generate_private_key(ec.SECP256K1())
public_key = private_key.public_key()

# 2) 공개키 PEM 출력 (이걸 Vercel PUBLIC_KEY_PEM_DEFAULT에 넣기)
pem_pub = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print(pem_pub.decode())

# 3) 메시지 (원하는 걸로 바꿔도 됨. 단, 서버에 보내는 message와 EXACT MATCH)
message = "hello trusted world"
msg_bytes = message.encode("utf-8")

# 4) 서버 로직과 동일: SHA256 해시 후 Prehashed로 서명
h = hashes.Hash(hashes.SHA256())
h.update(msg_bytes)
digest = h.finalize()

signature = private_key.sign(
    digest,
    ec.ECDSA(Prehashed(hashes.SHA256()))
)

sig_b64 = base64.b64encode(signature).decode()

print("message:", message)
print("signature_b64:", sig_b64)
