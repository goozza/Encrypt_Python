import os
import json
import base64
import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# ตั้งค่า logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = FastAPI()

# -------------------- CORS --------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],   # ปรับตาม FE
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- ฟังก์ชัน Base64 (แยกตามประเภท) ----------
def b64_std_encode(data: bytes) -> str:
    """Base64 standard (มี padding) ใช้กับ payload"""
    return base64.b64encode(data).decode()

def b64_std_decode(data: str) -> bytes:
    """Base64 standard (มี padding) ใช้กับ payload"""
    return base64.b64decode(data)

def b64url_encode(data: bytes) -> str:
    """Base64url (ไม่มี padding) ใช้กับ JWK"""
    return base64.urlsafe_b64encode(data).decode().rstrip('=')

def b64url_decode(data: str) -> bytes:
    """Base64url (ไม่มี padding) ใช้กับ JWK"""
    # เติม padding ให้ถูกต้อง (ความยาวต้องเป็นทวีคูณของ 4)
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)

# ---------- แปลง JWK <-> CryptoKey (ใช้ base64url) ----------
def jwk_to_private_key(jwk: dict):
    d_bytes = b64url_decode(jwk['d'])
    private_value = int.from_bytes(d_bytes, 'big')
    return ec.derive_private_key(private_value, ec.SECP256R1())

def jwk_to_public_key(jwk: dict):
    x_bytes = b64url_decode(jwk['x'])
    y_bytes = b64url_decode(jwk['y'])
    x_int = int.from_bytes(x_bytes, 'big')
    y_int = int.from_bytes(y_bytes, 'big')
    public_numbers = ec.EllipticCurvePublicNumbers(x_int, y_int, ec.SECP256R1())
    return public_numbers.public_key()

def private_key_to_jwk(private_key):
    private_numbers = private_key.private_numbers()
    public_numbers = private_key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "d": b64url_encode(private_numbers.private_value.to_bytes(32, 'big')),
        "x": b64url_encode(public_numbers.x.to_bytes(32, 'big')),
        "y": b64url_encode(public_numbers.y.to_bytes(32, 'big')),
    }

def public_key_to_jwk(public_key):
    public_numbers = public_key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(public_numbers.x.to_bytes(32, 'big')),
        "y": b64url_encode(public_numbers.y.to_bytes(32, 'big')),
    }

# ---------- โหลด Server Keys ----------
SERVER_PRIVATE_KEY = None
SERVER_PUBLIC_JWK = None

def get_server_keys():
    global SERVER_PRIVATE_KEY, SERVER_PUBLIC_JWK
    if SERVER_PRIVATE_KEY is not None:
        return SERVER_PRIVATE_KEY, SERVER_PUBLIC_JWK

    private_jwk_b64 = os.getenv("SERVER_PRIVATE_JWK_B64")
    public_jwk_b64 = os.getenv("SERVER_PUBLIC_JWK_B64")

    if private_jwk_b64 and public_jwk_b64:
        private_jwk = json.loads(base64.b64decode(private_jwk_b64).decode())
        public_jwk = json.loads(base64.b64decode(public_jwk_b64).decode())
        private_key = jwk_to_private_key(private_jwk)
        logger.info("✅ โหลด server keys จาก Environment สำเร็จ")
    else:
        # สร้างใหม่ (เฉพาะ dev)
        logger.warning("⚠️ ไม่พบ SERVER_*_JWK_B64, สร้างคู่ใหม่ชั่วคราว")
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        private_jwk = private_key_to_jwk(private_key)
        public_jwk = public_key_to_jwk(public_key)
        # แสดงค่าที่ต้องใส่ใน .env
        print("\n🔑  เก็บ Environment เหล่านี้:")
        print(f"SERVER_PRIVATE_JWK_B64={base64.b64encode(json.dumps(private_jwk).encode()).decode()}")
        print(f"SERVER_PUBLIC_JWK_B64={base64.b64encode(json.dumps(public_jwk).encode()).decode()}\n")

    SERVER_PRIVATE_KEY = private_key
    SERVER_PUBLIC_JWK = public_jwk
    return SERVER_PRIVATE_KEY, SERVER_PUBLIC_JWK

# ---------- ฟังก์ชัน ECDH + AES-GCM ----------
def derive_shared_key(client_public_jwk: dict, server_private_key):
    client_public = jwk_to_public_key(client_public_jwk)
    shared_secret = server_private_key.exchange(ec.ECDH(), client_public)
    # shared_secret คือ 32 bytes (ตรงกับ Web Crypto)
    return shared_secret

def encrypt_aes_gcm(key: bytes, plaintext: bytes):
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # รวม tag
    return nonce, ciphertext

def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

# ---------- Endpoint: /api/public-key ----------
@app.get("/api/public-key")
async def get_public_key(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    _, public_jwk = get_server_keys()
    return {"serverPublicKeyJwk": public_jwk}

# ---------- Wrapper สำหรับ Secure POST ----------
async def handle_secure_post(request: Request, handler):
    # token = request.cookies.get("access_token")
    # if not token:
    #     raise HTTPException(status_code=401, detail="Unauthorized")

    body = await request.json()
    client_public_jwk = body.get("clientPublicKeyJwk")
    payload = body.get("payload")

    if not client_public_jwk or not payload:
        raise HTTPException(status_code=400, detail="Missing fields")

    # 1. Derive shared key
    server_private, _ = get_server_keys()
    shared_key = derive_shared_key(client_public_jwk, server_private)
    logger.debug("✅ Shared key derived (length %d)", len(shared_key))

    # 2. Decrypt request payload
    try:
        iv_b64 = payload.get("iv")
        ciphertext_b64 = payload.get("ciphertext")
        nonce = b64_std_decode(iv_b64)
        ciphertext = b64_std_decode(ciphertext_b64)

        decrypted_bytes = decrypt_aes_gcm(shared_key, nonce, ciphertext)
        decrypted_data = json.loads(decrypted_bytes.decode('utf-8'))
        logger.debug("✅ Decrypted data: %s", decrypted_data)
    except Exception as e:
        logger.error("❌ Decryption failed: %s", str(e), exc_info=True)
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

    # 3. เรียก handler
    response_data = await handler(decrypted_data)

    # 4. Encrypt response
    response_bytes = json.dumps(response_data, ensure_ascii=False).encode('utf-8')
    resp_nonce, resp_ciphertext = encrypt_aes_gcm(shared_key, response_bytes)

    return {
        "iv": b64_std_encode(resp_nonce),
        "ciphertext": b64_std_encode(resp_ciphertext)
    }

# ---------- ตัวอย่าง Endpoint ----------
@app.post("/api/secure-data")
async def secure_data(request: Request):
    async def handler(decrypted):
        name = decrypted.get("name", "World")
        return {"message": f"Hello {name}!"}
    return await handle_secure_post(request, handler)

# ---------- รัน ----------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)