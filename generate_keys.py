import json
import base64
from cryptography.hazmat.primitives.asymmetric import ec


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def private_key_to_jwk(private_key):
    private_numbers = private_key.private_numbers()
    public_numbers = private_key.public_key().public_numbers()

    return {
        "kty": "EC",
        "crv": "P-256",
        "d": b64url_encode(private_numbers.private_value.to_bytes(32, "big")),
        "x": b64url_encode(public_numbers.x.to_bytes(32, "big")),
        "y": b64url_encode(public_numbers.y.to_bytes(32, "big")),
    }


def public_key_to_jwk(public_key):
    public_numbers = public_key.public_numbers()

    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(public_numbers.x.to_bytes(32, "big")),
        "y": b64url_encode(public_numbers.y.to_bytes(32, "big")),
    }


# --------------------------
# Generate Key Pair
# --------------------------
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

private_jwk = private_key_to_jwk(private_key)
public_jwk = public_key_to_jwk(public_key)

# Base64(JSON)
private_jwk_b64 = base64.b64encode(
    json.dumps(private_jwk, separators=(",", ":")).encode("utf-8")
).decode("utf-8")

public_jwk_b64 = base64.b64encode(
    json.dumps(public_jwk, separators=(",", ":")).encode("utf-8")
).decode("utf-8")

print("\n========== COPY TO RENDER ==========\n")

print(f"SERVER_PRIVATE_JWK_B64={private_jwk_b64}\n")
print(f"SERVER_PUBLIC_JWK_B64={public_jwk_b64}\n")

print("====================================")