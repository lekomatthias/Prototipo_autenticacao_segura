import hmac
import hashlib
import base64
import json
import time

class JWT_HS256:

    @staticmethod
    def base64url_encode(data):
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

    @staticmethod
    def base64url_decode(data):
        return base64.urlsafe_b64decode(data + ('=' * (-len(data) % 4)))

    @staticmethod
    def _tag(secret_key, msg):
        return hmac.new(secret_key, msg, hashlib.sha256).digest()

    @staticmethod
    def create_jwt(payload, secret_key):
        header = {
            "alg": "HS256",
            "typ": "JWT"
        }
        header_b64 = JWT_HS256.base64url_encode(json.dumps(header, separators=(',', ':')).encode())
        payload_b64 = JWT_HS256.base64url_encode(json.dumps(payload, separators=(',', ':')).encode())
        message = f"{header_b64}.{payload_b64}".encode()
        signature = JWT_HS256._tag(secret_key, message)
        signature_b64 = JWT_HS256.base64url_encode(signature)
        return f"{header_b64}.{payload_b64}.{signature_b64}"

    @staticmethod
    def verify_jwt(token, secret_key):
        try:
            header_b64, payload_b64, signature_b64 = token.split('.')
            message = f"{header_b64}.{payload_b64}".encode()
            signature = JWT_HS256.base64url_decode(signature_b64)

            if not hmac.compare_digest(JWT_HS256._tag(secret_key, message), signature):
                return False

            payload_json = JWT_HS256.base64url_decode(payload_b64)
            payload = json.loads(payload_json)

            if "exp" in payload and time.time() > payload["exp"]:
                return False

            return True
        except Exception:
            return False


if __name__ == "__main__":
    secret = b"Troque-por-32-bytes-aleatorios-&-secretos"
    payload = {
        "user_id": 123,
        "exp": int(time.time()) + 3600
    }

    token = JWT_HS256.create_jwt(payload, secret)
    print("Token JWT:", token)

    print(f"Token {'validado' if JWT_HS256.verify_jwt(token, secret) else 'rejeitado'}.")
