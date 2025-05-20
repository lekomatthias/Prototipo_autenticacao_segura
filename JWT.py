import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from time import time

class JWT:

    @staticmethod
    def base64url_encode(data):
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')
    
    @staticmethod
    def base64url_decode(data):
        return base64.urlsafe_b64decode(data + ('=' * (-len(data) % 4)))

    @staticmethod
    def create_jwt(payload, private_key):
        header = {
            "alg": "RS256",
            "typ": "JWT"
        }
        header_b64 = JWT.base64url_encode(json.dumps(header, separators=(',', ':')).encode())
        payload_b64 = JWT.base64url_encode(json.dumps(payload, separators=(',', ':')).encode())
        message = f"{header_b64}.{payload_b64}".encode()
        # Assina com RSA (PKCS1 v1.5 + SHA256)
        signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        signature_b64 = JWT.base64url_encode(signature)

        jwt_token = f"{header_b64}.{payload_b64}.{signature_b64}"
        return jwt_token

    @staticmethod
    def verify_jwt(token, public_key):
        try:
            header_b64, payload_b64, signature_b64 = token.split('.')
            message = f"{header_b64}.{payload_b64}".encode()
            signature = JWT.base64url_decode(signature_b64)
            print("Assinatura decodificada no token RSA.")
            public_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            print("Assinatura verificada com sucesso.")
            payload_json = JWT.base64url_decode(payload_b64)
            payload = json.loads(payload_json)

            if "exp" in payload:
                if time() > payload["exp"]:
                    print("Token expirado")
                    raise Exception("Token expirado")

            return True

        except:
            return False

if __name__ == "__main__":

    from RSA import RSA

    payload = {
        "user_id": 123,
        "exp": int(time()) + 3600
    }

    private_key, public_key = RSA.KeyGen()
    token = JWT.create_jwt(payload, private_key)
    print("Token JWT:", token)

    print(f"Token { 'validado' if (JWT.verify_jwt(token, public_key)) else 'rejeitado'}.")
