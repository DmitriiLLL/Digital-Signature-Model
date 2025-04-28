import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class DigitalSignatureSystem:
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self._generate_keys()

    def _generate_keys(self):
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        self._public_key = self._private_key.public_key()

    def export_private_key(self) -> bytes:
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def export_public_key(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def verify(self, message: bytes, signature: bytes, public_key_pem: bytes = None) -> bool:
        public_key = serialization.load_pem_public_key(
            public_key_pem, backend=default_backend()
        ) if public_key_pem else self._public_key
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

if __name__ == "__main__":
    system = DigitalSignatureSystem()
    with open('private_key.pem', 'wb') as f:
        f.write(system.export_private_key())
    with open('public_key.pem', 'wb') as f:
        f.write(system.export_public_key())

    action = input("Выберите действие (1 - Подписать и проверить, 2 - Только проверить): ")

    if action == '1':
        text = input("Введите сообщение для подписи: ")
        msg_bytes = text.encode('utf-8')
        signature = system.sign(msg_bytes)
        sig_b64 = base64.b64encode(signature).decode('utf-8')
        print("Signature (Base64):", sig_b64)
        valid = system.verify(msg_bytes, signature)
        print("Проверка подписи:", "действительна" if valid else "недействительна")

    elif action == '2':
        text = input("Введите сообщение для проверки: ")
        sig_b64 = input("Введите подпись (Base64): ")
        msg_bytes = text.encode('utf-8')
        signature = base64.b64decode(sig_b64)
        pub_pem = open('public_key.pem', 'rb').read()
        valid = system.verify(msg_bytes, signature, public_key_pem=pub_pem)
        print("Подпись действительна" if valid else "Подпись недействительна")

    else:
        print("Неверный выбор")