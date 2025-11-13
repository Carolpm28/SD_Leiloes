"""
Certificate Authority (CA) em memória
Aceita ficheiros PEM diretamente (sem paths)
"""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import datetime


class AuctionCA:
    """
    Certificate Authority (CA) em memória
    Pode ser criada a partir de PEMs existentes ou gerar novos.
    """

    def __init__(self, ca_key_pem=None, ca_cert_pem=None):
        self.backend = default_backend()

        if ca_key_pem and ca_cert_pem:
            # Se PEMs foram passados, carregar diretamente
            self.ca_private_key = serialization.load_pem_private_key(
                ca_key_pem.encode() if isinstance(ca_key_pem, str) else ca_key_pem,
                password=None,
                backend=self.backend
            )
            self.ca_cert = x509.load_pem_x509_certificate(
                ca_cert_pem.encode() if isinstance(ca_cert_pem, str) else ca_cert_pem,
                self.backend
            )
            print("✓ CA loaded from PEM data")
        else:
            # Criar nova CA
            print("Creating new in-memory CA...")
            self.ca_private_key, self.ca_cert = self._create_ca()
            print("✓ New CA generated")

    def _create_ca(self):
        """Cria uma nova chave e certificado autoassinado"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=self.backend
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Porto"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Porto"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Auction System CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "auction-ca.local"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(private_key, hashes.SHA256(), self.backend)
        )

        return private_key, cert

    def issue_certificate(self, user_id, username, user_public_key, validity_days=365):
        """Emite certificado X.509 para utilizador"""
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Auction System"),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
            x509.NameAttribute(NameOID.USER_ID, user_id),
        ])

        issuer = self.ca_cert.subject

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(user_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self.ca_private_key, hashes.SHA256(), self.backend)
        )

        return cert.public_bytes(serialization.Encoding.PEM).decode()

    def verify_certificate(self, cert_pem):
        """Verifica se um certificado foi emitido por esta CA"""
        try:
            cert = x509.load_pem_x509_certificate(
                cert_pem.encode() if isinstance(cert_pem, str) else cert_pem,
                self.backend
            )

            if cert.issuer != self.ca_cert.subject:
                return False, None, None

            self.ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )

            now = datetime.datetime.utcnow()
            if now < cert.not_valid_before or now > cert.not_valid_after:
                return False, None, None

            username = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            user_id = cert.subject.get_attributes_for_oid(NameOID.USER_ID)[0].value
            return True, user_id, username

        except Exception as e:
            print(f"Certificate verification error: {e}")
            return False, None, None

    def get_ca_certificate_pem(self):
        """Retorna o certificado da CA em PEM"""
        return self.ca_cert.public_bytes(serialization.Encoding.PEM).decode()

    def get_ca_private_key_pem(self):
        """Retorna a chave privada da CA em PEM"""
        return self.ca_private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode()


# 🔧 Teste rápido
if __name__ == "__main__":
    from cryptography.hazmat.primitives.asymmetric import rsa

    ca = AuctionCA()  # Cria nova CA em memória
    print("\nCA certificate:\n", ca.get_ca_certificate_pem()[:120], "...")

    # Gerar chave de utilizador
    user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert_pem = ca.issue_certificate("user123", "alice", user_key.public_key())
    print("\nUser certificate:\n", cert_pem[:120], "...")

    valid, uid, uname = ca.verify_certificate(cert_pem)
    print(f"✓ Verification: {valid}, user={uname}, id={uid}")
