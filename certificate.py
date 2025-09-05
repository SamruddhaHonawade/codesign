import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes

def create_self_signed_cert(private_key, subject_name: str, valid_days=365, is_ca=False):
    """Creates a detailed self-signed X.509 certificate and prints details."""

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Karnataka"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Bengaluru"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyCompany Pvt Ltd"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Software Division"),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, "support@mycompany.com"),
    ])

    now = datetime.datetime.utcnow()

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()), critical=False)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,  # for code signing
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("mycompany.com"),
                x509.RFC822Name("security@mycompany.com"),
            ]),
            critical=False,
        )
    )

    cert = cert_builder.sign(private_key, hashes.SHA256())

    # === Print details ===
    print("\n=== Certificate Details ===")
    print("Subject:", cert.subject.rfc4514_string())
    print("Issuer:", cert.issuer.rfc4514_string())
    print("Serial Number:", cert.serial_number)
    print("Validity:")
    print("   Not Before:", cert.not_valid_before)
    print("   Not After :", cert.not_valid_after)
    print("Signature Algorithm:", cert.signature_hash_algorithm.name)

    print("\nExtensions:")
    for ext in cert.extensions:
        print(f" - {ext.oid._name} (critical={ext.critical}): {ext.value}")

    return cert
