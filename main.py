import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def main():
    one_day = datetime.timedelta(days=1)
    today = datetime.date.today()
    yest = today - one_day
    tom = today + one_day
    yesterday = datetime.datetime(yest.year, yest.month, yest.day)
    tomorrow = datetime.datetime(tom.year, tom.month, tom.day)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'Simple Test CA'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Organization'),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')
    ])

    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(ca_name)
    builder = builder.issuer_name(ca_name)
    builder = builder.not_valid_before(yesterday)
    builder = builder.not_valid_after(tomorrow)
    builder = builder.serial_number(12345)  # x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )
    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())
    public_bytes = certificate.public_bytes(
        encoding=serialization.Encoding.PEM)
    with open("certs/root_ca.key", "wb") as fout:
        fout.write(private_bytes)
    with open("certs/root_ca.crt", "wb") as fout:
        fout.write(public_bytes)

    ca_public_bytes = public_bytes

    print('-----------------------------------------------')

    service_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    service_public_key = service_private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'service.test.local')
    ]))
    builder = builder.issuer_name(ca_name)
    builder = builder.serial_number(456789)
    builder = builder.not_valid_before(yesterday)
    builder = builder.not_valid_after(tomorrow)
    builder = builder.public_key(service_public_key)
    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    private_bytes = service_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())
    public_bytes = certificate.public_bytes(
        encoding=serialization.Encoding.PEM)
    with open("certs/service.test.local.crt", "wb") as fout:
        fout.write(public_bytes+ca_public_bytes)
    with open("certs/service.test.local.key", "wb") as fout:
        fout.write(private_bytes)

main()
