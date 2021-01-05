import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import random

def gen_root():
    one_day = datetime.timedelta(days=1)
    today = datetime.date.today()
    yest = today - one_day
    tom = today + one_day
    yesterday = datetime.datetime(yest.year, yest.month, yest.day)
    tomorrow = datetime.datetime(tom.year, tom.month, tom.day)
    print('---------------------Root--------------------------')
    root_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    root_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Simple Root CA'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Organization'),
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US')
    ])

    root_public_key = root_private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(root_name)
    builder = builder.issuer_name(root_name)
    builder = builder.not_valid_before(yesterday)
    builder = builder.not_valid_after(tomorrow)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(root_public_key)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )
    certificate = builder.sign(
        private_key=root_private_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    private_bytes = root_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())
    public_bytes = certificate.public_bytes(
        encoding=serialization.Encoding.PEM)
    with open("certs/root_ca.key", "wb") as fout:
        fout.write(private_bytes)
    with open("certs/root_ca.crt", "wb") as fout:
        fout.write(public_bytes)


def gen_ca(root_name, root_private_key):
    one_day = datetime.timedelta(days=1)
    today = datetime.date.today()
    yest = today - one_day
    tom = today + one_day
    yesterday = datetime.datetime(yest.year, yest.month, yest.day)
    tomorrow = datetime.datetime(tom.year, tom.month, tom.day)
    print('---------------------CA--------------------------')
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Simple Test CA'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Organization'),
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US')
    ])

    ca_public_key = ca_private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(ca_name)
    builder = builder.issuer_name(root_name)
    builder = builder.not_valid_before(yesterday)
    builder = builder.not_valid_after(tomorrow)
    builder = builder.serial_number(x509.random_serial_number())  # x509.random_serial_number())
    builder = builder.public_key(ca_public_key)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )
    certificate = builder.sign(
        private_key=root_private_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    private_bytes = ca_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())
    public_bytes = certificate.public_bytes(
        encoding=serialization.Encoding.PEM)
    with open("certs/intermedia_ca.key", "wb") as fout:
        fout.write(private_bytes)
    with open("certs/intermedia_ca.crt", "wb") as fout:
        fout.write(public_bytes)

def gen_service(ca_cert, ca_private_key, domain):
    one_day = datetime.timedelta(days=1)
    today = datetime.date.today()
    yest = today - one_day
    tom = today + one_day
    yesterday = datetime.datetime(yest.year, yest.month, yest.day)
    tomorrow = datetime.datetime(tom.year, tom.month, tom.day)
    print('-------------------Service------------------------')
    service_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    service_public_key = service_private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain)
    ]))
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(yesterday)
    builder = builder.not_valid_after(tomorrow)
    builder = builder.public_key(service_public_key)

    builder = builder.add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(domain),
            x509.DNSName('www.%s' %domain),
        ]),
        critical=False
    )

    certificate = builder.sign(
        private_key=ca_private_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    private_bytes = service_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = certificate.public_bytes(
        encoding=serialization.Encoding.PEM)

    ca_public_bytes = ca_cert.public_bytes(encoding=serialization.Encoding.PEM)
    with open("certs/%s.crt" %domain, "wb") as fout:
        fout.write(public_bytes+ca_public_bytes)
    with open("certs/%s.key" %domain, "wb") as fout:
        fout.write(private_bytes)

def load_key(filename):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = load_pem_private_key(pemlines, None, default_backend())
    return private_key

def load_cert(filename):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    cert = load_pem_x509_certificate(pemlines, default_backend())
    return cert

def main():
    ca_private_key = load_key("ca/intermedia_ca.key")
    ca_cert = load_cert("ca/intermedia_ca.crt")
    gen_service(ca_cert, ca_private_key, 'yolo.example.com')


main()
