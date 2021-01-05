import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key

FOLDER = "certs"

def gen_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

def gen_cert(issuer_private_key, private_key, subject_name, issuer_name, is_ca=False, filename="", expired_after=90):
    today = datetime.datetime.today() - datetime.timedelta(days=expired_after)
    expired_day = today + datetime.timedelta(days=expired_after)

    ca_public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject_name)
    builder = builder.issuer_name(issuer_name)
    builder = builder.not_valid_before(today)
    builder = builder.not_valid_after(expired_day)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(ca_public_key)
    builder = builder.add_extension(
        x509.BasicConstraints(
            ca=is_ca,
            path_length=None
        ),
        critical=True
    )

    if not is_ca:
        domain = subject_name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(domain),
                x509.DNSName('www.%s' %domain),
            ]),
            critical=False
        )

    certificate = builder.sign(
        private_key=issuer_private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = certificate.public_bytes(
        encoding=serialization.Encoding.PEM
    )
    return private_bytes, public_bytes

def gen_root_ca(common_name='Simple Root CA', filename="root_ca", expired_after=90):
    root_private_key = gen_key()
    root_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Organization'),
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US')
    ])

    private_bytes, public_bytes = gen_cert(
        issuer_private_key=root_private_key,
        private_key=root_private_key,
        subject_name=root_name,
        issuer_name=root_name,
        is_ca=True,
        expired_after=expired_after,
        filename=filename
    )

    with open("%s/%s.key" % (FOLDER, filename), "wb") as fout:
        fout.write(private_bytes)
    with open("%s/%s.crt" % (FOLDER, filename), "wb") as fout:
        fout.write(public_bytes)

def gen_ca(root_cert, root_private_key, common_name='Simple Test CA', filename="intermedia_ca", expired_after=90):
    ca_private_key = gen_key()
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Organization'),
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US')
    ])

    private_bytes, public_bytes = gen_cert(
        issuer_private_key=root_private_key,
        private_key=ca_private_key,
        subject_name=ca_name,
        issuer_name=root_cert.subject,
        is_ca=True,
        expired_after=expired_after,
        filename=filename
    )
    with open("%s/%s.key" %(FOLDER, filename), "wb") as fout:
        fout.write(private_bytes)
    with open("%s/%s.crt" %(FOLDER, filename), "wb") as fout:
        fout.write(public_bytes)

def gen_service(ca_cert, ca_private_key, domain, expired_after=90):
    service_private_key = gen_key()
    service_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain)
    ])

    private_bytes, public_bytes = gen_cert(
        issuer_private_key=ca_private_key,
        private_key=service_private_key,
        subject_name=service_name,
        issuer_name=ca_cert.subject,
        is_ca=False,
        expired_after=expired_after,
        filename=domain
    )

    with open("%s/%s.key" %(FOLDER, domain), "wb") as fout:
        fout.write(private_bytes)
    with open("%s/%s.crt" %(FOLDER, domain), "wb") as fout:
        fout.write(public_bytes + ca_cert.public_bytes(encoding=serialization.Encoding.PEM))

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
    gen_root_ca("Local Root CA")

    root_private_key = load_key("certs/root_ca.key")
    root_cert = load_cert("certs/root_ca.crt")
    gen_ca(
        root_cert=root_cert,
        root_private_key=root_private_key,
        common_name="Local Intermedia CA",
    )

    ca_private_key = load_key("certs/intermedia_ca.key")
    ca_cert = load_cert("certs/intermedia_ca.crt")
    gen_service(
        ca_cert=ca_cert,
        ca_private_key=ca_private_key,
        domain='ca.example.com'
    )

main()
