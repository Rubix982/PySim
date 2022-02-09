# This code is used to create Self Signed Certificate
from OpenSSL import crypto
from cryptography.fernet import Fernet
import hashlib
import random
import string


class CertificateAux:
    @staticmethod
    def cert_gen(
        emailAddress="emailAddress",
        commonName="commonName",
        countryName="NT",
        localityName="localityName",
        stateOrProvinceName="stateOrProvinceName",
        organizationName="organizationName",
        organizationUnitName="organizationUnitName",
        serialNumber=0,
        validityStartInSeconds=0,
        validityEndInSeconds=10 * 365 * 24 * 60 * 60,
        KEY_FILE="private.key",
        CERT_FILE="selfsigned.crt",
    ):

        # Can look at generated file using OpenSSL
        # Openssl x509 -inform pem -in selfsigned.crt -noout -text
        # Create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 4096)

        # Create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = countryName
        cert.get_subject().ST = stateOrProvinceName
        cert.get_subject().L = localityName
        cert.get_subject().O = organizationName  # noqa: E741
        cert.get_subject().OU = organizationUnitName
        cert.get_subject().CN = commonName
        cert.get_subject().emailAddress = emailAddress
        cert.set_serial_number(CertificateAux().serial_id_generator())
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(validityEndInSeconds)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, "sha512")

        with open(CERT_FILE, "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))

        with open(KEY_FILE, "wt") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))

    @staticmethod
    def hash_file(filename):
        """
        This function is for the hashing concept.

        Actions:
            - Takes the hash of Existing Self-Signed Certificate to create session Key

        Returns::
            - Returns the SHA-1 hash of the file passed into it
        """

        # Make a hash object
        h = hashlib.sha1()

        # Open file for reading in binary mode
        with open(filename, "rb") as file:

            # Loop till the end of the file
            chunk = 0

            while chunk != b"":

                # Read only 1024 bytes at a time
                chunk = file.read(1024)
                h.update(chunk)

        # Return the hex representation of digest
        return h.hexdigest()

    @staticmethod
    def encrypt_with_fernet(message: str) -> str:
        '''
        Use to encrypt session key
        '''

        fernet = Fernet(Fernet.generate_key())
        return fernet.encrypt(message.encode())

    @staticmethod
    def decrypt_with_fernet(enc_message: str) -> str:
        '''
        Used to decrypt session key
        '''

        fernet = Fernet(Fernet.generate_key())
        return fernet.decrypt(enc_message).decode()

    @staticmethod
    def serial_id_generator(size: int = 10, chars: str = string.digits) -> str:
        return int(''.join(random.choice(chars) for _ in range(size)))
