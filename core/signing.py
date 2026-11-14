"""Sign PDFs with a user's own RSA key and certificate.

The signature is a standard PDF signature (PAdES baseline): pyHanko appends an
*incremental update* holding a signature field, a ``/ByteRange`` that covers
every byte except the signature itself, and a CMS/PKCS#7 ``SignedData``
structure with the SHA-256 digest, the RSA signature (PKCS#1 v1.5) and the
signer's certificate. Readers such as Adobe Acrobat check it without Cipher
Safe. Because the update is appended, the original bytes stay unchanged.

The key and certificate come from :mod:`core.crypto` (generated with
``cryptography``); pyHanko only builds the PDF and CMS structures around them.
"""

from __future__ import annotations

import time
from io import BytesIO

from asn1crypto import keys as asn1_keys
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import PdfReadError
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers
from pyhanko_certvalidator.registry import SimpleCertificateStore

#: Name of the signature field Cipher Safe adds.
SIGNATURE_FIELD = "CipherSafe"

#: Reason shown in the reader's signature panel.
SIGNATURE_REASON = "Signed in Cipher Safe"


class PdfSigningError(ValueError):
    """Base class: the bytes can't be signed. The message is safe to show."""


class NotAPdf(PdfSigningError):
    pass


class EncryptedPdf(PdfSigningError):
    pass


class AlreadySigned(PdfSigningError):
    pass


def is_pdf(data: bytes) -> bool:
    """A PDF starts with ``%PDF-`` (the content type alone can be wrong)."""

    return data[:5] == b"%PDF-"


def _signer(private_key: rsa.RSAPrivateKey, certificate: x509.Certificate) -> signers.SimpleSigner:
    """pyHanko signer from our key and certificate (converted to asn1crypto)."""

    key_der = private_key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    cert = asn1_x509.Certificate.load(certificate.public_bytes(serialization.Encoding.DER))
    return signers.SimpleSigner(
        signing_cert=cert,
        signing_key=asn1_keys.PrivateKeyInfo.load(key_der),
        cert_registry=SimpleCertificateStore.from_certs([cert]),
    )


def _open(data: bytes) -> IncrementalPdfFileWriter:
    if not is_pdf(data):
        raise NotAPdf("This file is not a PDF.")
    try:
        writer = IncrementalPdfFileWriter(BytesIO(data))
    except (PdfReadError, ValueError, KeyError) as exc:
        raise NotAPdf("This PDF could not be read.") from exc
    if writer.prev.encrypted:
        raise EncryptedPdf("This PDF is password-protected and can't be signed.")
    return writer


def has_cipher_safe_signature(data: bytes) -> bool:
    """Whether the PDF already carries a Cipher Safe signature."""

    try:
        reader = PdfFileReader(BytesIO(data))
        return any(sig.field_name == SIGNATURE_FIELD for sig in reader.embedded_signatures)
    except (PdfReadError, ValueError, KeyError):
        return False


def sign_pdf(
    data: bytes, private_key: rsa.RSAPrivateKey, certificate: x509.Certificate, signer_name: str
) -> tuple[bytes, float]:
    """Sign ``data`` and return ``(signed_bytes, sign_ms)``.

    Raises :class:`NotAPdf`, :class:`EncryptedPdf` or :class:`AlreadySigned`.
    The original bytes are a prefix of the result.
    """

    writer = _open(data)
    if has_cipher_safe_signature(data):
        raise AlreadySigned("This PDF is already signed in Cipher Safe.")
    metadata = signers.PdfSignatureMetadata(
        field_name=SIGNATURE_FIELD,
        md_algorithm="sha256",
        subfilter=fields.SigSeedSubFilter.PADES,
        reason=SIGNATURE_REASON,
        name=signer_name,
    )
    started = time.perf_counter()
    output = signers.sign_pdf(writer, metadata, signer=_signer(private_key, certificate))
    sign_ms = (time.perf_counter() - started) * 1000
    return output.getvalue(), round(sign_ms, 3)
