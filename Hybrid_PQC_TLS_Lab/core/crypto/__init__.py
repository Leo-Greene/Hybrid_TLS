"""密码学核心模块"""

from .key_exchange import (
    KeyExchange,
    X25519KeyExchange,
    KyberKEM,
    HybridKeyExchange,
    create_key_exchange,
)

from .signature import (
    Signature,
    ECDSASignature,
    DilithiumSignature,
    HybridSignature,
    create_signature,
)

from .record_encryption import (
    TLSRecordEncryption,
    encrypt_application_data,
    decrypt_application_data,
)

__all__ = [
    'KeyExchange',
    'X25519KeyExchange',
    'KyberKEM',
    'HybridKeyExchange',
    'create_key_exchange',
    'Signature',
    'ECDSASignature',
    'DilithiumSignature',
    'HybridSignature',
    'create_signature',
    'TLSRecordEncryption',
    'encrypt_application_data',
    'decrypt_application_data',
]

