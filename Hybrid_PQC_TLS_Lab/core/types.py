"""TLS 1.3 类型定义"""
from enum import IntEnum, Enum
from dataclasses import dataclass
from typing import List, Optional, Union


class TLSMode(str, Enum):
    """TLS运行模式"""
    CLASSIC = "classic"      # 经典TLS（X25519 + ECDSA）
    PQC = "pqc"             # 纯后量子（Kyber + Dilithium）
    HYBRID = "hybrid"        # 混合模式（两者结合）


class NamedGroup(IntEnum):
    """命名组（密钥交换算法）"""
    # 经典椭圆曲线
    secp256r1 = 0x0017
    secp384r1 = 0x0018
    secp521r1 = 0x0019
    x25519 = 0x001D
    
    # NIST标准化的PQC KEM
    ML_KEM_512 = 0x0200    # Kyber512 (NIST ML-KEM-512)
    ML_KEM_768 = 0x0201    # Kyber768 (NIST ML-KEM-768)
    ML_KEM_1024 = 0x0202   # Kyber1024 (NIST ML-KEM-1024)
    
    # 备选PQC KEM
    kyber512 = 0x020F      # Kyber512 (实验)
    kyber768 = 0x0210      # Kyber768 (实验)
    kyber1024 = 0x0211     # Kyber1024 (实验)
    
    # FrodoKEM (基于LWE，保守的安全选择)
    frodokem640 = 0x0212        # FrodoKEM-640-AES
    frodokem976 = 0x0213        # FrodoKEM-976-AES
    frodokem1344 = 0x0214       # FrodoKEM-1344-AES
    
    # NTRU KEM (经典格基密码)
    ntru_hps2048509 = 0x0215    # NTRU-HPS-2048-509
    ntru_hps2048677 = 0x0216    # NTRU-HPS-2048-677
    ntru_hrss701 = 0x0217       # NTRU-HRSS-701
    
    # 混合密钥交换（经典 + Kyber）
    p256_kyber512 = 0x2F29
    p256_kyber768 = 0x2F2A
    p384_kyber768 = 0x2F2B
    p521_kyber1024 = 0x2F2C
    
    # 混合密钥交换（经典 + FrodoKEM）
    p256_frodokem640 = 0x2F2D
    p256_frodokem976 = 0x2F2E
    p521_frodokem1344 = 0x2F2F
    
    # 混合密钥交换（经典 + NTRU）
    p256_ntru_hps2048509 = 0x2F30
    p384_ntru_hps2048677 = 0x2F31


class CipherSuite(IntEnum):
    """TLS 1.3加密套件"""
    TLS_AES_128_GCM_SHA256 = 0x1301
    TLS_AES_256_GCM_SHA384 = 0x1302
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303
    TLS_AES_128_CCM_SHA256 = 0x1304
    TLS_AES_128_CCM_8_SHA256 = 0x1305


class SignatureScheme(IntEnum):
    """签名算法"""
    # 经典签名
    ecdsa_secp256r1_sha256 = 0x0403
    ecdsa_secp384r1_sha384 = 0x0503
    ecdsa_secp521r1_sha512 = 0x0603
    rsa_pss_sha256 = 0x0804
    rsa_pss_sha384 = 0x0805
    rsa_pss_sha512 = 0x0806
    rsa_pss_rsae_sha256 = 0x0804  # 与rsa_pss_sha256相同
    rsa_pss_rsae_sha384 = 0x0805  # 与rsa_pss_sha384相同
    rsa_pss_rsae_sha512 = 0x0806  # 与rsa_pss_sha512相同
    
    # NIST标准化的PQC签名
    ML_DSA_44 = 0xFE00     # Dilithium2 (NIST ML-DSA-44)
    ML_DSA_65 = 0xFE01     # Dilithium3 (NIST ML-DSA-65)
    ML_DSA_87 = 0xFE02     # Dilithium5 (NIST ML-DSA-87)
    
    # 实验性PQC签名
    dilithium2 = 0xFE03
    dilithium3 = 0xFE06
    dilithium5 = 0xFE07
    falcon512 = 0xFE0B
    falcon1024 = 0xFE0E
    
    # 混合签名
    p256_dilithium2 = 0xFE04
    p256_dilithium3 = 0xFEF2
    p384_dilithium5 = 0xFE08
    p256_falcon512 = 0xFE0C
    p521_falcon1024 = 0xFE0F


class HandshakeType(IntEnum):
    """握手消息类型"""
    client_hello = 1
    server_hello = 2
    new_session_ticket = 4
    end_of_early_data = 5
    encrypted_extensions = 8
    certificate = 11
    certificate_request = 13
    certificate_verify = 15
    finished = 20
    key_update = 24
    message_hash = 254


class AlertLevel(IntEnum):
    """警报级别"""
    warning = 1
    fatal = 2


class AlertDescription(IntEnum):
    """警报描述"""
    close_notify = 0
    unexpected_message = 10
    bad_record_mac = 20
    decryption_failed = 21
    record_overflow = 22
    handshake_failure = 40
    bad_certificate = 42
    unsupported_certificate = 43
    certificate_revoked = 44
    certificate_expired = 45
    certificate_unknown = 46
    illegal_parameter = 47
    unknown_ca = 48
    access_denied = 49
    decode_error = 50
    decrypt_error = 51
    protocol_version = 70
    insufficient_security = 71
    internal_error = 80
    inappropriate_fallback = 86
    user_canceled = 90
    missing_extension = 109
    unsupported_extension = 110
    unrecognized_name = 112
    bad_certificate_status_response = 113
    unknown_psk_identity = 115
    certificate_required = 116
    no_application_protocol = 120


@dataclass
class KeyShareEntry:
    """密钥共享条目"""
    group: NamedGroup
    key_exchange: bytes
    
    def __len__(self):
        return 4 + len(self.key_exchange)  # 2字节group + 2字节长度 + 数据


@dataclass
class ClientHello:
    """ClientHello消息"""
    random: bytes  # 32字节
    cipher_suites: List[CipherSuite]
    key_shares: List[KeyShareEntry]
    supported_groups: List[NamedGroup]
    signature_algorithms: List[SignatureScheme]
    server_name: Optional[str] = None
    alpn_protocols: Optional[List[str]] = None


@dataclass
class ServerHello:
    """ServerHello消息"""
    random: bytes  # 32字节
    cipher_suite: CipherSuite
    key_share: KeyShareEntry


@dataclass
class Certificate:
    """证书消息"""
    certificate_list: List[bytes]  # DER编码的证书链


@dataclass
class CertificateVerify:
    """证书验证消息"""
    algorithm: SignatureScheme
    signature: bytes


@dataclass
class Finished:
    """Finished消息"""
    verify_data: bytes


def get_mode_config(mode: TLSMode) -> dict:
    """获取模式配置"""
    # 模式只限定supportedgroup，签名算法必须是后量子的，除了纯经典模式
    configs = {
        TLSMode.CLASSIC: {
            "supported_groups": [NamedGroup.x25519, NamedGroup.secp256r1],
            "signature_algorithms": [
                SignatureScheme.ecdsa_secp256r1_sha256,
                SignatureScheme.rsa_pss_sha256
            ],
            "cipher_suites": [CipherSuite.TLS_AES_256_GCM_SHA384],
        },
        TLSMode.PQC: {
            "supported_groups": [
                # Kyber (NIST标准)
                NamedGroup.kyber768, 
                NamedGroup.ML_KEM_768,
                NamedGroup.kyber512,
                NamedGroup.kyber1024,
                # NTRU (经典格基)
                NamedGroup.ntru_hps2048509,
                NamedGroup.ntru_hps2048677,
            ],
            "signature_algorithms": [
                SignatureScheme.ML_DSA_44,
                SignatureScheme.ML_DSA_65,
                SignatureScheme.ML_DSA_87,
                SignatureScheme.falcon512,
                SignatureScheme.falcon1024,
            ],
            "cipher_suites": [CipherSuite.TLS_AES_256_GCM_SHA384],
        },
        TLSMode.HYBRID: {
            "supported_groups": [
                # Kyber混合 (推荐)
                NamedGroup.p256_kyber768,
                NamedGroup.p384_kyber768,
                NamedGroup.p256_kyber512,
                # NTRU混合 (小尺寸)
                NamedGroup.p256_ntru_hps2048509,
                NamedGroup.p384_ntru_hps2048677,
                # 纯PQC回退
                NamedGroup.kyber768,
                # 经典回退
                NamedGroup.x25519,
                NamedGroup.secp256r1
            ],
            "signature_algorithms": [
                SignatureScheme.ML_DSA_44,
                SignatureScheme.ML_DSA_65,
                SignatureScheme.ML_DSA_87,
                SignatureScheme.falcon512,
                SignatureScheme.falcon1024,
            ],
            "cipher_suites": [CipherSuite.TLS_AES_256_GCM_SHA384],
        }
    }

    return configs[mode]


def get_group_name(group: NamedGroup) -> str:
    """获取组的友好名称"""
    names = {
        NamedGroup.x25519: "X25519",
        NamedGroup.secp256r1: "P-256",
        NamedGroup.secp384r1: "P-384",
        NamedGroup.secp521r1: "P-521",
        NamedGroup.ML_KEM_512: "ML-KEM-512",
        NamedGroup.ML_KEM_768: "ML-KEM-768",
        NamedGroup.ML_KEM_1024: "ML-KEM-1024",
        NamedGroup.kyber512: "Kyber512",
        NamedGroup.kyber768: "Kyber768",
        NamedGroup.kyber1024: "Kyber1024",
        NamedGroup.frodokem640: "FrodoKEM-640",
        NamedGroup.frodokem976: "FrodoKEM-976",
        NamedGroup.frodokem1344: "FrodoKEM-1344",
        NamedGroup.ntru_hps2048509: "NTRU-HPS-2048-509",
        NamedGroup.ntru_hps2048677: "NTRU-HPS-2048-677",
        NamedGroup.ntru_hrss701: "NTRU-HRSS-701",
        NamedGroup.p256_kyber512: "P-256+Kyber512",
        NamedGroup.p256_kyber768: "P-256+Kyber768",
        NamedGroup.p384_kyber768: "P-384+Kyber768",
        NamedGroup.p521_kyber1024: "P-521+Kyber1024",
        NamedGroup.p256_frodokem640: "P-256+FrodoKEM-640",
        NamedGroup.p256_frodokem976: "P-256+FrodoKEM-976",
        NamedGroup.p521_frodokem1344: "P-521+FrodoKEM-1344",
        NamedGroup.p256_ntru_hps2048509: "P-256+NTRU-HPS-2048-509",
        NamedGroup.p384_ntru_hps2048677: "P-384+NTRU-HPS-2048-677",
    }
    return names.get(group, f"Unknown({hex(group)})")


def get_signature_name(sig: SignatureScheme) -> str:
    """获取签名算法的友好名称"""
    names = {
        SignatureScheme.ecdsa_secp256r1_sha256: "ECDSA-P256",
        SignatureScheme.ecdsa_secp384r1_sha384: "ECDSA-P384",
        SignatureScheme.rsa_pss_sha256: "RSA-PSS-SHA256",
        SignatureScheme.rsa_pss_rsae_sha256: "RSA-PSS-RSAE-SHA256",
        SignatureScheme.rsa_pss_rsae_sha384: "RSA-PSS-RSAE-SHA384",
        SignatureScheme.rsa_pss_rsae_sha512: "RSA-PSS-RSAE-SHA512",
        SignatureScheme.ML_DSA_44: "ML-DSA-44",
        SignatureScheme.ML_DSA_65: "ML-DSA-65",
        SignatureScheme.ML_DSA_87: "ML-DSA-87",
        SignatureScheme.dilithium2: "Dilithium2",
        SignatureScheme.dilithium3: "Dilithium3",
        SignatureScheme.dilithium5: "Dilithium5",
        SignatureScheme.falcon512: "Falcon512",
        SignatureScheme.falcon1024: "Falcon1024",
        SignatureScheme.p256_dilithium2: "P256+Dilithium2",
        SignatureScheme.p256_dilithium3: "P256+Dilithium3",
        SignatureScheme.p256_falcon512: "P256+Falcon512",
    }
    return names.get(sig, f"Unknown({hex(sig)})")

def oid_to_signature_algorithm_name(oid: str) -> str:
    """根据OID获取签名算法名称"""
    # 接受格式：<ObjectIdentifier(oid=1.2.840.10045.4.3.2, name=ecdsa-with-SHA256)>
    oid_mapping = {
        "1.3.101.110": "ML-DSA-44",
        "1.3.101.111": "ML-DSA-65",
        "1.3.101.112": "ML-DSA-87",
        "1.3.101.113": "Dilithium2",
        "1.3.101.114": "Dilithium3",
        "1.3.101.115": "Dilithium5",
        "1.3.101.116": "Falcon512",
        "1.3.101.117": "Falcon1024",
    }
    return oid_mapping.get(oid, "Unknown")


def get_signature_scheme(name: str) -> SignatureScheme:
    """根据签名算法名称获取SignatureScheme枚举"""
    name_mapping = {
        "ECDSA-P256": SignatureScheme.ecdsa_secp256r1_sha256,
        "ECDSA-P384": SignatureScheme.ecdsa_secp384r1_sha384,
        "RSA-PSS-SHA256": SignatureScheme.rsa_pss_sha256,
        "RSA-PSS-RSAE-SHA256": SignatureScheme.rsa_pss_rsae_sha256,
        "RSA-PSS-RSAE-SHA384": SignatureScheme.rsa_pss_rsae_sha384,
        "RSA-PSS-RSAE-SHA512": SignatureScheme.rsa_pss_rsae_sha512,
        "ML-DSA-44": SignatureScheme.ML_DSA_44,
        "ML-DSA-65": SignatureScheme.ML_DSA_65,
        "ML-DSA-87": SignatureScheme.ML_DSA_87,
        "Dilithium2": SignatureScheme.dilithium2,
        "Dilithium3": SignatureScheme.dilithium3,
        "Dilithium5": SignatureScheme.dilithium5,
        "Falcon-512": SignatureScheme.falcon512,      # 带连字符
        "Falcon512": SignatureScheme.falcon512,
        "Falcon-1024": SignatureScheme.falcon1024,    # 带连字符
        "Falcon1024": SignatureScheme.falcon1024,
        "P256+Dilithium2": SignatureScheme.p256_dilithium2,
        "P256+Dilithium3": SignatureScheme.p256_dilithium3,
        "P256+Falcon512": SignatureScheme.p256_falcon512,
    }
    
    # 尝试直接匹配
    if name in name_mapping:
        return name_mapping[name]
    
    # 尝试不区分大小写匹配
    name_lower = name.lower()
    for key, value in name_mapping.items():
        if key.lower() == name_lower:
            return value
    
    # 如果无法匹配，默认返回hybrid算法
    return SignatureScheme.p256_dilithium3

