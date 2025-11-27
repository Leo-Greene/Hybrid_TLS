from dataclasses import dataclass
from typing import Optional, List, Union
from enum import Enum

class AlgorithmType(Enum):
    CLASSIC = "classic"
    POST_QUANTUM = "pq"
    HYBRID = "hybrid"

class SecurityLevel(Enum):
    LEVEL_1 = 1  # 低安全性
    LEVEL_2 = 2  # ML-DSA-44, Falcon-512
    LEVEL_3 = 3  # ML-DSA-65  
    LEVEL_5 = 5  # ML-DSA-87, Falcon-1024

@dataclass
class CertificateInfo:
    """证书信息抽象"""
    subject: str
    issuer: str
    public_key: bytes
    signature_algorithm: str
    signature: bytes
    tbs_certificate: bytes  # To-Be-Signed 数据
    algorithm_type: AlgorithmType
    security_level: SecurityLevel
    is_ca: bool = False
    path_length_constraint: Optional[int] = None

    @property
    def is_pq_signed(self) -> bool:
        return self.algorithm_type in [AlgorithmType.POST_QUANTUM, AlgorithmType.HYBRID]