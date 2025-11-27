"""
增强证书验证模块

一个支持经典和后量子混合签名算法的证书验证系统，
专门为TLS 1.3混合模式设计。

主要功能：
- 支持ML-DSA、Falcon等后量子签名算法
- 支持RSA、ECDSA等经典签名算法  
- 灵活的混合安全策略配置
- 完整的证书链验证

使用示例：
    from core.crypto.enhanced_certificate import HybridCertificateVerifier
    from core.crypto.enhanced_certificate.models import CertificateInfo
    
    verifier = HybridCertificateVerifier(trust_anchors)
    result = verifier.verify_certificate_chain(leaf_cert, intermediate_certs)
"""

from .core import (
    HybridCertificateVerifier,
    AlgorithmRegistry,
    HybridSecurityPolicy,
    VerificationPolicy,
    CertificateChainBuilder,
)

from .models import (
    CertificateInfo,
    AlgorithmType,
    SecurityLevel,
)

from .exceptions import (
    PQSignatureError,
    CertificateChainError,
    SecurityPolicyViolationError,
    MixedSecurityError,
    AlgorithmNotSupportedError,
)

__all__ = [
    # 核心验证类
    'HybridCertificateVerifier',
    'AlgorithmRegistry',
    'HybridSecurityPolicy',
    'VerificationPolicy',
    'CertificateChainBuilder',
    
    # 数据模型
    'CertificateInfo',
    'AlgorithmType',
    'SecurityLevel',
    
    # 异常类
    'PQSignatureError',
    'CertificateChainError',
    'SecurityPolicyViolationError',
    'MixedSecurityError',
    'AlgorithmNotSupportedError',
]

__version__ = "1.0.0"