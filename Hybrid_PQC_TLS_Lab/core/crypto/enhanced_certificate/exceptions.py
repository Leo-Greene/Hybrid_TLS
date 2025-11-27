class HybridCertificateError(Exception):
    """混合证书验证基础异常"""
    pass

class PQSignatureError(HybridCertificateError):
    """后量子签名验证失败"""
    pass

class AlgorithmNotSupportedError(HybridCertificateError):
    """算法不支持"""
    pass

class CertificateChainError(HybridCertificateError):
    """证书链构建失败"""
    pass

class SecurityPolicyViolationError(HybridCertificateError):
    """安全策略违规"""
    pass

class MixedSecurityError(HybridCertificateError):
    """混合安全性错误"""
    pass