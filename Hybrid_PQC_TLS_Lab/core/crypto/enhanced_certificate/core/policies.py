from typing import List, Set
from enum import Enum
import sys
from pathlib import Path

# 添加enhanced_certificate目录到路径，支持导入本地模块
enhanced_certificate_dir = Path(__file__).parent.parent
sys.path.insert(0, str(enhanced_certificate_dir))

# 导入本地模块（使用绝对导入）
from models.certificates import CertificateInfo, SecurityLevel, AlgorithmType
from exceptions import SecurityPolicyViolationError, MixedSecurityError

class VerificationPolicy(Enum):
    STRICT_PQ = "strict_pq"           # 严格要求PQ签名
    HYBRID_TRANSITION = "hybrid"      # 允许混合过渡
    CLASSIC_FALLBACK = "classic"      # 经典算法回退

class HybridSecurityPolicy:
    """
    混合安全策略实施
    基于NIST迁移指南和IETF最佳实践
    """
    
    def __init__(self, 
                 policy: VerificationPolicy = VerificationPolicy.HYBRID_TRANSITION,
                 min_security_level: SecurityLevel = SecurityLevel.LEVEL_2,  # ⭐ 支持Falcon-512等LEVEL_2算法
                 require_pq_leaf: bool = True):
        
        self.policy = policy
        self.min_security_level = min_security_level
        self.require_pq_leaf = require_pq_leaf
        
        # 允许的算法组合
        self._allowed_transitions = {
            AlgorithmType.POST_QUANTUM: {AlgorithmType.POST_QUANTUM},
            AlgorithmType.CLASSIC: {AlgorithmType.CLASSIC, AlgorithmType.POST_QUANTUM}
        }
    
    def validate_certificate_chain(self, chain: List[CertificateInfo]) -> None:
        """验证整个证书链的安全性"""
        if not chain:
            raise SecurityPolicyViolationError("Empty certificate chain")
        
        leaf_cert = chain[0]
        ca_certs = chain[1:]
        
        # 1. 验证叶子证书
        self._validate_leaf_certificate(leaf_cert)
        
        # 2. 验证CA证书
        for i, ca_cert in enumerate(ca_certs):
            self._validate_ca_certificate(ca_cert, i)
        
        # 3. 验证算法过渡
        self._validate_algorithm_transitions(chain)
        
        # 4. 验证安全级别
        self._validate_security_levels(chain)
    
    def _validate_leaf_certificate(self, cert: CertificateInfo) -> None:
        """验证叶子证书"""
        if self.require_pq_leaf and not cert.is_pq_signed:
            raise SecurityPolicyViolationError(
                "Leaf certificate must use post-quantum signature"
            )
        
        if cert.security_level.value < self.min_security_level.value:
            raise SecurityPolicyViolationError(
                f"Leaf certificate security level {cert.security_level} "
                f"below minimum {self.min_security_level}"
            )
    
    def _validate_ca_certificate(self, cert: CertificateInfo, depth: int) -> None:
        """验证CA证书"""
        if not cert.is_ca:
            raise SecurityPolicyViolationError(
                f"Intermediate certificate at depth {depth} is not a CA"
            )
        
        # 路径长度约束检查
        if (cert.path_length_constraint is not None and 
            depth > cert.path_length_constraint):
            raise SecurityPolicyViolationError(
                f"Path length constraint violated at depth {depth}"
            )
    
    def _validate_algorithm_transitions(self, chain: List[CertificateInfo]) -> None:
        """验证算法过渡规则"""
        for i in range(len(chain) - 1):
            subject = chain[i]
            issuer = chain[i + 1]
            
            # 不允许PQ CA签发经典证书（安全降级）
            if (issuer.is_pq_signed and 
                not subject.is_pq_signed and
                self.policy != VerificationPolicy.CLASSIC_FALLBACK):
                
                raise MixedSecurityError(
                    f"PQ-signed CA cannot issue classic-signed certificate. "
                    f"Subject: {subject.subject}, Issuer: {issuer.subject}"
                )
            
            # 检查安全级别降级
            if subject.security_level.value > issuer.security_level.value:
                raise SecurityPolicyViolationError(
                    f"Security level downgrade detected: "
                    f"subject={subject.security_level}, issuer={issuer.security_level}"
                )
    
    def _validate_security_levels(self, chain: List[CertificateInfo]) -> None:
        """验证整个链的安全级别"""
        min_chain_level = min(cert.security_level.value for cert in chain)
        
        if min_chain_level < self.min_security_level.value:
            raise SecurityPolicyViolationError(
                f"Chain minimum security level {min_chain_level} "
                f"below required {self.min_security_level.value}"
            )