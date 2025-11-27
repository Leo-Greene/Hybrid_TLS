from typing import List, Optional
import sys
from pathlib import Path

# 添加enhanced_certificate目录到路径，支持导入本地模块
enhanced_certificate_dir = Path(__file__).parent.parent
sys.path.insert(0, str(enhanced_certificate_dir))

# 导入本地模块（使用绝对导入）
from .algorithms import AlgorithmRegistry
from .policies import HybridSecurityPolicy
from .chain_builder import CertificateChainBuilder
from models.certificates import CertificateInfo
from exceptions import PQSignatureError, CertificateChainError

class HybridCertificateVerifier:
    """
    混合证书验证器 - 核心类
    支持经典和后量子签名算法的证书验证
    """
    
    def __init__(self, 
                 trust_anchors: List[CertificateInfo],
                 policy: Optional[HybridSecurityPolicy] = None):
        
        self.trust_anchors = trust_anchors
        self.algorithm_registry = AlgorithmRegistry()
        self.policy = policy or HybridSecurityPolicy()
        self.chain_builder = CertificateChainBuilder(trust_anchors)
    
    def verify_certificate_chain(self,
                               leaf_cert: CertificateInfo,
                               intermediate_certs: List[CertificateInfo] = None) -> bool:
        """
        验证完整的证书链
        返回: True如果验证成功，否则抛出异常
        """
        if intermediate_certs is None:
            intermediate_certs = []
        
        try:
            # 1. 构建证书链
            chain = self.chain_builder.build_chain(leaf_cert, intermediate_certs)
            
            # 2. 应用安全策略
            self.policy.validate_certificate_chain(chain)
            
            # 3. 验证每个签名
            for i in range(len(chain) - 1):
                subject_cert = chain[i]
                issuer_cert = chain[i + 1]
                
                if not self._verify_certificate_signature(subject_cert, issuer_cert):
                    raise PQSignatureError(
                        f"Signature verification failed for: {subject_cert.subject}"
                    )
            
            # 4. 额外的混合安全检查
            self._perform_hybrid_security_checks(chain)
            
            return True
            
        except Exception as e:
            # 记录详细的验证错误
            self._log_verification_error(e, leaf_cert, intermediate_certs)
            raise
    
    def _verify_certificate_signature(self, 
                                    subject_cert: CertificateInfo,
                                    issuer_cert: CertificateInfo) -> bool:
        """验证单个证书签名"""
        try:
            # 获取签名算法信息
            algo_name = subject_cert.signature_algorithm
            
            # 使用颁发者公钥验证签名
            result = self.algorithm_registry.verify_signature(
                algorithm=algo_name,
                message=subject_cert.tbs_certificate,
                signature=subject_cert.signature,
                public_key=issuer_cert.public_key
            )
            
            return result
            
        except Exception as e:
            raise PQSignatureError(
                f"Signature verification error for {subject_cert.subject}: {str(e)}"
            )
    
    def _perform_hybrid_security_checks(self, chain: List[CertificateInfo]) -> None:
        """执行混合安全特定检查"""
        pq_count = sum(1 for cert in chain if cert.is_pq_signed)
        total_count = len(chain)
        
        # 记录混合安全指标
        pq_percentage = (pq_count / total_count) * 100
        
        print(f"混合安全分析: {pq_count}/{total_count} 证书使用后量子签名 ({pq_percentage:.1f}%)")
        
        # 可以根据策略发出警告
        if pq_percentage < 50 and self.policy.require_pq_leaf:
            print("警告: 证书链中后量子签名比例较低")
    
    def _log_verification_error(self, error: Exception, 
                              leaf_cert: CertificateInfo,
                              intermediate_certs: List[CertificateInfo]) -> None:
        """记录验证错误详情"""
        print(f"证书验证失败: {str(error)}")
        print(f"叶子证书: {leaf_cert.subject}")
        print(f"算法: {leaf_cert.signature_algorithm}")
        print(f"中间证书数量: {len(intermediate_certs)}")