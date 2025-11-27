from typing import List, Optional
import sys
from pathlib import Path

# 添加enhanced_certificate目录到路径，支持导入本地模块
enhanced_certificate_dir = Path(__file__).parent.parent
sys.path.insert(0, str(enhanced_certificate_dir))

# 导入本地模块（使用绝对导入）
from models.certificates import CertificateInfo
from exceptions import CertificateChainError

class CertificateChainBuilder:
    """混合证书链构建器"""
    
    def __init__(self, trust_anchors: List[CertificateInfo]):
        self.trust_anchors = trust_anchors
        self._cert_cache = {}  # 主题到证书的映射
    
    def build_chain(self, leaf_cert: CertificateInfo, 
                   intermediate_certs: List[CertificateInfo]) -> List[CertificateInfo]:
        """
        构建从叶子证书到信任锚的完整证书链
        """
        # 构建证书缓存
        self._build_cert_cache(intermediate_certs)
        
        chain = [leaf_cert]
        current_cert = leaf_cert
        
        while not self._is_trust_anchor(current_cert):
            issuer = self._find_issuer(current_cert)
            if not issuer:
                raise CertificateChainError(
                    f"Cannot find issuer for certificate: {current_cert.subject}"
                )
            
            # 检查循环引用
            if issuer in chain:
                raise CertificateChainError(
                    f"Certificate chain cycle detected: {issuer.subject}"
                )
            
            chain.append(issuer)
            current_cert = issuer
        
        return chain
    
    def _build_cert_cache(self, certificates: List[CertificateInfo]) -> None:
        """构建证书缓存以加速查找"""
        self._cert_cache.clear()
        for cert in certificates:
            self._cert_cache[cert.subject] = cert
    
    def _find_issuer(self, certificate: CertificateInfo) -> Optional[CertificateInfo]:
        """查找证书的颁发者"""
        issuer_subject = certificate.issuer
        
        # 在中间证书中查找
        if issuer_subject in self._cert_cache:
            return self._cert_cache[issuer_subject]
        
        # 在信任锚中查找
        for trust_anchor in self.trust_anchors:
            if trust_anchor.subject == issuer_subject:
                return trust_anchor
        
        return None
    
    def _is_trust_anchor(self, certificate: CertificateInfo) -> bool:
        """检查是否为信任锚"""
        return any(ta.subject == certificate.subject for ta in self.trust_anchors)