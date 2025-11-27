#!/usr/bin/env python3
"""
信任存储管理器
客户端本地存储多个根CA，根据服务器证书链动态匹配验证
"""

import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# 添加项目路径
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from enhanced_certificates.x509_wrapper import PQWrappedCertificate
from implementation.enhanced_v2_by_val import config as config_module
from core.crypto.enhanced_certificate.models.certificates import CertificateInfo, AlgorithmType, SecurityLevel
from core.crypto.enhanced_certificate.core.verifier import HybridCertificateVerifier

get_cert_config = config_module.get_cert_config
SUPPORTED_ALGORITHMS = config_module.SUPPORTED_ALGORITHMS


class TrustStoreManager:
    """
    信任存储管理器
    
    功能：
    1. 本地存储多个签名算法的根CA（信任锚）
    2. 根据服务器发来的证书链，动态匹配对应的根CA
    3. 使用enhanced_certificate验证逻辑，验证整个证书链的签名
    """
    
    def __init__(self, algorithms: Optional[List[str]] = None):
        """
        初始化信任存储
        
        Args:
            algorithms: 要加载的根CA算法列表，None表示加载所有可用
        """
        self.trust_anchors: Dict[str, CertificateInfo] = {}  # 算法 -> 根CA证书信息
        self.root_certs: Dict[str, x509.Certificate] = {}    # 算法 -> 根CA X.509证书
        self.root_public_keys: Dict[str, bytes] = {}          # 算法 -> 根CA公钥
        
        # 如果未指定算法，加载默认列表（包括所有支持的算法）
        if algorithms is None:
            algorithms = ["mldsa65", "mldsa44", "mldsa87", "falcon512", "falcon1024"]
        
        self._load_trust_anchors(algorithms)
    
    def _load_trust_anchors(self, algorithms: List[str]):
        """加载多个算法的根CA作为信任锚"""
        print("\n" + "=" * 80)
        print("信任存储管理器 - 加载根CA")
        print("=" * 80)
        
        loaded_count = 0
        for algo in algorithms:
            try:
                # 获取根CA路径
                cert_config = get_cert_config(algo)
                paths = cert_config.get_cert_paths()
                
                root_cert_path = paths['trust_store_cert']
                root_sig_path = paths['trust_store_sig']
                
                # 检查文件是否存在
                if not os.path.exists(root_cert_path):
                    print(f"⚠️  跳过 {algo}: 根CA不存在")
                    continue
                
                # 加载根CA证书
                print(f"\n[{loaded_count + 1}] 加载 {algo} 根CA...")
                wrapped_root = PQWrappedCertificate.load_pem(root_cert_path, root_sig_path)
                
                root_cert = wrapped_root.x509_cert
                root_pq_public_key = wrapped_root.get_pq_public_key()
                root_pq_algorithm = wrapped_root.pq_algorithm
                
                # 创建CertificateInfo（用于enhanced_certificate验证）
                cert_info = CertificateInfo(
                    subject=str(root_cert.subject),
                    issuer=str(root_cert.issuer),
                    public_key=root_pq_public_key,
                    signature_algorithm=root_pq_algorithm,
                    signature=wrapped_root.pq_signature,
                    tbs_certificate=root_cert.tbs_certificate_bytes,
                    algorithm_type=AlgorithmType.POST_QUANTUM,
                    security_level=self._get_security_level(root_pq_algorithm),
                    is_ca=True
                )
                
                # 存储
                self.trust_anchors[algo] = cert_info
                self.root_certs[algo] = root_cert
                self.root_public_keys[algo] = root_pq_public_key
                
                print(f"  ✓ {algo}: {root_pq_algorithm}")
                print(f"    主题: {root_cert.subject}")
                print(f"    公钥: {len(root_pq_public_key)} 字节")
                
                loaded_count += 1
                
            except Exception as e:
                print(f"  ✗ 加载 {algo} 失败: {e}")
        
        print("\n" + "=" * 80)
        print(f"[OK] 加载完成: {loaded_count}/{len(algorithms)} 个根CA")
        print("=" * 80)
        
        if loaded_count == 0:
            raise RuntimeError("没有可用的根CA，请先生成证书")
        
        print(f"\n可用的信任锚: {', '.join(self.trust_anchors.keys())}")
    
    def _get_security_level(self, algorithm: str) -> SecurityLevel:
        """根据算法名称获取安全级别"""
        level_map = {
            "ML-DSA-44": SecurityLevel.LEVEL_2,
            "ML-DSA-65": SecurityLevel.LEVEL_3,
            "ML-DSA-87": SecurityLevel.LEVEL_5,
            "Falcon-512": SecurityLevel.LEVEL_2,
            "Falcon-1024": SecurityLevel.LEVEL_5,
            "Dilithium2": SecurityLevel.LEVEL_2,
            "Dilithium3": SecurityLevel.LEVEL_3,
            "Dilithium5": SecurityLevel.LEVEL_5,
        }
        return level_map.get(algorithm, SecurityLevel.LEVEL_3)
    
    def find_trust_anchor_for_chain(
        self, 
        intermediate_cert: x509.Certificate
    ) -> Optional[Tuple[str, CertificateInfo, x509.Certificate, bytes]]:
        """
        根据中间CA证书，找到对应的根CA
        
        Args:
            intermediate_cert: 中间CA证书
        
        Returns:
            (算法key, 根CA CertificateInfo, 根CA X.509证书, 根CA公钥) 或 None
        """
        print(f"\n[匹配] 查找根CA：中间CA的颁发者 = {intermediate_cert.issuer}")
        
        # 遍历所有根CA，找到issuer匹配的
        for algo_key, root_cert in self.root_certs.items():
            if root_cert.subject == intermediate_cert.issuer:
                print(f"[匹配] ✓ 找到匹配的根CA: {algo_key}")
                print(f"[匹配]   根CA主题: {root_cert.subject}")
                print(f"[匹配]   根CA算法: {self.trust_anchors[algo_key].signature_algorithm}")
                
                return (
                    algo_key,
                    self.trust_anchors[algo_key],
                    root_cert,
                    self.root_public_keys[algo_key]
                )
        
        print(f"[匹配] ✗ 未找到匹配的根CA")
        print(f"[匹配]   可用的根CA:")
        for algo_key, root_cert in self.root_certs.items():
            print(f"     • {algo_key}: {root_cert.subject}")
        
        return None
    
    def verify_chain_with_enhanced_verifier(
        self,
        server_cert: x509.Certificate,
        server_pq_sig: bytes,
        server_pq_algo: str,
        intermediate_cert: x509.Certificate,
        intermediate_pq_sig: bytes,
        intermediate_pq_algo: str
    ) -> Tuple[bool, Optional[str]]:
        """
        使用enhanced_certificate验证器验证证书链
        
        验证逻辑：
        1. 根据中间CA的issuer找到对应的根CA
        2. 构建CertificateInfo列表
        3. 使用HybridCertificateVerifier验证整个链的签名
        
        Returns:
            (验证是否成功, 错误信息)
        """
        print("\n" + "=" * 80)
        print("证书链验证 - 使用Enhanced Certificate验证器")
        print("=" * 80)
        
        # 1. 找到对应的根CA
        match_result = self.find_trust_anchor_for_chain(intermediate_cert)
        
        if not match_result:
            return False, "未找到匹配的根CA"
        
        algo_key, root_info, root_cert, root_public_key = match_result
        
        # 2. 构建CertificateInfo列表
        print(f"\n[构建] 构建证书链信息...")
        
        # 服务器证书（叶子）
        server_pq_public_key = self._extract_pq_public_key(server_cert)
        
        # ⭐ signature_algorithm应该是签名者（中间CA）的算法
        # 服务器证书是由中间CA签名的，所以应该使用中间CA的算法进行验证
        server_info = CertificateInfo(
            subject=str(server_cert.subject),
            issuer=str(server_cert.issuer),
            public_key=server_pq_public_key,
            signature_algorithm=intermediate_pq_algo,  # ⭐ 使用中间CA的算法（签名者）
            signature=server_pq_sig,
            tbs_certificate=server_cert.tbs_certificate_bytes,
            algorithm_type=AlgorithmType.POST_QUANTUM,
            security_level=self._get_security_level(intermediate_pq_algo),
            is_ca=False
        )
        print(f"  ✓ 服务器证书: {server_cert.subject}")
        print(f"    算法: {server_pq_algo}")
        
        # 中间CA证书
        inter_pq_public_key = self._extract_pq_public_key(intermediate_cert)
        
        # ⭐ 关键修复：signature_algorithm应该是签名者（根CA）的算法，而不是证书主体的算法
        # 中间CA证书是由根CA签名的，所以应该使用根CA的算法进行验证
        intermediate_info = CertificateInfo(
            subject=str(intermediate_cert.subject),
            issuer=str(intermediate_cert.issuer),
            public_key=inter_pq_public_key,
            signature_algorithm=root_info.signature_algorithm,  # ⭐ 使用根CA的算法
            signature=intermediate_pq_sig,
            tbs_certificate=intermediate_cert.tbs_certificate_bytes,
            algorithm_type=AlgorithmType.POST_QUANTUM,
            security_level=self._get_security_level(root_info.signature_algorithm),  # ⭐ 使用根CA的安全级别
            is_ca=True
        )
        print(f"  ✓ 中间CA: {intermediate_cert.subject}")
        print(f"    算法: {intermediate_pq_algo}")
        
        # 根CA（信任锚）
        print(f"  ✓ 根CA: {root_cert.subject}")
        print(f"    算法: {root_info.signature_algorithm}")
        
        # 3. 创建验证器并验证
        print(f"\n[验证] 使用Enhanced Certificate验证器...")
        
        try:
            verifier = HybridCertificateVerifier(
                trust_anchors=[root_info]
            )
            
            # 验证证书链（叶子 → 中间 → 根）
            result = verifier.verify_certificate_chain(
                leaf_cert=server_info,
                intermediate_certs=[intermediate_info]
            )
            
            print(f"[验证] [OK] 证书链验证成功！")
            print(f"[验证]   验证路径: {server_cert.subject} ← {intermediate_cert.subject} ← {root_cert.subject}")
            print(f"[验证]   签名验证: 全部通过（使用后量子算法）")
            
            return True, None
            
        except Exception as e:
            error_msg = str(e)
            print(f"[验证] ❌ 证书链验证失败: {error_msg}")
            import traceback
            traceback.print_exc()
            return False, error_msg
    
    def _extract_pq_public_key(self, cert: x509.Certificate) -> bytes:
        """从证书扩展中提取后量子公钥"""
        from enhanced_certificates.x509_wrapper import PQ_PUBLIC_KEY_OID
        import json
        
        try:
            ext = cert.extensions.get_extension_for_oid(PQ_PUBLIC_KEY_OID)
            metadata = json.loads(ext.value.value.decode('utf-8'))
            return bytes.fromhex(metadata['public_key'])
        except Exception as e:
            raise ValueError(f"无法提取后量子公钥: {e}")
    
    def list_trust_anchors(self) -> List[str]:
        """列出所有信任锚"""
        return list(self.trust_anchors.keys())


def test_trust_store_manager():
    """测试信任存储管理器"""
    print("\n🧪 测试信任存储管理器\n")
    
    # 1. 加载多个根CA
    manager = TrustStoreManager(algorithms=["mldsa65", "falcon512", "mldsa44"])
    
    # 2. 列出信任锚
    print(f"\n信任锚列表: {manager.list_trust_anchors()}")
    
    # 3. 测试匹配
    # 模拟一个中间CA的issuer
    for algo in manager.list_trust_anchors():
        root_cert = manager.root_certs[algo]
        print(f"\n{algo} 根CA:")
        print(f"  主题: {root_cert.subject}")
        print(f"  算法: {manager.trust_anchors[algo].signature_algorithm}")


if __name__ == "__main__":
    test_trust_store_manager()

