#!/usr/bin/env python3
"""
多证书管理器
服务器可以同时加载多个签名算法的证书，根据客户端ClientHello动态选择
"""

import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# 添加项目路径
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import sys
sys.path.insert(0, str(project_root))

# 直接导入避免__init__.py问题
from implementation.enhanced_v2 import cert_loader
from implementation.enhanced_v2 import config as config_module
from core.types import SignatureScheme, get_signature_name

ServerCertificateBundle = cert_loader.ServerCertificateBundle
get_cert_config = config_module.get_cert_config
SUPPORTED_ALGORITHMS = config_module.SUPPORTED_ALGORITHMS


class MultiCertificateManager:
    """
    多证书管理器
    
    功能：
    1. 启动时加载多个签名算法的证书
    2. 握手时根据客户端的supported_signature_algorithms选择合适的证书
    3. 支持算法优先级配置
    """
    
    def __init__(self, algorithms: Optional[List[str]] = None):
        """
        初始化多证书管理器
        
        Args:
            algorithms: 要加载的算法列表，None表示加载所有可用算法
        """
        self.cert_bundles: Dict[str, ServerCertificateBundle] = {}
        self.algorithm_priority: List[str] = []
        self.pq_algorithm_to_scheme: Dict[str, SignatureScheme] = {}
        
        # 如果未指定算法，使用默认优先级列表
        if algorithms is None:
            algorithms = ["mldsa65", "mldsa44", "falcon512", "mldsa87", "falcon1024"]
        
        self._load_certificates(algorithms)
        self._build_algorithm_mapping()
    
    def _load_certificates(self, algorithms: List[str]):
        """加载多个算法的证书"""
        print("\n" + "=" * 80)
        print("多证书管理器 - 加载证书")
        print("=" * 80)
        
        loaded_count = 0
        for algo in algorithms:
            try:
                # 检查证书是否存在
                config = get_cert_config(algo)
                if not config.validate_certs_exist():
                    print(f"⚠️  跳过 {algo}: 证书不存在")
                    continue
                
                # 加载证书
                print(f"\n[{loaded_count + 1}] 加载 {algo} 证书...")
                cert_bundle = ServerCertificateBundle(algorithm=algo)
                self.cert_bundles[algo] = cert_bundle
                self.algorithm_priority.append(algo)
                loaded_count += 1
                
                # 安全地访问属性，避免属性不存在时出错
                algo_name = getattr(cert_bundle, 'server_pq_algorithm', algo)
                print(f"  ✓ {algo}: {algo_name}")
                # print(f"    公钥: {len(cert_bundle.server_pq_public_key)} 字节")
                
            except Exception as e:
                import traceback
                error_detail = traceback.format_exc()
                print(f"  ✗ 加载 {algo} 失败: {e}")
                print(f"  [详细错误] {error_detail}")
                # 继续处理下一个算法，不中断整个加载过程
        
        print("\n" + "=" * 80)
        print(f"[OK] 加载完成: {loaded_count}/{len(algorithms)} 个证书")
        print("=" * 80)
        
        if loaded_count == 0:
            raise RuntimeError("没有可用的证书，请先生成证书")
        
        print(f"\n算法优先级: {' > '.join(self.algorithm_priority)}")
    
    def _build_algorithm_mapping(self):
        """构建PQ算法到SignatureScheme的映射"""
        mapping = {
            "ML-DSA-44": SignatureScheme.ML_DSA_44,
            "ML-DSA-65": SignatureScheme.ML_DSA_65,
            "ML-DSA-87": SignatureScheme.ML_DSA_87,
            "Dilithium2": SignatureScheme.dilithium2,
            "Dilithium3": SignatureScheme.dilithium3,
            "Dilithium5": SignatureScheme.dilithium5,
            "Falcon-512": SignatureScheme.falcon512,
            "Falcon-1024": SignatureScheme.falcon1024,
        }
        
        # 为每个已加载的证书建立映射
        for algo_key, bundle in self.cert_bundles.items():
            pq_algo = bundle.server_pq_algorithm
            if pq_algo in mapping:
                self.pq_algorithm_to_scheme[pq_algo] = mapping[pq_algo]
    
    def select_certificate(
        self, 
        client_supported_algorithms: List[SignatureScheme]
    ) -> Tuple[Optional[ServerCertificateBundle], Optional[SignatureScheme]]:
        """
        根据客户端支持的签名算法选择证书
        
        Args:
            client_supported_algorithms: 客户端支持的签名算法列表（按优先级排序）
        
        Returns:
            (证书包, 选择的签名算法) 或 (None, None)
        """
        print("\n" + "=" * 80)
        print("算法协商 - 选择证书")
        print("=" * 80)
        
        print(f"客户端支持的算法 ({len(client_supported_algorithms)}个):")
        for i, scheme in enumerate(client_supported_algorithms[:10], 1):
            print(f"  {i}. {get_signature_name(scheme)}")
        if len(client_supported_algorithms) > 10:
            print(f"  ... 还有 {len(client_supported_algorithms) - 10} 个")
        
        print(f"\n服务器可用的证书 ({len(self.cert_bundles)}个):")
        for algo_key, bundle in self.cert_bundles.items():
            pq_algo = bundle.server_pq_algorithm
            scheme = self.pq_algorithm_to_scheme.get(pq_algo)
            print(f"  • {algo_key}: {pq_algo} → {get_signature_name(scheme) if scheme else 'Unknown'}")
        
        # 策略1：优先使用服务器的优先级顺序
        print("\n协商策略: 服务器优先级")
        for algo_key in self.algorithm_priority:
            bundle = self.cert_bundles[algo_key]
            pq_algo = bundle.server_pq_algorithm
            scheme = self.pq_algorithm_to_scheme.get(pq_algo)
            
            if scheme and scheme in client_supported_algorithms:
                print(f"\n[OK] 选择: {algo_key}")
                print(f"   算法: {pq_algo}")
                print(f"   SignatureScheme: {get_signature_name(scheme)}")
                print(f"   客户端排名: #{client_supported_algorithms.index(scheme) + 1}")
                print("=" * 80)
                return bundle, scheme
        
        # 策略2：如果没有匹配，尝试使用客户端的优先级
        print("\n尝试策略2: 客户端优先级")
        for scheme in client_supported_algorithms:
            for algo_key, bundle in self.cert_bundles.items():
                pq_algo = bundle.server_pq_algorithm
                if self.pq_algorithm_to_scheme.get(pq_algo) == scheme:
                    print(f"\n[OK] 选择: {algo_key}")
                    print(f"   算法: {pq_algo}")
                    print(f"   SignatureScheme: {get_signature_name(scheme)}")
                    print("=" * 80)
                    return bundle, scheme
        
        print("\n❌ 协商失败: 没有共同支持的签名算法")
        print("=" * 80)
        return None, None
    
    def get_default_certificate(self) -> ServerCertificateBundle:
        """获取默认证书（优先级最高的）"""
        if not self.algorithm_priority:
            raise RuntimeError("没有可用的证书")
        
        default_algo = self.algorithm_priority[0]
        return self.cert_bundles[default_algo]
    
    def get_certificate_by_algorithm(self, algorithm: str) -> Optional[ServerCertificateBundle]:
        """根据算法标识获取证书"""
        return self.cert_bundles.get(algorithm)
    
    def list_available_algorithms(self) -> List[str]:
        """列出所有可用的算法"""
        return list(self.algorithm_priority)


def test_multi_cert_manager():
    """测试多证书管理器"""
    print("\n🧪 测试多证书管理器\n")
    
    # 1. 加载证书
    manager = MultiCertificateManager(algorithms=["mldsa65", "falcon512", "mldsa44"])
    
    # 2. 模拟客户端支持的算法（优先后量子）
    client_algorithms = [
        SignatureScheme.ML_DSA_65,
        SignatureScheme.ML_DSA_44,
        SignatureScheme.falcon512,
        SignatureScheme.ecdsa_secp256r1_sha256,
    ]
    
    # 3. 选择证书
    bundle, scheme = manager.select_certificate(client_algorithms)
    
    if bundle:
        print(f"\n[OK] 协商成功")
        print(f"   选择的算法: {bundle.server_pq_algorithm}")
        print(f"   签名方案: {get_signature_name(scheme)}")
    else:
        print(f"\n❌ 协商失败")


if __name__ == "__main__":
    test_multi_cert_manager()

