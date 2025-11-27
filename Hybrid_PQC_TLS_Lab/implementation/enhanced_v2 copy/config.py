#!/usr/bin/env python3
"""
TLS服务器/客户端配置
支持多算法证书选择
"""

import os
from pathlib import Path
from typing import Optional


class CertificateConfig:
    """证书配置"""
    def __init__(self, algorithm: str, base_dir: str = None):
        self.algorithm = algorithm
        # 如果没有指定base_dir，使用项目根目录的绝对路径
        if base_dir is None:
            # 默认指向implementation/enhanced_v2目录下的pq_certificates
            config_dir = Path(__file__).parent
            base_dir = str(config_dir / "pq_certificates")
        self.base_dir = base_dir
    
    def get_cert_paths(self) -> dict:
        """获取证书文件路径"""
        # 使用Path对象确保跨平台兼容性
        algo_base = Path(self.base_dir) / self.algorithm
        
        return {
            # 根CA
            "root_cert": str(algo_base / "root" / "root_ca.crt"),
            "root_key": str(algo_base / "root" / "root_ca.key"),
            "root_sig": str(algo_base / "root" / "root_ca_pq.sig"),
            
            # 中间CA
            "intermediate_cert": str(algo_base / "intermediate" / "intermediate_ca.crt"),
            "intermediate_key": str(algo_base / "intermediate" / "intermediate_ca.key"),
            "intermediate_sig": str(algo_base / "intermediate" / "intermediate_ca_pq.sig"),
            
            # 服务器证书
            "server_cert": str(algo_base / "server" / "server.crt"),
            "server_key": str(algo_base / "server" / "server.key"),
            "server_sig": str(algo_base / "server" / "server_pq.sig"),
            
            # 客户端信任存储
            "trust_store_cert": str(algo_base / "client" / "trust_store" / "root_ca.crt"),
            "trust_store_sig": str(algo_base / "client" / "trust_store" / "root_ca_pq.sig"),
        }
    
    def validate_certs_exist(self) -> bool:
        """验证证书文件是否存在"""
        paths = self.get_cert_paths()
        missing = []
        
        for name, path in paths.items():
            if not os.path.exists(path):
                missing.append(f"{name}: {path}")
        
        if missing:
            print(f"❌ 缺少证书文件 ({self.algorithm}):")
            for m in missing:
                print(f"   {m}")
            return False
        
        return True


# 默认配置
DEFAULT_CERT_ALGORITHM = "mldsa65"  # 默认使用ML-DSA-65

# 支持的算法列表
SUPPORTED_ALGORITHMS = [
    "mldsa44",    # ML-DSA-44 (Level 2)
    "mldsa65",    # ML-DSA-65 (Level 3) - 推荐
    "mldsa87",    # ML-DSA-87 (Level 5)
    "falcon512",  # Falcon-512
    "falcon1024", # Falcon-1024
    "dilithium2", # Dilithium2 (实验)
    "dilithium3", # Dilithium3 (实验)
]


def get_cert_config(algorithm: Optional[str] = None) -> CertificateConfig:
    """
    获取证书配置
    
    Args:
        algorithm: 算法名称，None则使用默认
    
    Returns:
        CertificateConfig对象
    """
    if algorithm is None:
        algorithm = DEFAULT_CERT_ALGORITHM
    
    if algorithm not in SUPPORTED_ALGORITHMS:
        print(f"⚠️  算法 '{algorithm}' 不在支持列表中，使用默认: {DEFAULT_CERT_ALGORITHM}")
        print(f"   支持的算法: {', '.join(SUPPORTED_ALGORITHMS)}")
        algorithm = DEFAULT_CERT_ALGORITHM
    
    return CertificateConfig(algorithm=algorithm)


def get_cert_algorithm_from_env() -> str:
    """从环境变量获取证书算法"""
    return os.environ.get("PQC_CERT_ALGORITHM", DEFAULT_CERT_ALGORITHM)


def get_default_cert_paths(algorithm: Optional[str] = None) -> dict:
    """
    获取默认证书路径（兼容旧代码）
    
    Args:
        algorithm: 算法名称
    
    Returns:
        证书路径字典
    """
    config = get_cert_config(algorithm)
    paths = config.get_cert_paths()
    
    # 转换为旧格式
    return {
        'server_cert': paths['server_cert'],
        'server_cert_pq_sig': paths['server_sig'],
        'server_key': paths['server_key'],
        'cert_chain': paths['intermediate_cert'],
        'ca_cert': paths['root_cert'],
        'ca_cert_pq_sig': paths['root_sig'],
        'client_trust_store': paths['trust_store_cert'],
        'client_trust_store_pq_sig': paths['trust_store_sig'],
        'client_intermediate_cache': paths['intermediate_cert'],
        'client_intermediate_cache_pq_sig': paths['intermediate_sig'],
    }


class ServerConfig:
    """服务器配置"""
    def __init__(
        self,
        host: str = "localhost",
        port: int = 8443,
        mode = None,  # TLSMode
        algorithm: Optional[str] = None
    ):
        self.host = host
        self.port = port
        self.mode = mode
        self.algorithm = algorithm
    
    def get_cert_paths(self) -> dict:
        """获取证书路径"""
        return get_default_cert_paths(self.algorithm)


class ClientConfig:
    """客户端配置"""
    def __init__(
        self,
        host: str = "localhost",
        port: int = 8443,
        mode = None,  # TLSMode
        algorithm: Optional[str] = None
    ):
        self.host = host
        self.port = port
        self.mode = mode
        self.algorithm = algorithm
    
    def get_trust_store_paths(self) -> dict:
        """获取信任存储路径（可以加载多个算法的根证书）"""
        if self.algorithm:
            # 指定了算法，加载该算法的根证书
            config = get_cert_config(self.algorithm)
            paths = config.get_cert_paths()
            return {
                'root_cert': paths['trust_store_cert'],
                'root_sig': paths['trust_store_sig'],
            }
        else:
            # 未指定算法，加载默认的根证书
            config = get_cert_config(DEFAULT_CERT_ALGORITHM)
            paths = config.get_cert_paths()
            return {
                'root_cert': paths['trust_store_cert'],
                'root_sig': paths['trust_store_sig'],
            }


if __name__ == "__main__":
    # 测试配置
    print("证书配置测试\n")
    
    for algo in SUPPORTED_ALGORITHMS:
        print(f"\n算法: {algo}")
        config = get_cert_config(algo)
        paths = config.get_cert_paths()
        print(f"  服务器证书: {paths['server_cert']}")
        print(f"  证书存在: {config.validate_certs_exist()}")
