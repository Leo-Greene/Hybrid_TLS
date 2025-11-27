#!/usr/bin/env python3
"""
证书加载工具
用于加载 X.509 包装的后量子证书
"""

import os
import sys
import json
from pathlib import Path
from typing import Optional, Tuple
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# 添加项目根目录到路径
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

# 导入 X.509 包装器
from enhanced_certificates.x509_wrapper import PQWrappedCertificate


class CertificateLoader:
    """证书加载器 - 加载 X.509 包装的后量子证书"""
    
    @staticmethod
    def load_x509_pq_certificate(cert_path: str, sig_path: str) -> PQWrappedCertificate:
        """加载 X.509 包装的后量子证书"""
        if not os.path.exists(cert_path):
            raise FileNotFoundError(f"证书文件不存在: {cert_path}")
        if not os.path.exists(sig_path):
            raise FileNotFoundError(f"签名文件不存在: {sig_path}")
        
        return PQWrappedCertificate.load_pem(cert_path, sig_path)
    
    @staticmethod
    def load_private_key(key_path: str) -> bytes:
        """加载私钥（ML-DSA 格式）"""
        if not os.path.exists(key_path):
            raise FileNotFoundError(f"私钥文件不存在: {key_path}")
        
        with open(key_path, 'rb') as f:
            return f.read()
    
    @staticmethod
    def load_x509_certificate(cert_path: str) -> x509.Certificate:
        """加载标准 X.509 证书"""
        if not os.path.exists(cert_path):
            raise FileNotFoundError(f"证书文件不存在: {cert_path}")
        
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        
        return x509.load_pem_x509_certificate(cert_data, default_backend())
    
    @staticmethod
    def load_certificate_chain(chain_path: str) -> list:
        """加载证书链文件"""
        if not os.path.exists(chain_path):
            raise FileNotFoundError(f"证书链文件不存在: {chain_path}")
        
        with open(chain_path, 'rb') as f:
            chain_data = f.read()
        
        # 分离多个证书
        certs = []
        cert_start = b'-----BEGIN CERTIFICATE-----'
        cert_end = b'-----END CERTIFICATE-----'
        
        start_pos = 0
        while True:
            start = chain_data.find(cert_start, start_pos)
            if start == -1:
                break
            
            end = chain_data.find(cert_end, start)
            if end == -1:
                break
            
            cert_pem = chain_data[start:end + len(cert_end)]
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            certs.append(cert)
            
            start_pos = end + len(cert_end)
        
        return certs
    
    @staticmethod
    def extract_pq_public_key_from_cert(cert: x509.Certificate) -> Optional[bytes]:
        """从 X.509 证书的扩展字段中提取后量子公钥"""
        try:
            from enhanced_certificates.x509_wrapper import PQ_PUBLIC_KEY_OID
            
            ext = cert.extensions.get_extension_for_oid(PQ_PUBLIC_KEY_OID)
            metadata = json.loads(ext.value.value.decode('utf-8'))
            return bytes.fromhex(metadata['public_key'])
        except Exception:
            return None
    
    @staticmethod
    def extract_pq_algorithm_from_cert(cert: x509.Certificate) -> Optional[str]:
        """从 X.509 证书的扩展字段中提取后量子算法"""
        try:
            from enhanced_certificates.x509_wrapper import PQ_ALGORITHM_OID
            
            ext = cert.extensions.get_extension_for_oid(PQ_ALGORITHM_OID)
            return ext.value.value.decode('utf-8')
        except Exception:
            return None


class ServerCertificateBundle:
    """服务器证书包 - 包含服务器需要的所有证书和密钥"""
    
    def __init__(self, cert_paths: dict = None, algorithm: str = None):
        """
        初始化证书包
        
        Args:
            cert_paths: 证书路径字典（可选，提供则使用，否则根据algorithm自动生成）
            algorithm: 签名算法（如 "mldsa65", "falcon512"）
        """
        # 如果没有提供cert_paths，根据algorithm自动生成
        if cert_paths is None:
            from implementation.enhanced_v2_by_val.config import get_cert_config
            config = get_cert_config(algorithm)
            paths = config.get_cert_paths()
            self.cert_paths = {
                'server_cert': paths['server_cert'],
                'server_cert_pq_sig': paths['server_sig'],
                'server_key': paths['server_key'],
                'cert_chain': paths['intermediate_cert'],
                'ca_cert': paths['root_cert'],
                'ca_cert_pq_sig': paths['root_sig'],
            }
            self.algorithm = algorithm or "mldsa65"
        else:
            self.cert_paths = cert_paths
            self.algorithm = algorithm or "custom"
        
        self.loader = CertificateLoader()
        
        self.server_cert = None
        self.server_pq_public_key = None
        self.server_pq_algorithm = None
        self.server_pq_signature = None
        self.server_private_key = None
        self.server_signer = None  # ⭐ 签名器对象
        
        self.intermediate_cert = None
        self.root_cert = None
        
        print(f"[配置] 使用签名算法: {self.algorithm}")
        self._load_certificates()
    
    def _load_certificates(self):
        """加载所有证书"""
        print("[加载] 加载服务器证书...")
        
        # 1. 加载服务器证书
        wrapped_cert = self.loader.load_x509_pq_certificate(
            self.cert_paths['server_cert'],
            self.cert_paths['server_cert_pq_sig']
        )
        
        self.server_cert = wrapped_cert.x509_cert
        self.server_pq_public_key = wrapped_cert.get_pq_public_key()
        self.server_pq_algorithm = wrapped_cert.pq_algorithm
        self.server_pq_signature = wrapped_cert.pq_signature
        
        print(f"  [OK] 服务器证书: {self.server_cert.subject}")
        print(f"  [OK] PQ 算法: {self.server_pq_algorithm}")
        print(f"  [OK] PQ 公钥大小: {len(self.server_pq_public_key)} 字节")
        
        # 2. 加载私钥
        self.server_private_key = self.loader.load_private_key(self.cert_paths['server_key'])
        print(f"  [OK] 服务器私钥大小: {len(self.server_private_key)} 字节")
        
        # 3. ⭐ 创建签名器（使用证书中保存的真实私钥）
        import oqs
        
        # ⭐ 使用私钥初始化签名器（liboqs的正确方式）
        # oqs.Signature(algorithm, secret_key) 第二个参数是私钥
        self.server_signer = oqs.Signature(
            self.server_pq_algorithm,
            self.server_private_key  # ⭐ 使用证书中保存的真实私钥
        )
        
        print(f"  [OK] 签名器已用证书私钥初始化")
        print(f"  [OK] 签名将使用{self.server_pq_algorithm}算法")
        print(f"  [OK] 公钥与私钥匹配，客户端可验证签名")
        
        # 4. ⭐ 加载中间CA证书（直接加载）
        try:
            # 从cert_paths中获取中间CA路径
            from implementation.enhanced_v2_by_val.config import get_cert_config
            config = get_cert_config(self.algorithm)
            paths = config.get_cert_paths()
            
            wrapped_intermediate = self.loader.load_x509_pq_certificate(
                paths['intermediate_cert'],
                paths['intermediate_sig']
            )
            self.intermediate_cert = wrapped_intermediate.x509_cert
            self.intermediate_pq_signature = wrapped_intermediate.pq_signature
            self.intermediate_pq_algorithm = wrapped_intermediate.pq_algorithm
            print(f"  [OK] 中间CA证书: {self.intermediate_cert.subject}")
            print(f"  [OK] 中间CA算法: {self.intermediate_pq_algorithm}")
        except Exception as e:
            print(f"  [警告] 加载中间CA失败: {e}")
            self.intermediate_cert = None
        
        # 5. 加载根证书
        wrapped_root = self.loader.load_x509_pq_certificate(
            self.cert_paths['ca_cert'],
            self.cert_paths['ca_cert_pq_sig']
        )
        self.root_cert = wrapped_root.x509_cert
        print(f"  [OK] 根证书: {self.root_cert.subject}")
        
        print("[完成] 服务器证书加载完成\n")
    
    def get_cert_chain_bytes(self) -> bytes:
        """获取证书链的字节表示（用于 TLS 握手）"""
        cert_bytes = self.server_cert.public_bytes(serialization.Encoding.DER)
        
        if self.intermediate_cert:
            cert_bytes += self.intermediate_cert.public_bytes(serialization.Encoding.DER)
        
        return cert_bytes


class ClientCertificateBundle:
    """客户端证书包"""
    
    def __init__(self, cert_paths: dict):
        self.cert_paths = cert_paths
        self.loader = CertificateLoader()
        
        self.root_cert = None
        self.root_pq_public_key = None
        self.root_pq_algorithm = None
        
        self.intermediate_cert = None
        self.intermediate_pq_public_key = None
        self.intermediate_pq_algorithm = None
        
        self._load_trust_store()
    
    def _load_trust_store(self):
        """加载信任存储"""
        print("[加载] 加载客户端信任存储...")
        
        # 1. 加载根证书
        wrapped_root = self.loader.load_x509_pq_certificate(
            self.cert_paths['client_trust_store'],
            self.cert_paths['client_trust_store_pq_sig']
        )
        
        self.root_cert = wrapped_root.x509_cert
        self.root_pq_public_key = wrapped_root.get_pq_public_key()
        self.root_pq_algorithm = wrapped_root.pq_algorithm
        
        print(f"  [OK] 根证书（信任锚点）: {self.root_cert.subject}")
        print(f"  [OK] 根 PQ 算法: {self.root_pq_algorithm}")
        
        # 2. 加载中间证书缓存
        wrapped_intermediate = self.loader.load_x509_pq_certificate(
            self.cert_paths['client_intermediate_cache'],
            self.cert_paths['client_intermediate_cache_pq_sig']
        )
        
        self.intermediate_cert = wrapped_intermediate.x509_cert
        self.intermediate_pq_public_key = wrapped_intermediate.get_pq_public_key()
        self.intermediate_pq_algorithm = wrapped_intermediate.pq_algorithm
        
        print(f"  [OK] 中间证书（缓存）: {self.intermediate_cert.subject}")
        print(f"  [OK] 中间 PQ 算法: {self.intermediate_pq_algorithm}")
        
        print("[完成] 客户端信任存储加载完成\n")


# 便捷函数
def load_server_certificates(mode: str = 'HYBRID') -> ServerCertificateBundle:
    """加载服务器证书包"""
    from implementation.enhanced_v2_by_val.config import get_default_cert_paths
    cert_paths = get_default_cert_paths(mode)
    return ServerCertificateBundle(cert_paths)


def load_client_certificates(mode: str = 'HYBRID') -> ClientCertificateBundle:
    """加载客户端证书包"""
    from implementation.enhanced_v2_by_val.config import get_default_cert_paths
    cert_paths = get_default_cert_paths(mode)
    return ClientCertificateBundle(cert_paths)

