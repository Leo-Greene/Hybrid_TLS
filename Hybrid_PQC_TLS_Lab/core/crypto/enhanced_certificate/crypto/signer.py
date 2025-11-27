"""
证书签发器 - 支持经典和后量子算法的签名生成
"""

from abc import ABC, abstractmethod
from typing import Tuple

# 修复导入路径
import sys
from pathlib import Path

# 添加项目根目录到路径
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

# 添加core.crypto目录到路径
crypto_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(crypto_dir))

# 导入真实的签名实现
from signature import (
    DilithiumSignature, FalconSignature, 
    ECDSASignature, RSAPSSSignature
)

# 自定义异常类
class PQSignatureError(Exception):
    """后量子签名错误"""
    pass

class CertificateSigner(ABC):
    """证书签发器抽象基类"""
    
    @abstractmethod
    def sign_certificate(self, tbs_data: bytes, private_key: bytes) -> Tuple[bytes, bytes]:
        """
        为证书数据生成签名
        
        参数:
            tbs_data: 待签名的证书数据
            private_key: 签发者私钥
            
        返回:
            Tuple[签名, 公钥]
        """
        pass
    
    @abstractmethod
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """生成密钥对"""
        pass


class MLDSASigner(CertificateSigner):
    """ML-DSA 证书签发器"""
    
    def __init__(self, variant: str = "ML-DSA-65"):
        self.variant = variant
        self._setup_parameters()
        
        # 创建真实的Dilithium签名实例
        variant_map = {
            "ML-DSA-44": 2,  # Dilithium2
            "ML-DSA-65": 3,  # Dilithium3  
            "ML-DSA-87": 5   # Dilithium5
        }
        self.dilithium_signer = DilithiumSignature(variant=variant_map[variant])
    
    def _setup_parameters(self):
        """设置ML-DSA参数"""
        self.parameters = {
            "ML-DSA-44": {"sig_size": 2420, "pub_key_size": 1312},
            "ML-DSA-65": {"sig_size": 3309, "pub_key_size": 1952},
            "ML-DSA-87": {"sig_size": 4627, "pub_key_size": 2592}
        }[self.variant]
    
    def sign_certificate(self, tbs_data: bytes, private_key: bytes) -> Tuple[bytes, bytes]:
        """为证书生成ML-DSA签名"""
        try:
            # 使用真实的Dilithium签名实现
            self.dilithium_signer.set_private_key(private_key)
            signature = self.dilithium_signer.sign(tbs_data)
            public_key = self.dilithium_signer.get_public_key()
            
            return signature, public_key
            
        except Exception as e:
            raise PQSignatureError(f"ML-DSA signing failed: {str(e)}")
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """生成ML-DSA密钥对"""
        # 使用真实的Dilithium密钥生成
        self.dilithium_signer.generate_keypair()
        private_key = self.dilithium_signer.get_private_key()
        public_key = self.dilithium_signer.get_public_key()
        return private_key, public_key


class ClassicSigner(CertificateSigner):
    """经典算法证书签发器"""
    
    def __init__(self, algorithm: str = "ECDSA-SHA256"):
        self.algorithm = algorithm
        
        # 创建真实的签名实例
        if self.algorithm == "ECDSA-SHA256":
            self.classic_signer = ECDSASignature("P-256")
        elif self.algorithm == "ECDSA-SHA384":
            self.classic_signer = ECDSASignature("P-384")
        else:  # RSA算法
            key_size = 2048 if "2048" in algorithm else 3072 if "3072" in algorithm else 4096
            self.classic_signer = RSAPSSSignature(key_size=key_size)
    
    def sign_certificate(self, tbs_data: bytes, private_key: bytes) -> Tuple[bytes, bytes]:
        """为证书生成经典算法签名"""
        try:
            # 使用真实的经典算法签名实现
            self.classic_signer.set_private_key(private_key)
            signature = self.classic_signer.sign(tbs_data)
            public_key = self.classic_signer.get_public_key()
            
            return signature, public_key
            
        except Exception as e:
            raise PQSignatureError(f"Classic signing failed: {str(e)}")
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """生成经典算法密钥对"""
        # 使用真实的经典算法密钥生成
        self.classic_signer.generate_keypair()
        private_key = self.classic_signer.get_private_key()
        public_key = self.classic_signer.get_public_key()
        return private_key, public_key


class FalconSigner(CertificateSigner):
    """Falcon 证书签发器"""
    
    def __init__(self, variant: str = "Falcon-512"):
        self.variant = variant
        
        # 创建真实的Falcon签名实例
        variant_map = {
            "Falcon-512": 512,
            "Falcon-1024": 1024
        }
        self.falcon_signer = FalconSignature(variant=variant_map[variant])
    
    def sign_certificate(self, tbs_data: bytes, private_key: bytes) -> Tuple[bytes, bytes]:
        """为证书生成Falcon签名"""
        try:
            # 使用真实的Falcon签名实现
            self.falcon_signer.set_private_key(private_key)
            signature = self.falcon_signer.sign(tbs_data)
            public_key = self.falcon_signer.get_public_key()
            
            return signature, public_key
            
        except Exception as e:
            raise PQSignatureError(f"Falcon signing failed: {str(e)}")
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """生成Falcon密钥对"""
        # 使用真实的Falcon密钥生成
        self.falcon_signer.generate_keypair()
        private_key = self.falcon_signer.get_private_key()
        public_key = self.falcon_signer.get_public_key()
        return private_key, public_key

