"""数字签名实现 - 支持经典、PQC和混合模式"""

from abc import ABC, abstractmethod
from typing import Tuple
import os
import hashlib
from pathlib import Path
import sys
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature
)
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import oqs


# 在signature.py中直接定义SignatureScheme枚举，避免导入路径问题
class SignatureScheme:
    """签名算法枚举"""
    # 经典签名
    ecdsa_secp256r1_sha256 = 0x0403
    ecdsa_secp384r1_sha384 = 0x0503
    ecdsa_secp521r1_sha512 = 0x0603
    rsa_pss_sha256 = 0x0804
    rsa_pss_sha384 = 0x0805
    rsa_pss_sha512 = 0x0806
    rsa_pss_rsae_sha256 = 0x0804  # 与rsa_pss_sha256相同
    rsa_pss_rsae_sha384 = 0x0805  # 与rsa_pss_sha384相同
    rsa_pss_rsae_sha512 = 0x0806  # 与rsa_pss_sha512相同
    
    # NIST标准化的PQC签名
    ML_DSA_44 = 0xFE00     # Dilithium2 (NIST ML-DSA-44)
    ML_DSA_65 = 0xFE01     # Dilithium3 (NIST ML-DSA-65)
    ML_DSA_87 = 0xFE02     # Dilithium5 (NIST ML-DSA-87)
    
    # 实验性PQC签名
    dilithium2 = 0xFE03
    dilithium3 = 0xFE06
    dilithium5 = 0xFE07
    falcon512 = 0xFE0B
    falcon1024 = 0xFE0E
    
    # 混合签名
    p256_dilithium2 = 0xFE04
    p256_dilithium3 = 0xFEF2
    p384_dilithium5 = 0xFE08
    p256_falcon512 = 0xFE0C
    p521_falcon1024 = 0xFE0F



class Signature(ABC):
    """数字签名抽象基类"""
    
    @abstractmethod
    def generate_keypair(self) -> None:
        """生成签名密钥对"""
        pass

    def set_private_key(self, private_key: bytes) -> None:
        """设置私钥"""
        self._private_key = private_key
    
    @abstractmethod
    def get_public_key(self) -> bytes:
        """获取公钥"""
        pass

    def set_public_key(self, public_key: bytes) -> None:
        """设置公钥"""
        self._public_key = public_key
    
    @abstractmethod
    def get_private_key(self) -> bytes:
        """获取私钥"""
        pass
    
    @abstractmethod
    def sign(self, message: bytes) -> bytes:
        """签名消息"""
        pass
    
    @abstractmethod
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """验证签名"""
        pass
    
    @abstractmethod
    def get_scheme(self) -> SignatureScheme:
        """获取签名算法标识"""
        pass


class ECDSASignature(Signature):
    """ECDSA签名（P-256）"""
    
    def __init__(self, curve_name: str = "P-256"):
        self.curve_name = curve_name
        self._private_key = None
        self._public_key = None
    
    def generate_keypair(self) -> None:
        """生成密钥对"""
        # 使用真实的ECDSA
        curve = ec.SECP256R1()  # P-256
        self._private_key = ec.generate_private_key(curve, default_backend())
        self._public_key = self._private_key.public_key()
    
    def get_public_key(self) -> bytes:
        """获取公钥"""
        if self._private_key is None:
            raise ValueError("Must call generate_keypair() or set_private_key() first")
        
        # 动态生成公钥（如果需要）
        if self._public_key is None:
            self._public_key = self._private_key.public_key()
        
        public_key_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        return public_key_bytes
    
    def get_private_key(self) -> bytes:
        """获取私钥"""
        if self._private_key is None:
            raise ValueError("Must call generate_keypair() first")
        
        private_key_bytes = self._private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return private_key_bytes
    
    def set_private_key(self, private_key: bytes) -> None:
        """设置私钥（从字节数据加载，支持PEM和DER格式）"""
        # 从字节数据加载私钥，支持PEM和DER格式
        try:
            # 检查是否为PEM格式（包含BEGIN/END标记）
            if b'-----BEGIN PRIVATE KEY-----' in private_key and b'-----END PRIVATE KEY-----' in private_key:
                # 首先尝试使用标准的load_pem_private_key
                try:
                    self._private_key = serialization.load_pem_private_key(
                        private_key,
                        password=None,
                        backend=default_backend()
                    )
                except Exception as e1:
                    # 如果标准方法失败，尝试手动提取DER数据
                    # 提取PEM内容（去除BEGIN/END标记和换行符）
                    pem_data = private_key
                    begin_marker = b'-----BEGIN PRIVATE KEY-----'
                    end_marker = b'-----END PRIVATE KEY-----'
                    
                    begin_pos = pem_data.find(begin_marker) + len(begin_marker)
                    end_pos = pem_data.find(end_marker)
                    
                    if begin_pos > 0 and end_pos > begin_pos:
                        # 提取Base64编码的内容
                        pem_content = pem_data[begin_pos:end_pos]
                        # 去除空白字符
                        pem_content = b''.join(pem_content.split())
                        
                        # Base64解码PEM内容得到DER数据
                        import base64
                        der_data = base64.b64decode(pem_content)
                        
                        # 尝试从DER格式加载私钥
                        self._private_key = serialization.load_der_private_key(
                            der_data,
                            password=None,
                            backend=default_backend()
                        )
                    else:
                        raise ValueError("无效的PEM格式")
            else:
                # 直接尝试从DER格式加载私钥
                self._private_key = serialization.load_der_private_key(
                    private_key,
                    password=None,
                    backend=default_backend()
                )
            
            # 不需要重新生成公钥，因为公钥应该从证书中提取
            # 公钥将在需要时通过get_public_key()方法动态生成
            
        except Exception as e:
            raise RuntimeError(f"无法加载ECDSA私钥: {e}")
    
    def sign(self, message: bytes) -> bytes:
        """签名消息"""
        if self._private_key is None:
            raise ValueError("Must call generate_keypair() first")
        
        signature = self._private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        
        return signature
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """验证签名"""
        try:
            pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(),
                public_key
            )
            pub_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception as e:
            return False
    
    def get_scheme(self) -> SignatureScheme:
        return SignatureScheme.ecdsa_secp256r1_sha256
    
    def get_key_object(self, key_bytes: bytes, key_type: str = "public") -> object:
        """
        将字节形式的ECDSA密钥转换为标准密钥对象
        
        Args:
            key_bytes: 密钥的字节表示
            key_type: 密钥类型（"public" 或 "private"）
        
        Returns:
            标准密钥对象（EllipticCurvePublicKey 或 EllipticCurvePrivateKey）
        """
        if key_type == "public":
            # 将字节数据转换为ECDSA公钥对象
            key_obj = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), key_bytes
            )
            return key_obj
        elif key_type == "private":
            # 将字节数据转换为ECDSA私钥对象
            key_obj = serialization.load_der_private_key(
                key_bytes, password=None, backend=default_backend()
            )
            return key_obj
        else:
            raise ValueError(f"不支持的密钥类型: {key_type}")


class RSAPSSSignature(Signature):
    """RSA-PSS签名"""
    
    def __init__(self, key_size: int = 2048):
        """
        Args:
            key_size: RSA密钥大小（2048, 3072, 4096等）
        """
        self.key_size = key_size
        self._private_key = None
        self._public_key = None
    def generate_keypair(self) -> None:
        """生成密钥对"""
        # 生成RSA密钥对
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        self._public_key = self._private_key.public_key()
    def get_public_key(self) -> bytes:
        """获取公钥"""
        if self._private_key is None:
            raise ValueError("Must call generate_keypair() or set_private_key() first")
        
        # 动态生成公钥（如果需要）
        if self._public_key is None:
            self._public_key = self._private_key.public_key()
        
        public_key_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_key_bytes
    
    def get_private_key(self) -> bytes:
        """获取私钥"""
        if self._private_key is None:
            raise ValueError("Must call generate_keypair() first")
        
        private_key_bytes = self._private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return private_key_bytes
    
    def set_private_key(self, private_key: bytes) -> None:
        """设置私钥（从字节数据加载，支持PEM和DER格式）"""
        # 从字节数据加载私钥，支持PEM和DER格式
        try:
            # 检查是否为PEM格式（包含BEGIN/END标记）
            if b'-----BEGIN PRIVATE KEY-----' in private_key and b'-----END PRIVATE KEY-----' in private_key:
                # 首先尝试使用标准的load_pem_private_key
                try:
                    self._private_key = serialization.load_pem_private_key(
                        private_key,
                        password=None,
                        backend=default_backend()
                    )
                except Exception as e1:
                    # 如果标准方法失败，尝试手动提取DER数据
                    # 提取PEM内容（去除BEGIN/END标记和换行符）
                    pem_data = private_key
                    begin_marker = b'-----BEGIN PRIVATE KEY-----'
                    end_marker = b'-----END PRIVATE KEY-----'
                    
                    begin_pos = pem_data.find(begin_marker) + len(begin_marker)
                    end_pos = pem_data.find(end_marker)
                    
                    if begin_pos > 0 and end_pos > begin_pos:
                        # 提取Base64编码的内容
                        pem_content = pem_data[begin_pos:end_pos]
                        # 去除空白字符
                        pem_content = b''.join(pem_content.split())
                        
                        # Base64解码PEM内容得到DER数据
                        import base64
                        der_data = base64.b64decode(pem_content)
                        
                        # 尝试从DER格式加载私钥
                        self._private_key = serialization.load_der_private_key(
                            der_data,
                            password=None,
                            backend=default_backend()
                        )
                    else:
                        raise ValueError("无效的PEM格式")
            else:
                # 直接尝试从DER格式加载私钥
                self._private_key = serialization.load_der_private_key(
                    private_key,
                    password=None,
                    backend=default_backend()
                )
            # 不需要重新生成公钥，因为公钥应该从证书中提取
            # 公钥将在需要时通过get_public_key()方法动态生成
        except Exception as e:
            raise RuntimeError(f"无法加载RSA私钥: {e}")
    
    def sign(self, message: bytes) -> bytes:
        """签名消息"""
        if self._private_key is None:
            raise ValueError("Must call generate_keypair() first")
        
        # 使用PSS填充方案进行签名
        signature = self._private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """验证签名"""
        try:
            # 从字节数据加载公钥
            pub_key = serialization.load_der_public_key(
                public_key,
                backend=default_backend()
            )
            
            # 验证签名
            pub_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            return False
    
    def get_scheme(self) -> SignatureScheme:
        """获取签名方案"""
        schemes = {
            2048: SignatureScheme.rsa_pss_rsae_sha256,
            3072: SignatureScheme.rsa_pss_rsae_sha256,
            4096: SignatureScheme.rsa_pss_rsae_sha256,
        }
        return schemes.get(self.key_size, SignatureScheme.rsa_pss_rsae_sha256)
    
    def get_key_object(self, key_bytes: bytes, key_type: str = "public") -> object:
        """
        将字节形式的RSA密钥转换为标准密钥对象
        
        Args:
            key_bytes: 密钥的字节表示
            key_type: 密钥类型（"public" 或 "private"）
        
        Returns:
            标准密钥对象（RSAPublicKey 或 RSAPrivateKey）
        """
        if key_type == "public":
            # 将字节数据转换为RSA公钥对象
            key_obj = serialization.load_der_public_key(
                key_bytes, backend=default_backend()
            )
            return key_obj
        elif key_type == "private":
            # 将字节数据转换为RSA私钥对象
            key_obj = serialization.load_der_private_key(
                key_bytes, password=None, backend=default_backend()
            )
            return key_obj
        else:
            raise ValueError(f"不支持的密钥类型: {key_type}")


class DilithiumSignature(Signature):
    """Dilithium后量子签名"""
    
    def __init__(self, variant: int = 3):
        """
        Args:
            variant: Dilithium变体 (2, 3, 5)
        """
        self.variant = variant
        
        # Dilithium参数
        self.params = {
            2: {'pk': 1312, 'sk': 2528, 'sig': 2420},
            3: {'pk': 1952, 'sk': 4000, 'sig': 3293},
            5: {'pk': 2592, 'sk': 4864, 'sig': 4595},
        }[variant]
        
        
        sig_names = {
            2: "ML-DSA-44",  # Dilithium2的标准化名称
            3: "ML-DSA-65",  # Dilithium3的标准化名称
            5: "ML-DSA-87",  # Dilithium5的标准化名称
        }
        
        try:
            self.sig = oqs.Signature(sig_names[variant])
        except Exception as e:
            # 尝试使用旧的Dilithium名称作为备选
            old_sig_names = {
                2: "Dilithium2",
                3: "Dilithium3",
                5: "Dilithium5",
            }
            try:
                self.sig = oqs.Signature(old_sig_names[variant])
            except Exception as e2:
                raise RuntimeError(f"创建Dilithium签名实例失败: {e} (尝试旧名称也失败: {e2})")
        
        self._private_key = None
        self._public_key = None
    
    def generate_keypair(self) -> None:
        """生成密钥对"""
        self._public_key = self.sig.generate_keypair()
        self._private_key = self.sig.export_secret_key()
    def get_public_key(self) -> bytes:
        """获取公钥"""
        if self._public_key is None:
            raise ValueError("Must call generate_keypair() first")
        return self._public_key
    
    def get_private_key(self) -> bytes:
        """获取私钥"""
        if self._private_key is None:
            raise ValueError("Must call generate_keypair() first")
        return self._private_key

    def set_private_key(self, private_key: bytes) -> None:
        """设置私钥"""
        self._private_key = private_key
    def sign(self, message: bytes) -> bytes:
        """
        ⭐ 签名消息 - 使用真实的ML-DSA私钥
        """
        if self._private_key is None:
            raise ValueError("必须先调用 generate_keypair() 或 set_private_key()")
        
        # ⭐ 关键修复：使用已设置的私钥进行签名
        # liboqs的Signature对象在创建时会生成新密钥对
        # 我们需要确保使用正确的私钥
        
        # 创建临时签名器并导入正确的私钥
        sig_names = {
            2: "ML-DSA-44",
            3: "ML-DSA-65",
            5: "ML-DSA-87",
        }
        
        temp_sig = oqs.Signature(sig_names[self.variant], self._private_key)
        signature = temp_sig.sign(message)
        return signature
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """验证签名 - 使用指定的公钥"""
        try:
            # ⭐ 为每次验证创建一个新的oqs.Signature实例
            # 使用传入的公钥初始化
            sig_names = {
                2: "ML-DSA-44",
                3: "ML-DSA-65", 
                5: "ML-DSA-87",
            }
            algo_name = sig_names.get(self.variant, f"Dilithium{self.variant}")
            
            # 创建临时验证器，使用传入的公钥
            temp_verifier = oqs.Signature(algo_name, secret_key=None)
            result = temp_verifier.verify(message, signature, public_key)
            
            return result
        except Exception as e:
            # 尝试使用不同的验证方法
            try:
                # 重新创建签名实例进行验证
                sig_names = {
                    2: "ML-DSA-44",
                    3: "ML-DSA-65", 
                    5: "ML-DSA-87",
                }
                temp_sig = oqs.Signature(sig_names[self.variant])
                result = temp_sig.verify(message, signature, public_key)
                return result
            except Exception as e2:
                return False
    
    def get_scheme(self) -> SignatureScheme:
        schemes = {
            2: SignatureScheme.dilithium2,
            3: SignatureScheme.dilithium3,
            5: SignatureScheme.dilithium5,
        }
        return schemes[self.variant]
    
    def get_key_object(self, key_bytes: bytes, key_type: str = "public") -> object:
        """
        将字节形式的Dilithium密钥转换为标准密钥对象
        
        Args:
            key_bytes: 密钥的字节表示
            key_type: 密钥类型（"public" 或 "private"）
        
        Returns:
            标准密钥对象（对于Dilithium，直接返回字节数据）
        """
        # Dilithium签名算法没有标准的Python对象表示
        # 因此直接返回字节数据
        return key_bytes

class FalconSignature(Signature):
    """Falcon签名"""
    
    def __init__(self, variant: int = 512):
        """
        Args:
            variant: Falcon变体（512或1024）
        """
        self.variant = variant

        try:
            self.sig = oqs.Signature(f"Falcon-{variant}")
        except Exception as e:
            raise RuntimeError(f"创建Falcon签名实例失败: {e}")
        
        self._private_key = None
        self._public_key = None
    
    def generate_keypair(self) -> None:
        """生成密钥对"""
        self._public_key = self.sig.generate_keypair()
        self._private_key = self.sig.export_secret_key()
    def get_public_key(self) -> bytes:
        """获取公钥"""
        if self._public_key is None:
            raise ValueError("Must call generate_keypair() first")
        return self._public_key
    
    def get_private_key(self) -> bytes:
        """获取私钥"""
        if self._private_key is None:
            raise ValueError("Must call generate_keypair() first")
        return self._private_key
    
    def set_private_key(self, private_key: bytes) -> None:
        """设置私钥"""
        self._private_key = private_key
    def sign(self, message: bytes) -> bytes:
        """签名消息"""
        if self._private_key is None:
            raise ValueError("Must call generate_keypair() or set_private_key() first")
        
        signature = self.sig.sign(message)
        return signature
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """验证签名"""
        try:
            # 检查公钥数据是否可能包含额外信息
            # Falcon-512公钥应该是897字节，Falcon-1024公钥应该是1793字节
            expected_sizes = {512: 897, 1024: 1793}
            expected_size = expected_sizes.get(self.variant)
            
            if expected_size and len(public_key) != expected_size:
                # 对于Falcon-1024，实际大小1793字节是正确的，不应该截取
                if self.variant == 1024 and len(public_key) == 1793: 
                    pass
                elif len(public_key) > expected_size:
                    public_key = public_key[:expected_size]
                elif len(public_key) < expected_size:
                    return False
            
            # ⭐ 为每次验证创建新的oqs.Signature实例，使用传入的公钥
            temp_verifier = oqs.Signature(f"Falcon-{self.variant}", secret_key=None)
            result = temp_verifier.verify(message, signature, public_key)
            
            if result:
                pass
            else:
                pass
            return result
        except Exception as e:
            return False
    
    def get_scheme(self) -> SignatureScheme:
        """获取签名方案"""
        schemes = {
            512: SignatureScheme.falcon512,
            1024: SignatureScheme.falcon1024,
        }
        return schemes[self.variant]
    
    def get_key_object(self, key_bytes: bytes, key_type: str = "public") -> object:
        """
        将字节形式的Falcon密钥转换为标准密钥对象
        
        Args:
            key_bytes: 密钥的字节表示
            key_type: 密钥类型（"public" 或 "private"）
        
        Returns:
            标准密钥对象（对于Falcon，直接返回字节数据）
        """
        # Falcon签名算法没有标准的Python对象表示
        # 因此直接返回字节数据
        return key_bytes
        


class HybridSignature(Signature):
    """混合签名：经典 + 后量子"""
    
    def __init__(self, classical: Signature, pqc: Signature):
        """
        Args:
            classical: 传统签名（如ECDSA）
            pqc: 后量子签名（如Dilithium）
        """
        self.classical = classical
        self.pqc = pqc
        self._scheme = self._determine_scheme()
    def _determine_scheme(self) -> SignatureScheme:
        """确定混合签名方案"""
        classical_scheme = self.classical.get_scheme()
        pqc_scheme = self.pqc.get_scheme()
        
        # 映射到混合方案
        mapping = {
            (SignatureScheme.ecdsa_secp256r1_sha256, SignatureScheme.dilithium2):
                SignatureScheme.p256_dilithium2,
            (SignatureScheme.ecdsa_secp256r1_sha256, SignatureScheme.dilithium3):
                SignatureScheme.p256_dilithium3,
            (SignatureScheme.ecdsa_secp384r1_sha384, SignatureScheme.dilithium5):
                SignatureScheme.p384_dilithium5,
        }
        
        return mapping.get(
            (classical_scheme, pqc_scheme),
            SignatureScheme.p256_dilithium3
        )
    
    def generate_keypair(self) -> None:
        """生成两个密钥对"""
        self.classical.generate_keypair()
        self.pqc.generate_keypair()
    def get_public_key(self) -> bytes:
        """获取组合的公钥"""
        classical_pub = self.classical.get_public_key()
        pqc_pub = self.pqc.get_public_key()
        # 格式: [classical_len(2字节)][classical_pub][pqc_pub]
        data = len(classical_pub).to_bytes(2, 'big')
        data += classical_pub
        data += pqc_pub
        return data
    
    def get_private_key(self) -> bytes:
        """获取组合的私钥"""
        classical_priv = self.classical.get_private_key()
        pqc_priv = self.pqc.get_private_key()
        # 格式: [classical_len(2字节)][classical_priv][pqc_priv]
        data = len(classical_priv).to_bytes(2, 'big')
        data += classical_priv
        data += pqc_priv
        return data
    
    def sign(self, message: bytes) -> bytes:
        """签名消息（两个签名）"""
        classical_sig = self.classical.sign(message)
        pqc_sig = self.pqc.sign(message)
        # 组合签名: [classical_len(4字节)][classical_sig][pqc_sig]
        data = len(classical_sig).to_bytes(4, 'big')
        data += classical_sig
        data += pqc_sig
        return data
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """验证混合签名（两个都必须有效）"""
        try:
            # 解析公钥
            classical_pub_len = int.from_bytes(public_key[:2], 'big')
            classical_pub = public_key[2:2+classical_pub_len]
            pqc_pub = public_key[2+classical_pub_len:]
            # 解析签名
            classical_sig_len = int.from_bytes(signature[:4], 'big')
            classical_sig = signature[4:4+classical_sig_len]
            pqc_sig = signature[4+classical_sig_len:]
            # 验证两个签名
            classical_valid = self.classical.verify(message, classical_sig, classical_pub)
            pqc_valid = self.pqc.verify(message, pqc_sig, pqc_pub)
            # 两个都必须有效
            result = classical_valid and pqc_valid
            if result:
                pass
            else:
                pass
            return result
            
        except Exception as e:
            return False
    
    def get_scheme(self) -> SignatureScheme:
        return self._scheme
    
    def get_key_object(self, key_bytes: bytes, key_type: str = "public") -> object:
        """
        将字节形式的混合密钥转换为标准密钥对象
        
        Args:
            key_bytes: 密钥的字节表示
            key_type: 密钥类型（"public" 或 "private"）
        
        Returns:
            标准密钥对象（对于混合签名，返回组合的密钥对象）
        """
        # 混合签名的密钥是组合的，需要分别处理经典和PQC部分
        if key_type == "public":
            # 解析组合公钥
            classical_pub_len = int.from_bytes(key_bytes[:2], 'big')
            classical_pub = key_bytes[2:2+classical_pub_len]
            pqc_pub = key_bytes[2+classical_pub_len:]
            
            # 分别转换经典和PQC公钥
            classical_obj = self.classical.get_key_object(classical_pub, "public")
            pqc_obj = self.pqc.get_key_object(pqc_pub, "public")
            
            # 返回组合对象（这里返回元组，因为混合密钥没有单一对象表示）
            return (classical_obj, pqc_obj)
            
        elif key_type == "private":
            # 解析组合私钥
            classical_priv_len = int.from_bytes(key_bytes[:2], 'big')
            classical_priv = key_bytes[2:2+classical_priv_len]
            pqc_priv = key_bytes[2+classical_priv_len:]
            
            # 分别转换经典和PQC私钥
            classical_obj = self.classical.get_key_object(classical_priv, "private")
            pqc_obj = self.pqc.get_key_object(pqc_priv, "private")
            
            # 返回组合对象
            return (classical_obj, pqc_obj)
        else:
            raise ValueError(f"不支持的密钥类型: {key_type}")


def create_signature(scheme: SignatureScheme) -> Signature:
    """创建签名实例
    
    Args:
        scheme: 签名算法
    
    Returns:
        Signature实例
    """
    from core.types import get_signature_name
    scheme_name = get_signature_name(scheme)
    if scheme == SignatureScheme.ecdsa_secp256r1_sha256:
        return ECDSASignature("P-256")
    
    elif scheme == SignatureScheme.ecdsa_secp384r1_sha384:
        return ECDSASignature("P-384")
    
    elif scheme in [SignatureScheme.dilithium2, SignatureScheme.ML_DSA_44]:
        return DilithiumSignature(variant=2)
    
    elif scheme in [SignatureScheme.dilithium3, SignatureScheme.ML_DSA_65]:
        return DilithiumSignature(variant=3)
    
    elif scheme in [SignatureScheme.dilithium5, SignatureScheme.ML_DSA_87]:
        return DilithiumSignature(variant=5)
    
    elif scheme == SignatureScheme.p256_dilithium2:
        return HybridSignature(
            ECDSASignature("P-256"),
            DilithiumSignature(variant=2)
        )
    
    elif scheme == SignatureScheme.p256_dilithium3:
        return HybridSignature(
            ECDSASignature("P-256"),
            DilithiumSignature(variant=3)
        )
    
    elif scheme == SignatureScheme.p384_dilithium5:
        return HybridSignature(
            ECDSASignature("P-384"),
            DilithiumSignature(variant=5)
        )
    
    elif scheme == SignatureScheme.falcon512:
        return FalconSignature(variant=512)
    
    elif scheme == SignatureScheme.falcon1024:
        return FalconSignature(variant=1024)
    
    elif scheme == SignatureScheme.rsa_pss_rsae_sha256:
        return RSAPSSSignature(key_size=2048)
    
    elif scheme == SignatureScheme.rsa_pss_rsae_sha384:
        return RSAPSSSignature(key_size=3072)
    
    elif scheme == SignatureScheme.rsa_pss_rsae_sha512:
        return RSAPSSSignature(key_size=4096)
    
    else:
        raise ValueError(f"Unsupported signature scheme: {scheme}")


def test_signature():
    """测试签名模块"""
    print("🧪 测试签名模块\n")
    
    schemes_to_test = [
        #SignatureScheme.ecdsa_secp256r1_sha256,
        SignatureScheme.ecdsa_secp384r1_sha384,
        SignatureScheme.ML_DSA_44,
        SignatureScheme.ML_DSA_65,
        SignatureScheme.falcon512,
        #SignatureScheme.p256_dilithium3,
        SignatureScheme.rsa_pss_rsae_sha256,
        SignatureScheme.rsa_pss_rsae_sha384,
        SignatureScheme.rsa_pss_rsae_sha512,
    ]
    
    message = b"Hello, Post-Quantum World!"
    
    for scheme in schemes_to_test:
        from core.types import get_signature_name
        print(f"测试: {get_signature_name(scheme)}")
        
        # 生成密钥对
        signer = create_signature(scheme)
        signer.generate_keypair()
        public_key = signer.get_public_key()
        print(f"  ✓ 公钥大小: {len(public_key)}字节")
        
        # 签名
        signature = signer.sign(message)
        print(f"  ✓ 签名大小: {len(signature)}字节")
        
        # 验证
        valid = signer.verify(message, signature, public_key)
        if valid:
            print(f"  [OK] 签名验证通过")
        else:
            print(f"  ❌ 签名验证失败")
        
        # 测试错误消息
        wrong_valid = signer.verify(b"Wrong message", signature, public_key)
        if not wrong_valid:
            print(f"  ✅ 正确拒绝错误消息")
        else:
            print(f"  ⚠️  警告：错误接受了错误消息")
        
        print()


if __name__ == '__main__':
    test_signature()

