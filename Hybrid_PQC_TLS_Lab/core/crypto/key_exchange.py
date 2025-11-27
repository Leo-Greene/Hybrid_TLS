"""密钥交换实现 - 支持经典、PQC和混合模式"""
from abc import ABC, abstractmethod
from typing import Tuple
import hashlib
from pathlib import Path
import sys

# 导入必要的库
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import oqs

# 添加项目根目录到路径，支持独立运行
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from core.types import SignatureScheme, NamedGroup



class KeyExchange(ABC):
    """密钥交换抽象基类"""
    
    @abstractmethod
    def generate_keypair(self) -> None:
        """生成密钥对"""
        pass
    
    @abstractmethod
    def get_public_key(self) -> bytes:
        """获取公钥（或KEM密文）"""
        pass
    
    @abstractmethod
    def compute_shared_secret(self, peer_public: bytes) -> bytes:
        """计算共享密钥"""
        pass
    
    @abstractmethod
    def get_group(self) -> NamedGroup:
        """获取算法组标识"""
        pass


class X25519KeyExchange(KeyExchange):
    """X25519密钥交换（经典ECDH）"""
    
    def __init__(self):
        self._private_key = None
        self._public_key = None
    
    def generate_keypair(self) -> None:
        """生成密钥对"""
        self._private_key = x25519.X25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
    
    def get_public_key(self) -> bytes:
        """获取公钥"""
        if self._public_key is None:
            raise ValueError("Must call generate_keypair() first")
        
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def compute_shared_secret(self, peer_public: bytes) -> bytes:
        """计算共享密钥"""
        if self._private_key is None:
            raise ValueError("Must call generate_keypair() first")
        
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public)
        shared = self._private_key.exchange(peer_public_key)
        return shared
    
    def get_group(self) -> NamedGroup:
        return NamedGroup.x25519

# p256实现在这里
class P256KeyExchange(KeyExchange):
    """P-256 (secp256r1) 密钥交换"""
    
    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        self.ec = ec
        self.hashes = hashes
        self._private_key = None
        self._public_key = None
    
    def generate_keypair(self) -> None:
        """生成P-256密钥对"""
        self._private_key = self.ec.generate_private_key(self.ec.SECP256R1())
        self._public_key = self._private_key.public_key()
    
    def get_public_key(self) -> bytes:
        """获取P-256公钥"""
        if self._public_key is None:
            raise ValueError("Must call generate_keypair() first")
        
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
    
    def compute_shared_secret(self, peer_public: bytes) -> bytes:
        """计算P-256共享密钥"""
        if self._private_key is None:
            raise ValueError("Must call generate_keypair() first")
        
        # 解析对端公钥
        peer_public_key = self.ec.EllipticCurvePublicKey.from_encoded_point(
            self.ec.SECP256R1(), peer_public
        )
        
        # 计算共享密钥
        shared_secret = self._private_key.exchange(self.ec.ECDH(), peer_public_key)
        
        # 使用SHA-256进行密钥派生
        derived_key = hashlib.sha256(shared_secret).digest()
        
        return derived_key
    
    def get_group(self) -> NamedGroup:
        return NamedGroup.secp256r1


class KyberKEM(KeyExchange):
    """Kyber后量子KEM"""
    
    def __init__(self, variant: int = 768, is_server: bool = False):
        """
        Args:
            variant: Kyber变体 (512, 768, 1024)
            is_server: 是否是服务器端
        """
        self.variant = variant
        self.is_server = is_server
        
        # Kyber算法名称映射
        kem_names = {
            512: "Kyber512",
            768: "Kyber768", 
            1024: "Kyber1024",
        }
        
        # 创建KEM实例
        self.kem = oqs.KeyEncapsulation(kem_names[variant])
        
        self._private_key = None
        self._public_key = None
        self._ciphertext = None
    
    def generate_keypair(self) -> None:
        """生成密钥对"""
        if self.is_server:
            # 服务器端：KEM封装时才生成共享密钥
            pass
        else:
            # 客户端：生成KEM密钥对
            self._public_key = self.kem.generate_keypair()
            self._private_key = self.kem.export_secret_key()
    
    def get_public_key(self) -> bytes:
        """获取公钥（或密文）"""
        if self.is_server:
            # 服务器返回密文（伪装成"公钥"）
            if self._ciphertext is None:
                raise ValueError("Server must call compute_shared_secret() first")
            return self._ciphertext
        else:
            # 客户端返回真实公钥
            if self._public_key is None:
                raise ValueError("Client must call generate_keypair() first")
            return self._public_key
    
    def compute_shared_secret(self, peer_data: bytes) -> bytes:
        """计算共享密钥"""
        if self.is_server:
            # 服务器：封装
            return self._kem_encapsulate(peer_data)
        else:
            # 客户端：解封装
            return self._kem_decapsulate(peer_data)
    
    def _kem_encapsulate(self, client_public_key: bytes) -> bytes:
        """KEM封装（服务器端）"""
        self._ciphertext, shared_secret = self.kem.encap_secret(client_public_key)
        return shared_secret
    
    def _kem_decapsulate(self, ciphertext: bytes) -> bytes:
        """KEM解封装（客户端）"""
        shared_secret = self.kem.decap_secret(ciphertext)
        return shared_secret
    
    def get_group(self) -> NamedGroup:
        groups = {
            512: NamedGroup.kyber512,
            768: NamedGroup.kyber768,
            1024: NamedGroup.kyber1024,
        }
        return groups[self.variant]


class FrodoKEM(KeyExchange):
    """FrodoKEM后量子KEM (基于LWE，保守的安全选择)"""
    
    def __init__(self, variant: int = 640, is_server: bool = False):
        """
        Args:
            variant: FrodoKEM变体 (640, 976, 1344)
            is_server: 是否是服务器端
        """
        self.variant = variant
        self.is_server = is_server
        
        # FrodoKEM算法名称映射
        kem_names = {
            640: "FrodoKEM-640-AES",
            976: "FrodoKEM-976-AES", 
            1344: "FrodoKEM-1344-AES",
        }
        
        # 创建KEM实例
        self.kem = oqs.KeyEncapsulation(kem_names[variant])
        
        self._private_key = None
        self._public_key = None
        self._ciphertext = None
    
    def generate_keypair(self) -> None:
        """生成密钥对"""
        if self.is_server:
            # 服务器端：KEM封装时才生成共享密钥
            pass
        else:
            # 客户端：生成KEM密钥对
            self._public_key = self.kem.generate_keypair()
            self._private_key = self.kem.export_secret_key()
    
    def get_public_key(self) -> bytes:
        """获取公钥（或密文）"""
        if self.is_server:
            # 服务器返回密文（伪装成"公钥"）
            if self._ciphertext is None:
                raise ValueError("Server must call compute_shared_secret() first")
            return self._ciphertext
        else:
            # 客户端返回真实公钥
            if self._public_key is None:
                raise ValueError("Client must call generate_keypair() first")
            return self._public_key
    
    def compute_shared_secret(self, peer_data: bytes) -> bytes:
        """计算共享密钥"""
        if self.is_server:
            # 服务器：封装
            return self._kem_encapsulate(peer_data)
        else:
            # 客户端：解封装
            return self._kem_decapsulate(peer_data)
    
    def _kem_encapsulate(self, client_public_key: bytes) -> bytes:
        """KEM封装（服务器端）"""
        self._ciphertext, shared_secret = self.kem.encap_secret(client_public_key)
        return shared_secret
    
    def _kem_decapsulate(self, ciphertext: bytes) -> bytes:
        """KEM解封装（客户端）"""
        shared_secret = self.kem.decap_secret(ciphertext)
        return shared_secret
    
    def get_group(self) -> NamedGroup:
        groups = {
            640: NamedGroup.frodokem640,
            976: NamedGroup.frodokem976,
            1344: NamedGroup.frodokem1344,
        }
        return groups[self.variant]


class NTRUKEM(KeyExchange):
    """NTRU后量子KEM (经典格基密码)"""
    
    def __init__(self, variant: str = "hps2048509", is_server: bool = False):
        """
        Args:
            variant: NTRU变体 (hps2048509, hps2048677, hrss701)
            is_server: 是否是服务器端
        """
        self.variant = variant
        self.is_server = is_server
        
        # NTRU算法名称映射
        kem_names = {
            "hps2048509": "NTRU-HPS-2048-509",
            "hps2048677": "NTRU-HPS-2048-677",
            "hrss701": "NTRU-HRSS-701",
        }
        
        # 创建KEM实例
        self.kem = oqs.KeyEncapsulation(kem_names[variant])
        
        self._private_key = None
        self._public_key = None
        self._ciphertext = None
    
    def generate_keypair(self) -> None:
        """生成密钥对"""
        if self.is_server:
            # 服务器端：KEM封装时才生成共享密钥
            pass
        else:
            # 客户端：生成KEM密钥对
            self._public_key = self.kem.generate_keypair()
            self._private_key = self.kem.export_secret_key()
    
    def get_public_key(self) -> bytes:
        """获取公钥（或密文）"""
        if self.is_server:
            # 服务器返回密文（伪装成"公钥"）
            if self._ciphertext is None:
                raise ValueError("Server must call compute_shared_secret() first")
            return self._ciphertext
        else:
            # 客户端返回真实公钥
            if self._public_key is None:
                raise ValueError("Client must call generate_keypair() first")
            return self._public_key
    
    def compute_shared_secret(self, peer_data: bytes) -> bytes:
        """计算共享密钥"""
        if self.is_server:
            # 服务器：封装
            return self._kem_encapsulate(peer_data)
        else:
            # 客户端：解封装
            return self._kem_decapsulate(peer_data)
    
    def _kem_encapsulate(self, client_public_key: bytes) -> bytes:
        """KEM封装（服务器端）"""
        self._ciphertext, shared_secret = self.kem.encap_secret(client_public_key)
        return shared_secret
    
    def _kem_decapsulate(self, ciphertext: bytes) -> bytes:
        """KEM解封装（客户端）"""
        shared_secret = self.kem.decap_secret(ciphertext)
        return shared_secret
    
    def get_group(self) -> NamedGroup:
        groups = {
            "hps2048509": NamedGroup.ntru_hps2048509,
            "hps2048677": NamedGroup.ntru_hps2048677,
            "hrss701": NamedGroup.ntru_hrss701,
        }
        return groups[self.variant]


class HybridKeyExchange(KeyExchange):
    """混合密钥交换：经典 + 后量子"""
    
    def __init__(self, classical: KeyExchange, pqc: KeyExchange):
        """
        Args:
            classical: 传统密钥交换（如X25519）
            pqc: 后量子密钥交换（如Kyber/HQC）
        """
        self.classical = classical
        self.pqc = pqc
        self._group = self._determine_group()
    
    def _determine_group(self) -> NamedGroup:
        """确定混合组标识"""
        classical_group = self.classical.get_group()
        pqc_group = self.pqc.get_group()
        
        # 映射到混合组
        mapping = {
            # Kyber混合
            (NamedGroup.secp256r1, NamedGroup.kyber512): NamedGroup.p256_kyber512,
            (NamedGroup.secp256r1, NamedGroup.kyber768): NamedGroup.p256_kyber768,
            (NamedGroup.secp384r1, NamedGroup.kyber768): NamedGroup.p384_kyber768,
            (NamedGroup.secp521r1, NamedGroup.kyber1024): NamedGroup.p521_kyber1024,
            # FrodoKEM混合
            (NamedGroup.secp256r1, NamedGroup.frodokem640): NamedGroup.p256_frodokem640,
            (NamedGroup.secp256r1, NamedGroup.frodokem976): NamedGroup.p256_frodokem976,
            (NamedGroup.secp521r1, NamedGroup.frodokem1344): NamedGroup.p521_frodokem1344,
            # NTRU混合
            (NamedGroup.secp256r1, NamedGroup.ntru_hps2048509): NamedGroup.p256_ntru_hps2048509,
            (NamedGroup.secp384r1, NamedGroup.ntru_hps2048677): NamedGroup.p384_ntru_hps2048677,
        }
        
        return mapping.get((classical_group, pqc_group), NamedGroup.p256_kyber768)
    
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
    
    def compute_shared_secret(self, peer_data: bytes) -> bytes:
        """计算组合的共享密钥"""
        # 解析对方的公钥
        classical_len = int.from_bytes(peer_data[:2], 'big')
        classical_pub = peer_data[2:2+classical_len]
        pqc_pub = peer_data[2+classical_len:]
        
        # 分别计算两个共享密钥
        classical_secret = self.classical.compute_shared_secret(classical_pub)
        pqc_secret = self.pqc.compute_shared_secret(pqc_pub)
        
        # 组合两个密钥（使用HKDF或简单串联）
        combined = hashlib.sha256(
            b"hybrid_" + classical_secret + pqc_secret
        ).digest()
        
        return combined
    
    def get_group(self) -> NamedGroup:
        return self._group


def create_key_exchange(group: NamedGroup, is_server: bool = False) -> KeyExchange:
    """创建密钥交换实例
    
    Args:
        group: 密钥交换算法组
        is_server: 是否是服务器端
    
    Returns:
        KeyExchange实例
    """
    # 经典算法
    if group == NamedGroup.x25519:
        return X25519KeyExchange()
    
    elif group == NamedGroup.secp256r1:
        return P256KeyExchange()
    
    # Kyber KEM
    elif group in [NamedGroup.kyber512, NamedGroup.ML_KEM_512]:
        return KyberKEM(variant=512, is_server=is_server)
    
    elif group in [NamedGroup.kyber768, NamedGroup.ML_KEM_768]:
        return KyberKEM(variant=768, is_server=is_server)
    
    elif group in [NamedGroup.kyber1024, NamedGroup.ML_KEM_1024]:
        return KyberKEM(variant=1024, is_server=is_server)
    
    # FrodoKEM
    elif group == NamedGroup.frodokem640:
        return FrodoKEM(variant=640, is_server=is_server)
    
    elif group == NamedGroup.frodokem976:
        return FrodoKEM(variant=976, is_server=is_server)
    
    elif group == NamedGroup.frodokem1344:
        return FrodoKEM(variant=1344, is_server=is_server)
    
    # NTRU KEM
    elif group == NamedGroup.ntru_hps2048509:
        return NTRUKEM(variant="hps2048509", is_server=is_server)
    
    elif group == NamedGroup.ntru_hps2048677:
        return NTRUKEM(variant="hps2048677", is_server=is_server)
    
    elif group == NamedGroup.ntru_hrss701:
        return NTRUKEM(variant="hrss701", is_server=is_server)
    
    # Kyber混合
    elif group == NamedGroup.p256_kyber512:
        return HybridKeyExchange(
            P256KeyExchange(),
            KyberKEM(variant=512, is_server=is_server)
        )
    
    elif group in [NamedGroup.p256_kyber768, NamedGroup.p384_kyber768]:
        return HybridKeyExchange(
            P256KeyExchange(),
            KyberKEM(variant=768, is_server=is_server)
        )
    
    elif group == NamedGroup.p521_kyber1024:
        return HybridKeyExchange(
            P256KeyExchange(),
            KyberKEM(variant=1024, is_server=is_server)
        )
    
    # FrodoKEM混合
    elif group == NamedGroup.p256_frodokem640:
        return HybridKeyExchange(
            P256KeyExchange(),
            FrodoKEM(variant=640, is_server=is_server)
        )
    
    elif group == NamedGroup.p256_frodokem976:
        return HybridKeyExchange(
            P256KeyExchange(),
            FrodoKEM(variant=976, is_server=is_server)
        )
    
    elif group == NamedGroup.p521_frodokem1344:
        return HybridKeyExchange(
            P256KeyExchange(),
            FrodoKEM(variant=1344, is_server=is_server)
        )
    
    # NTRU混合
    elif group == NamedGroup.p256_ntru_hps2048509:
        return HybridKeyExchange(
            P256KeyExchange(),
            NTRUKEM(variant="hps2048509", is_server=is_server)
        )
    
    elif group == NamedGroup.p384_ntru_hps2048677:
        return HybridKeyExchange(
            P256KeyExchange(),
            NTRUKEM(variant="hps2048677", is_server=is_server)
        )
    
    else:
        raise ValueError(f"Unsupported group: {group}")


def test_key_exchange():
    """测试密钥交换"""
    print("🧪 测试密钥交换模块\n")
    
    groups_to_test = [
        # 经典算法
        NamedGroup.x25519,
        NamedGroup.secp256r1,
        # Kyber KEM
        NamedGroup.kyber512,
        NamedGroup.kyber768,
        # FrodoKEM
        NamedGroup.frodokem640,
        NamedGroup.frodokem976,
        # NTRU KEM
        NamedGroup.ntru_hps2048509,
        # Kyber混合
        NamedGroup.p256_kyber768,
        # FrodoKEM混合
        NamedGroup.p256_frodokem640,
        # NTRU混合
        NamedGroup.p256_ntru_hps2048509,
    ]
    
    for group in groups_to_test:
        from core.types import get_group_name
        print(f"测试: {get_group_name(group)}")
        
        try:
            # 客户端
            client_kex = create_key_exchange(group, is_server=False)
            client_kex.generate_keypair()
            client_public = client_kex.get_public_key()
            print(f"  ✓ 客户端公钥: {len(client_public)}字节")
            
            # 服务器
            server_kex = create_key_exchange(group, is_server=True)
            server_kex.generate_keypair()
            server_shared = server_kex.compute_shared_secret(client_public)
            server_public = server_kex.get_public_key()
            print(f"  ✓ 服务器响应: {len(server_public)}字节")
            
            # 客户端计算共享密钥
            client_shared = client_kex.compute_shared_secret(server_public)
            
            # 验证
            if client_shared == server_shared:
                print(f"  [OK] 共享密钥一致: {client_shared[:16].hex()}...")
            else:
                print(f"  ❌ 共享密钥不匹配!")
        except Exception as e:
            print(f"  ❌ 测试失败: {e}")
        
        print()


if __name__ == '__main__':
    test_key_exchange()

