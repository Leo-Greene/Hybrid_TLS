from typing import Dict, Callable, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

# 导入signature.py中的签名功能
import sys
from pathlib import Path

# 添加项目根目录到路径，支持导入signature模块
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

# 添加core.crypto目录到路径
crypto_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(crypto_dir))


# 导入真实的签名类
try:
    from core.crypto.signature import (
        DilithiumSignature, FalconSignature, 
        ECDSASignature, RSAPSSSignature
    )
except ImportError as e:
    # 尝试其他可能的导入路径
    try:
        from signature import (
            DilithiumSignature, FalconSignature, 
            ECDSASignature, RSAPSSSignature
        )
    except ImportError as e2:
        raise

# 在algorithms.py中直接定义SignatureScheme枚举，避免导入路径问题
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

# 添加enhanced_certificate目录到路径，支持导入本地模块
enhanced_certificate_dir = Path(__file__).parent.parent
sys.path.insert(0, str(enhanced_certificate_dir))

# 导入本地模块（使用绝对导入）
from models.certificates import AlgorithmType, SecurityLevel
from exceptions import AlgorithmNotSupportedError

class AlgorithmRegistry:
    """算法注册器 - 支持经典和后量子算法"""
    
    # ML-DSA OIDs (基于IETF草案)
    ML_DSA_OIDS = {
        "1.3.6.1.4.1.2.267.12.4.4": ("ML-DSA-44", SecurityLevel.LEVEL_2),
        "1.3.6.1.4.1.2.267.12.5.5": ("ML-DSA-65", SecurityLevel.LEVEL_3),
        "1.3.6.1.4.1.2.267.12.6.6": ("ML-DSA-87", SecurityLevel.LEVEL_5),
    }
    
    # Falcon OIDs
    FALCON_OIDS = {
        "1.3.6.1.4.1.2.267.12.7.7": ("Falcon-512", SecurityLevel.LEVEL_2),
        "1.3.6.1.4.1.2.267.12.8.8": ("Falcon-1024", SecurityLevel.LEVEL_5),
    }
    
    # 经典算法 OIDs
    CLASSIC_OIDS = {
        "1.2.840.113549.1.1.11": ("RSASSA-PSS", SecurityLevel.LEVEL_1),
        "1.2.840.113549.1.1.12": ("RSA-SHA256", SecurityLevel.LEVEL_1),
        "1.2.840.10045.4.3.2": ("ECDSA-SHA256", SecurityLevel.LEVEL_1),
    }
    
    # 算法名称到SignatureScheme的映射
    ALGORITHM_TO_SCHEME = {
        "ML-DSA-44": SignatureScheme.ML_DSA_44,
        "ML-DSA-65": SignatureScheme.ML_DSA_65,
        "ML-DSA-87": SignatureScheme.ML_DSA_87,
        "Falcon-512": SignatureScheme.falcon512,
        "Falcon-1024": SignatureScheme.falcon1024,
        "RSASSA-PSS": SignatureScheme.rsa_pss_rsae_sha256,
        "RSA-SHA256": SignatureScheme.rsa_pss_rsae_sha256,  # 使用RSA-PSS作为RSA-SHA256的替代
        "ECDSA-SHA256": SignatureScheme.ecdsa_secp256r1_sha256,
    }
    
    def __init__(self):
        self._verifiers: Dict[str, Callable] = {}
        self._setup_verifiers()
    
    def _setup_verifiers(self):
        """注册验证器"""
        # 使用统一的签名验证方法，基于signature.py中的实现
        self._verifiers.update({
            "ML-DSA-44": self._verify_signature_unified,
            "ML-DSA-65": self._verify_signature_unified, 
            "ML-DSA-87": self._verify_signature_unified,
            "Falcon-512": self._verify_signature_unified,
            "Falcon-1024": self._verify_signature_unified,
            "RSASSA-PSS": self._verify_signature_unified,
            "ECDSA-SHA256": self._verify_signature_unified,
            "ECDSA-SHA384": self._verify_signature_unified,  # 添加P-384支持
            "ECDSA-SHA512": self._verify_signature_unified,  # 添加P-521支持
        })
    
    def get_algorithm_info(self, oid: str) -> tuple:
        """根据OID获取算法信息"""
        if oid in self.ML_DSA_OIDS:
            return self.ML_DSA_OIDS[oid], AlgorithmType.POST_QUANTUM
        elif oid in self.FALCON_OIDS:
            return self.FALCON_OIDS[oid], AlgorithmType.POST_QUANTUM
        elif oid in self.CLASSIC_OIDS:
            return self.CLASSIC_OIDS[oid], AlgorithmType.CLASSIC
        else:
            raise AlgorithmNotSupportedError(f"Unknown algorithm OID: {oid}")
    
    def verify_signature(self, algorithm: str, message: bytes, 
                        signature: bytes, public_key: bytes) -> bool:
        """验证签名"""
        if algorithm not in self._verifiers:
            raise AlgorithmNotSupportedError(f"Unsupported algorithm: {algorithm}")
        
        verifier = self._verifiers[algorithm]
        return verifier(algorithm, message, signature, public_key)
    
    def _verify_signature_unified(self, algorithm: str, message: bytes, 
                                 signature: bytes, public_key: bytes) -> bool:
        """统一的签名验证方法，使用真实的签名实现"""
        try:
            # 参数有效性检查
            if not message or not signature or not public_key:
                return False
            
            # 根据算法名称创建对应的签名实例
            if algorithm == "ML-DSA-44":
                signer = DilithiumSignature(variant=2)
            elif algorithm == "ML-DSA-65":
                signer = DilithiumSignature(variant=3)
            elif algorithm == "ML-DSA-87":
                signer = DilithiumSignature(variant=5)
            elif algorithm == "Falcon-512":
                signer = FalconSignature(variant=512)
            elif algorithm == "Falcon-1024":
                signer = FalconSignature(variant=1024)
            elif algorithm in ["ECDSA-SHA256", "ECDSA-SHA384", "ECDSA-SHA512"]:
                # ECDSA签名验证（所有曲线使用同一个ECDSASignature类）
                signer = ECDSASignature()
            elif algorithm == "RSASSA-PSS":
                signer = RSAPSSSignature()
            else:
                raise AlgorithmNotSupportedError(f"Unsupported algorithm: {algorithm}")
            
            # 使用签名实例进行验证
            return signer.verify(message, signature, public_key)
            
        except Exception as e:
            return False
        