"""
证书颁发机构 - 实现完整的证书签发流程
"""

import datetime
import sys
from pathlib import Path
from typing import List, Dict, Any

# 将项目根目录添加到路径
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

# 导入本地模块（使用绝对导入）
from core.crypto.enhanced_certificate.crypto.signer import CertificateSigner, MLDSASigner, FalconSigner, ClassicSigner
from core.crypto.enhanced_certificate.models.certificates import CertificateInfo, AlgorithmType, SecurityLevel
from core.crypto.enhanced_certificate.exceptions import PQSignatureError

class CertificateAuthority:
    """证书颁发机构 - 支持签发各级证书"""
    
    def __init__(self, name: str, signer: CertificateSigner, is_root: bool = False):
        self.name = name
        self.signer = signer
        self.is_root = is_root
        self.private_key, self.public_key = signer.generate_keypair()
        print(f"    生成的公钥: {self.public_key.hex()}")
        self.issued_certificates: List[CertificateInfo] = []
    
    def create_self_signed_certificate(self) -> CertificateInfo:
        """创建自签名根证书"""
        if not self.is_root:
            raise ValueError("Only root CA can create self-signed certificates")
        
        # 构建证书数据
        tbs_data = self._build_tbs_certificate(
            subject=self.name,
            issuer=self.name,  # 自签名
            public_key=self.public_key,
            is_ca=True,
            path_length_constraint=2  # 允许2级中间CA
        )
        
        # 使用自己的私钥签名
        signature, _ = self.signer.sign_certificate(tbs_data, self.private_key)
        
        # 确定算法类型和安全等级
        algo_type, security_level = self._get_algorithm_info()
        
        certificate = CertificateInfo(
            subject=self.name,
            issuer=self.name,
            public_key=self.public_key,
            signature_algorithm=self._get_algorithm_name(),
            signature=signature,
            tbs_certificate=tbs_data,
            algorithm_type=algo_type,
            security_level=security_level,
            is_ca=True,
            path_length_constraint=2
        )
        
        self.issued_certificates.append(certificate)
        return certificate
    
    def issue_certificate(self, 
                         subject_name: str,
                         public_key: bytes,
                         is_ca: bool = False,
                         path_length_constraint: int = None,
                         certificate_signer: CertificateSigner = None) -> CertificateInfo:
        """签发下级证书
        
        参数:
            subject_name: 证书主题名称
            public_key: 证书公钥
            is_ca: 是否为CA证书
            path_length_constraint: 路径长度约束
            certificate_signer: 被签发证书的签名器（用于确定算法信息）
        """
        # 只有CA才能签发证书（根CA或中间CA）
        if not self.is_root and not self._is_ca():
            raise ValueError("Only CA can issue certificates")
        
        # 构建证书数据
        tbs_data = self._build_tbs_certificate(
            subject=subject_name,
            issuer=self.name,
            public_key=public_key,
            is_ca=is_ca,
            path_length_constraint=path_length_constraint
        )
        
        # 使用CA私钥签名
        signature, _ = self.signer.sign_certificate(tbs_data, self.private_key)
        
        # 确定算法类型和安全等级
        # 签名算法应该使用签发者（CA）的算法，因为签名是由CA生成的
        # 被签发证书的算法信息仅用于标识证书本身的算法特性
        signature_algorithm = self._get_algorithm_name()
        
        # 如果提供了certificate_signer，使用被签发证书的算法信息
        # 否则使用签发者（CA）的算法信息
        if certificate_signer is not None:
            algo_type, security_level = self._get_algorithm_info_from_signer(certificate_signer)
        else:
            algo_type, security_level = self._get_algorithm_info()
        
        certificate = CertificateInfo(
            subject=subject_name,
            issuer=self.name,
            public_key=public_key,
            signature_algorithm=signature_algorithm,  # 使用签发者的算法
            signature=signature,
            tbs_certificate=tbs_data,
            algorithm_type=algo_type,
            security_level=security_level,
            is_ca=is_ca,
            path_length_constraint=path_length_constraint
        )
        
        self.issued_certificates.append(certificate)
        return certificate
    
    def _build_tbs_certificate(self, 
                             subject: str, 
                             issuer: str,
                             public_key: bytes,
                             is_ca: bool,
                             path_length_constraint: int = None) -> bytes:
        """构建待签名证书数据（模拟）"""
        # 在实际实现中，这里应该构建符合X.509标准的TBS证书数据
        cert_data = {
            "version": "v3",
            "serial_number": "1234567890",
            "signature_algorithm": self._get_algorithm_name(),
            "issuer": issuer,
            "validity": {
                "not_before": "20240101000000Z",
                "not_after": "20251231235959Z"
            },
            "subject": subject,
            "subject_public_key_info": {
                "algorithm": "PUBLIC_KEY",
                "public_key": public_key.hex()[:100] + "..."
            },
            "extensions": {
                "basic_constraints": {
                    "ca": is_ca,
                    "path_length_constraint": path_length_constraint
                },
                "key_usage": ["digitalSignature", "keyCertSign"] if is_ca else ["digitalSignature"]
            }
        }
        
        # 转换为字节（模拟）
        return f"TBS_CERTIFICATE_{subject}_{issuer}".encode()
    
    def _get_algorithm_name(self) -> str:
        """获取算法名称"""
        if isinstance(self.signer, MLDSASigner):
            return self.signer.variant
        elif isinstance(self.signer, FalconSigner):
            return self.signer.variant
        elif isinstance(self.signer, ClassicSigner):
            return self.signer.algorithm
        else:
            return "UNKNOWN"
    
    def _is_ca(self) -> bool:
        """判断当前CA是否具有签发证书的权限"""
        # 如果是根CA，直接具有签发权限
        if self.is_root:
            return True
        
        # 如果是中间CA，检查是否被授权签发证书
        # 在实际实现中，这里应该检查证书的基本约束扩展
        # 这里简化处理：中间CA默认具有签发叶子证书的权限
        return True
    
    def _get_algorithm_info(self) -> tuple:
        """获取算法类型和安全等级"""
        algorithm_name = self._get_algorithm_name()
        
        if algorithm_name.startswith("ML-DSA"):
            # 根据用户要求调整安全级别映射
            level_map = {"ML-DSA-44": 1, "ML-DSA-65": 3, "ML-DSA-87": 5}  # ML-DSA-44映射到LEVEL_1
            security_level = SecurityLevel(level_map.get(algorithm_name, 1))
            return AlgorithmType.POST_QUANTUM, security_level
            
        elif algorithm_name.startswith("Falcon"):
            level_map = {"Falcon-512": 2, "Falcon-1024": 5}
            security_level = SecurityLevel(level_map.get(algorithm_name, 2))
            return AlgorithmType.POST_QUANTUM, security_level
            
        else:  # 经典算法
            return AlgorithmType.CLASSIC, SecurityLevel.LEVEL_1
    
    def _get_algorithm_info_from_signer(self, signer: CertificateSigner) -> tuple:
        """从指定的签名器获取算法类型和安全等级"""
        if isinstance(signer, MLDSASigner):
            algorithm_name = signer.variant
            level_map = {"ML-DSA-44": 1, "ML-DSA-65": 3, "ML-DSA-87": 5}
            security_level = SecurityLevel(level_map.get(algorithm_name, 1))
            return AlgorithmType.POST_QUANTUM, security_level
            
        elif isinstance(signer, FalconSigner):
            algorithm_name = signer.variant
            level_map = {"Falcon-512": 2, "Falcon-1024": 5}
            security_level = SecurityLevel(level_map.get(algorithm_name, 2))
            return AlgorithmType.POST_QUANTUM, security_level
            
        elif isinstance(signer, ClassicSigner):
            return AlgorithmType.CLASSIC, SecurityLevel.LEVEL_1
            
        else:
            return AlgorithmType.CLASSIC, SecurityLevel.LEVEL_1
    
    def _get_algorithm_name_from_signer(self, signer: CertificateSigner) -> str:
        """从指定的签名器获取算法名称"""
        if isinstance(signer, MLDSASigner):
            return signer.variant
        elif isinstance(signer, FalconSigner):
            return signer.variant
        elif isinstance(signer, ClassicSigner):
            return signer.algorithm
        else:
            return "UNKNOWN"