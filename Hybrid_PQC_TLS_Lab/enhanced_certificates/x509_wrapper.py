#!/usr/bin/env python3
"""
X.509 包装器 - 将后量子证书包装成标准 X.509 格式

策略：
1. 使用 ECDSA (P-256) 作为"占位符"密钥（满足 X.509 格式要求）
2. 在自定义扩展字段中存储真实的 ML-DSA 公钥和签名
3. 提供包装器类自动处理验证逻辑

这样既符合 X.509 标准，又能使用后量子算法！
"""

import os
import sys
from pathlib import Path
from typing import Optional, Tuple
import datetime
import json

# 添加项目路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# 配置 liboqs
def setup_liboqs():
    if sys.platform == 'win32':
        possible_paths = [
            r"D:\Tools\lib\liboqs\build\bin\Release",
            r"C:\Program Files\liboqs\bin",
            r"C:\liboqs\bin",
        ]
        for dll_path in possible_paths:
            if os.path.exists(dll_path):
                dll_file = os.path.join(dll_path, "oqs.dll")
                if os.path.exists(dll_file):
                    if dll_path not in os.environ.get('PATH', ''):
                        os.environ['PATH'] = dll_path + os.pathsep + os.environ.get('PATH', '')
                    if hasattr(os, 'add_dll_directory'):
                        try:
                            os.add_dll_directory(dll_path)
                        except Exception:
                            pass
                    break

setup_liboqs()

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtensionOID

import oqs

# 自定义 OID（用于 ML-DSA 扩展）
PQ_PUBLIC_KEY_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1")  # 实验性 OID
PQ_SIGNATURE_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.2")   # 实验性 OID
PQ_ALGORITHM_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.3")   # 实验性 OID


class X509PQWrapper:
    """
    X.509 后量子包装器
    
    创建符合 X.509 标准的证书，同时在扩展字段中携带后量子信息
    """
    
    def __init__(self, pq_algorithm: str = "ML-DSA-65"):
        """
        初始化包装器
        
        Args:
            pq_algorithm: 后量子算法名称（ML-DSA-44/65/87）
        """
        self.pq_algorithm = pq_algorithm
        self.pq_signer = oqs.Signature(pq_algorithm)
        
        # 生成占位符 ECDSA 密钥（用于 X.509 格式）
        self.placeholder_private_key = ec.generate_private_key(
            ec.SECP256R1(), 
            default_backend()
        )
        self.placeholder_public_key = self.placeholder_private_key.public_key()
        
        # 后量子密钥对
        self.pq_public_key = None
        self.pq_private_key = None
    
    def generate_keypair(self):
        """生成后量子密钥对"""
        self.pq_public_key = self.pq_signer.generate_keypair()
        self.pq_private_key = self.pq_signer.export_secret_key()
        return self.pq_public_key
    
    def create_certificate(
        self,
        subject_name: str,
        issuer_name: str,
        issuer_wrapper: Optional['X509PQWrapper'] = None,
        is_ca: bool = False,
        path_length: Optional[int] = None,
        validity_days: int = 365
    ) -> x509.Certificate:
        """
        创建包装的 X.509 证书
        
        Args:
            subject_name: 主题名称
            issuer_name: 颁发者名称
            issuer_wrapper: 颁发者的包装器（用于签名，None 表示自签名）
            is_ca: 是否是 CA 证书
            path_length: CA 路径长度限制
            validity_days: 有效期（天）
        
        Returns:
            标准 X.509 证书对象
        """
        # 解析名称
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        ])
        
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, issuer_name),
        ])
        
        # 构建证书
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.public_key(self.placeholder_public_key)  # 占位符公钥
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.datetime.utcnow())
        builder = builder.not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=validity_days)
        )
        
        # 添加基本约束
        builder = builder.add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=path_length),
            critical=True
        )
        
        # ⭐ 关键：在扩展字段中存储后量子信息
        pq_metadata = {
            "algorithm": self.pq_algorithm,
            "public_key": self.pq_public_key.hex(),
            "key_size": len(self.pq_public_key),
            "format_version": "1.0"
        }
        
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                oid=PQ_PUBLIC_KEY_OID,
                value=json.dumps(pq_metadata).encode('utf-8')
            ),
            critical=False  # 非关键扩展，不影响传统验证
        )
        
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                oid=PQ_ALGORITHM_OID,
                value=self.pq_algorithm.encode('utf-8')
            ),
            critical=False
        )
        
        # 签名证书
        if issuer_wrapper is None:
            # 自签名：使用占位符密钥签名（传统部分）
            certificate = builder.sign(
                private_key=self.placeholder_private_key,
                algorithm=hashes.SHA256(),
                backend=default_backend()
            )
        else:
            # 由颁发者签名
            certificate = builder.sign(
                private_key=issuer_wrapper.placeholder_private_key,
                algorithm=hashes.SHA256(),
                backend=default_backend()
            )
        
        # 添加后量子签名作为额外扩展
        # 注意：这需要重新构建证书，因为要对整个证书进行 PQ 签名
        certificate = self._add_pq_signature(certificate, issuer_wrapper or self)
        
        return certificate
    
    def _add_pq_signature(
        self, 
        certificate: x509.Certificate, 
        signer_wrapper: 'X509PQWrapper'
    ) -> x509.Certificate:
        """
        为证书添加后量子签名
        
        策略：对证书的 TBS（To Be Signed）部分进行 ML-DSA 签名
        符合X.509标准：签名对象是TBS证书数据
        """
        # ⭐ 获取证书的 TBS（To Be Signed）部分
        # 这是X.509标准的签名对象
        tbs_certificate_bytes = certificate.tbs_certificate_bytes
        
        # 使用 ML-DSA 对 TBS 部分签名
        pq_signature = signer_wrapper.pq_signer.sign(tbs_certificate_bytes)
        
        # 重新构建证书，添加签名扩展
        # 注意：这里我们需要重新构建，因为不能修改已有证书
        # 为了简化，我们将签名信息存储在文件系统或返回元组
        
        # 将签名附加到证书对象（作为属性）
        # X.509 Certificate 是不可变的，所以我们用包装对象
        # ⭐ 关键修复：使用签名者的算法，而不是证书持有者的算法
        wrapped_cert = PQWrappedCertificate(certificate, pq_signature, signer_wrapper.pq_algorithm)
        
        return wrapped_cert


class PQWrappedCertificate:
    """
    包装的后量子证书
    
    包含：
    1. 标准 X.509 证书（可以用传统工具处理）
    2. 后量子签名（用于真实的安全验证）
    """
    
    def __init__(
        self, 
        x509_cert: x509.Certificate, 
        pq_signature: bytes,
        signature_algorithm: str  # 签名使用的算法（颁发者的算法）
    ):
        self.x509_cert = x509_cert
        self.pq_signature = pq_signature
        self.signature_algorithm = signature_algorithm  # 签名算法
        
        # 从证书扩展中提取证书持有者的PQ算法
        try:
            ext = x509_cert.extensions.get_extension_for_oid(PQ_ALGORITHM_OID)
            self.pq_algorithm = ext.value.value.decode('utf-8')  # 证书持有者的算法
        except:
            # 如果无法提取，使用签名算法作为后备
            self.pq_algorithm = signature_algorithm
    
    def get_x509_certificate(self) -> x509.Certificate:
        """获取标准 X.509 证书"""
        return self.x509_cert
    
    def get_pq_signature(self) -> bytes:
        """获取后量子签名"""
        return self.pq_signature
    
    def get_pq_public_key(self) -> bytes:
        """从扩展字段中提取后量子公钥"""
        try:
            # 读取自定义扩展
            ext = self.x509_cert.extensions.get_extension_for_oid(PQ_PUBLIC_KEY_OID)
            metadata = json.loads(ext.value.value.decode('utf-8'))
            return bytes.fromhex(metadata['public_key'])
        except Exception as e:
            raise ValueError(f"无法提取后量子公钥: {e}")
    
    def save_pem(self, cert_path: str, sig_path: Optional[str] = None):
        """
        保存为 PEM 格式
        
        Args:
            cert_path: 证书文件路径
            sig_path: 签名文件路径（可选，不提供则附加到证书文件）
        """
        # 保存 X.509 证书
        pem_data = self.x509_cert.public_bytes(serialization.Encoding.PEM)
        
        with open(cert_path, 'wb') as f:
            f.write(pem_data)
            
            # 如果不单独保存签名，则附加到证书文件
            if sig_path is None:
                f.write(b"\n# PQ Signature (ML-DSA)\n")
                f.write(b"# Algorithm: " + self.pq_algorithm.encode() + b"\n")
                f.write(b"# Signature: " + self.pq_signature.hex().encode() + b"\n")
        
        # 单独保存签名
        if sig_path:
            sig_data = {
                "algorithm": self.signature_algorithm,  # ⭐ 使用签名算法（签名者的算法）
                "signature": self.pq_signature.hex()
            }
            with open(sig_path, 'w') as f:
                json.dump(sig_data, f, indent=2)
    
    def save_der(self, cert_path: str, sig_path: str):
        """
        保存为 DER 格式（二进制）
        
        Args:
            cert_path: 证书文件路径
            sig_path: 签名文件路径
        """
        # 保存 X.509 证书
        der_data = self.x509_cert.public_bytes(serialization.Encoding.DER)
        with open(cert_path, 'wb') as f:
            f.write(der_data)
        
        # 保存签名
        sig_data = {
            "algorithm": self.pq_algorithm,
            "signature": self.pq_signature.hex()
        }
        with open(sig_path, 'w') as f:
            json.dump(sig_data, f, indent=2)
    
    @staticmethod
    def load_pem(cert_path: str, sig_path: Optional[str] = None) -> 'PQWrappedCertificate':
        """
        从 PEM 文件加载
        
        Args:
            cert_path: 证书文件路径
            sig_path: 签名文件路径（可选）
        """
        # 读取证书
        with open(cert_path, 'rb') as f:
            cert_pem = f.read()
        
        # 分离 X.509 部分和签名注释
        lines = cert_pem.decode().split('\n')
        cert_lines = []
        pq_signature = None
        pq_algorithm = None
        
        for line in lines:
            if line.startswith('# Algorithm:'):
                pq_algorithm = line.split(':', 1)[1].strip()
            elif line.startswith('# Signature:'):
                pq_signature = bytes.fromhex(line.split(':', 1)[1].strip())
            elif not line.startswith('#'):
                cert_lines.append(line)
        
        cert_pem_clean = '\n'.join(cert_lines).encode()
        cert = x509.load_pem_x509_certificate(cert_pem_clean, default_backend())
        
        # 如果有单独的签名文件，优先使用
        if sig_path and os.path.exists(sig_path):
            with open(sig_path, 'r') as f:
                sig_data = json.load(f)
                pq_algorithm = sig_data['algorithm']
                pq_signature = bytes.fromhex(sig_data['signature'])
        
        if not pq_signature or not pq_algorithm:
            raise ValueError("缺少后量子签名信息")
        
        return PQWrappedCertificate(cert, pq_signature, pq_algorithm)
    
    def verify(self, issuer_public_key: bytes, issuer_algorithm: str) -> bool:
        """
        验证证书（后量子签名）
        
        Args:
            issuer_public_key: 颁发者的后量子公钥
            issuer_algorithm: 颁发者的算法（用于验证）
        
        Returns:
            签名是否有效
        """
        # 获取证书的 DER 编码
        cert_der = self.x509_cert.public_bytes(serialization.Encoding.DER)
        
        # 验证后量子签名（使用颁发者的算法）
        verifier = oqs.Signature(issuer_algorithm)
        is_valid = verifier.verify(cert_der, self.pq_signature, issuer_public_key)
        
        return is_valid


def demo_wrapper():
    """演示包装器的使用"""
    print("=" * 70)
    print("X.509 后量子包装器演示")
    print("=" * 70)
    
    # 创建证书目录
    os.makedirs("enhanced_certificates/x509_wrapped", exist_ok=True)
    
    # 1. 创建根 CA
    print("\n[1] 创建根 CA（ML-DSA-87）")
    root_wrapper = X509PQWrapper("ML-DSA-87")
    root_wrapper.generate_keypair()
    
    root_cert = root_wrapper.create_certificate(
        subject_name="Post-Quantum Root CA",
        issuer_name="Post-Quantum Root CA",  # 自签名
        issuer_wrapper=None,
        is_ca=True,
        path_length=2,
        validity_days=3650
    )
    
    print(f"[OK] 根 CA 创建完成")
    print(f"   X.509 主题: {root_cert.x509_cert.subject}")
    print(f"   PQ 算法: {root_cert.pq_algorithm}")
    print(f"   PQ 公钥大小: {len(root_cert.get_pq_public_key())} 字节")
    
    # 保存根证书
    root_cert.save_pem(
        "enhanced_certificates/x509_wrapped/root_ca.pem",
        "enhanced_certificates/x509_wrapped/root_ca_pq.sig"
    )
    print(f"   已保存: root_ca.pem")
    
    # 2. 创建中间 CA
    print("\n[2] 创建中间 CA（ML-DSA-65）")
    intermediate_wrapper = X509PQWrapper("ML-DSA-65")
    intermediate_wrapper.generate_keypair()
    
    intermediate_cert = intermediate_wrapper.create_certificate(
        subject_name="PQ Intermediate CA",
        issuer_name="Post-Quantum Root CA",
        issuer_wrapper=root_wrapper,
        is_ca=True,
        path_length=1,
        validity_days=1825
    )
    
    print(f"[OK] 中间 CA 创建完成")
    print(f"   X.509 颁发者: {intermediate_cert.x509_cert.issuer}")
    
    intermediate_cert.save_pem(
        "enhanced_certificates/x509_wrapped/intermediate_ca.pem",
        "enhanced_certificates/x509_wrapped/intermediate_ca_pq.sig"
    )
    print(f"   已保存: intermediate_ca.pem")
    
    # 3. 创建服务器证书
    print("\n[3] 创建服务器证书（ML-DSA-44）")
    server_wrapper = X509PQWrapper("ML-DSA-44")
    server_wrapper.generate_keypair()
    
    server_cert = server_wrapper.create_certificate(
        subject_name="server.example.com",
        issuer_name="PQ Intermediate CA",
        issuer_wrapper=intermediate_wrapper,
        is_ca=False,
        validity_days=365
    )
    
    print(f"[OK] 服务器证书创建完成")
    
    server_cert.save_pem(
        "enhanced_certificates/x509_wrapped/server.pem",
        "enhanced_certificates/x509_wrapped/server_pq.sig"
    )
    print(f"   已保存: server.pem")
    
    # 4. 验证证书
    print("\n[4] 验证证书链")
    
    # 验证中间证书（由根 CA 签名）
    intermediate_valid = intermediate_cert.verify(
        root_wrapper.pq_public_key,
        root_wrapper.pq_algorithm
    )
    print(f"   中间证书验证: {'[OK] 通过' if intermediate_valid else '[ERROR] 失败'}")
    
    # 验证服务器证书（由中间 CA 签名）
    server_valid = server_cert.verify(
        intermediate_wrapper.pq_public_key,
        intermediate_wrapper.pq_algorithm
    )
    print(f"   服务器证书验证: {'[OK] 通过' if server_valid else '[ERROR] 失败'}")
    
    # 5. 演示使用标准工具查看
    print("\n[5] 使用标准工具查看证书")
    print("   可以使用以下命令查看证书（标准 X.509 部分）:")
    print("   $ openssl x509 -in enhanced_certificates/x509_wrapped/server.pem -text -noout")
    print("\n   证书同时包含:")
    print("   - [OK] 标准 X.509 结构（ECDSA 占位符）")
    print("   - [OK] 后量子公钥（在自定义扩展中）")
    print("   - [OK] 后量子签名（在注释或单独文件中）")
    
    print("\n" + "=" * 70)
    print("演示完成！证书已保存到 enhanced_certificates/x509_wrapped/")
    print("=" * 70)


if __name__ == "__main__":
    demo_wrapper()

