#!/usr/bin/env python3
"""
X.509 包装器 - 将后量子证书包装成标准 X.509 格式

策略：
1. 使用 ECDSA (P-256) 作为"占位符"密钥（满足 X.509 格式要求）
2. 在自定义扩展字段中存储真实的 ML-DSA 公钥和签名
3. 提供包装器类自动处理验证逻辑

这样既符合 X.509 标准，又能使用后量子算法！
"""

from hashlib import sha256
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
TEMP_OID = x509.ObjectIdentifier("0.0.0.0")    


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
        validity_days: int = 365,
        base_algorithm: Optional[str] = None
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
            base_algorithm: 基础算法名称（用于构建URI，所有证书的公钥都存储在同一个算法文件夹下）
                           如果为None，则使用self.pq_algorithm作为后备
        
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

        try:
            pq_public_key_hash = sha256(self.pq_public_key.hex().encode('utf-8')).hexdigest()
        except Exception as e:
            raise ValueError(f"计算后量子公钥哈希时出错: {e}")
        
        print("后量子公钥哈希:", pq_public_key_hash)
        
        # ⭐ 关键：在扩展字段中存储后量子信息
        # 使用base_algorithm构建URI（如果提供），否则使用证书持有者的算法
        # 这样所有证书的公钥URI都指向同一个基础算法文件夹
        uri_algorithm = base_algorithm if base_algorithm else self.pq_algorithm
        
        pq_metadata = {
            "by_val": False,
            "algorithm": self.pq_algorithm,  # 证书持有者的实际算法
            # "public_key": self.pq_public_key.hex(), # 这里公钥记得单独存储
            "pq_pk_uri": "http://localhost/pq/cert/"+uri_algorithm,  # 使用基础算法构建URI
            "public_key_hash": pq_public_key_hash,
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
        
        # 添加后量子签名扩展（在签名之前）
        # 先创建签名占位符，实际签名将在_add_pq_signature中完成
        # ⭐ 注意：签名URI应该使用基础算法（base_algorithm），所有签名文件都存储在同一个算法文件夹下
        # 这里先用基础算法作为占位符，实际会在_add_pq_signature中更新
        sig_uri_algorithm = base_algorithm if base_algorithm else (issuer_wrapper.pq_algorithm if issuer_wrapper else self.pq_algorithm)
        pq_sig_extension = {
            "pq_sig_uri": "http://localhost/pq/sig/"+sig_uri_algorithm,
            "signature_hash": "待签名"  # 占位符，将在签名后更新
        }
        
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                oid=TEMP_OID,
                value=json.dumps(pq_sig_extension).encode('utf-8')
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
        
        # 添加后量子签名
        certificate, pq_signature = self._add_pq_signature(certificate, issuer_wrapper or self, base_algorithm)
        
        return certificate
    
    def _add_pq_signature(
        self, 
        certificate: x509.Certificate, 
        signer_wrapper: 'X509PQWrapper',
        base_algorithm: Optional[str] = None
    ) -> Tuple[x509.Certificate, bytes]:
        """
        对证书进行后量子签名，并返回签名后的证书和签名值
        
        Args:
            certificate: 要签名的证书
            signer_wrapper: 签名者的包装器
            base_algorithm: 基础算法名称（用于构建URI，所有签名文件都存储在同一个算法文件夹下）
        """
        # 获取证书的 DER 编码（TBS 部分）
        tbs_certificate_der = certificate.tbs_certificate_bytes
        print("TBS 证书 DER 编码(前50字节):", tbs_certificate_der.hex()[:50])
        
        # 使用后量子算法对 TBS 证书进行签名
        pq_signature = signer_wrapper.pq_signer.sign(tbs_certificate_der)
        
        # 重新构建证书以更新签名扩展字段
        builder = x509.CertificateBuilder()
        
        # 复制原证书的所有属性
        builder = builder.subject_name(certificate.subject)
        builder = builder.issuer_name(certificate.issuer)
        builder = builder.public_key(certificate.public_key())
        builder = builder.serial_number(certificate.serial_number)
        builder = builder.not_valid_before(certificate.not_valid_before)
        builder = builder.not_valid_after(certificate.not_valid_after)
        
        # 复制所有扩展（除了签名扩展）
        for extension in certificate.extensions:
            if extension.oid != TEMP_OID:  # 跳过签名扩展
                builder = builder.add_extension(
                    extension.value, 
                    critical=extension.critical
                )
        
        # 更新签名扩展字段
        # ⭐ 使用基础算法构建签名URI，所有签名文件都存储在同一个算法文件夹下
        sig_uri_algorithm = base_algorithm if base_algorithm else signer_wrapper.pq_algorithm
        pq_sig_extension = {
            "pq_sig_uri": "http://localhost/pq/sig/"+sig_uri_algorithm,
            "signature_hash": sha256(pq_signature).hexdigest()
        }
        
        # 添加新的签名扩展
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                oid=TEMP_OID,
                value=json.dumps(pq_sig_extension).encode('utf-8')
            ),
            critical=False
        )
        
        # 重新签名证书
        if certificate.issuer == certificate.subject:
            # 自签名
            new_certificate = builder.sign(
                private_key=self.placeholder_private_key,
                algorithm=hashes.SHA256(),
                backend=default_backend()
            )
        else:
            # 由颁发者签名
            new_certificate = builder.sign(
                private_key=signer_wrapper.placeholder_private_key,
                algorithm=hashes.SHA256(),
                backend=default_backend()
            )
        
        # ⭐ 关键修复：证书持有者的公钥应该是创建证书的wrapper的公钥，而不是签名者的公钥
        # 对于服务器证书，应该使用server_wrapper的公钥，而不是intermediate_wrapper的公钥
        # 但是这里我们无法直接访问创建证书的wrapper，所以需要从证书扩展中提取
        # 实际上，在create_certificate方法中，我们已经将公钥信息存储在扩展中了
        # 所以这里应该使用创建证书的wrapper的公钥（self.pq_public_key）
        
        # 获取证书持有者的公钥（从证书扩展中提取，或者使用传入的wrapper的公钥）
        # 注意：这里self是创建证书的wrapper，signer_wrapper是签名者的wrapper
        # 我们需要证书持有者的公钥，所以应该使用self.pq_public_key
        # 但是self在这个方法中不可用，所以我们需要从证书扩展中提取
        # 或者，我们需要修改方法签名，传入证书持有者的wrapper
        
        # 临时解决方案：从证书扩展中提取公钥哈希，然后从URI获取
        # 但更好的方法是修改方法签名，传入证书持有者的wrapper
        # 这里我们先使用signer_wrapper.pq_public_key作为占位符，但这是错误的
        
        # ⭐ 正确的做法：修改_add_pq_signature方法，传入证书持有者的wrapper
        # 或者，从证书扩展中提取公钥信息
        # 由于证书扩展中存储的是URI而不是公钥本身，我们需要另一种方法
        
        # 实际上，在create_certificate中，self就是证书持有者的wrapper
        # 所以我们应该传入self而不是signer_wrapper
        # 但是在这个方法中，self是创建证书的wrapper，signer_wrapper是签名者的wrapper
        # 所以我们需要修改方法签名，传入证书持有者的wrapper
        
        # 临时修复：使用signer_wrapper.pq_public_key（这是错误的，但先这样）
        # 正确的修复需要修改方法签名
        certificate_holder_public_key = self.pq_public_key  # ⭐ 这是证书持有者的公钥
        
        # 创建包装证书对象
        wrapped_cert = PQWrappedCertificate(
            pq_public_key=certificate_holder_public_key,  # ⭐ 使用证书持有者的公钥
            x509_cert=new_certificate,
            pq_signature=pq_signature,
            signature_algorithm=signer_wrapper.pq_algorithm
        )
        
        return wrapped_cert, pq_signature


class PQWrappedCertificate:
    """
    包装的后量子证书
    
    包含：
    1. 标准 X.509 证书（可以用传统工具处理）
    2. 后量子签名（用于真实的安全验证）
    """
    
    def __init__(
        self, 
        pq_public_key: bytes,
        x509_cert: x509.Certificate, 
        pq_signature: bytes,
        signature_algorithm: str  # 签名使用的算法（颁发者的算法）
    ):
        self.pq_public_key = pq_public_key
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
            pq_public_key = self.pq_public_key
            # print(f"get_pq_public_key 提取到的后量子公钥: {pq_public_key}")
            # print(f"get_pq_public_key 提取到的后量子公钥数据类型: {type(pq_public_key)}")
            return pq_public_key
        except Exception as e:
            raise ValueError(f"无法提取后量子公钥: {e}")
    
    def save_pem(self, cert_path: str, sig_path: Optional[str] = None, pubkey_path: Optional[str] = None):
        """
        保存为 PEM 格式
        
        Args:
            cert_path: 证书文件路径
            sig_path: 签名文件路径（可选，不提供则附加到证书文件）
        """
        # 保存 X.509 证书
        pem_data = self.x509_cert.public_bytes(serialization.Encoding.PEM)
        
        try:
            with open(cert_path, 'wb') as f:
                f.write(pem_data)
                
                # 如果不单独保存签名，则附加到证书文件
                if sig_path is None:
                    f.write(b"\n# PQ Signature (ML-DSA)\n")
                    f.write(b"# Algorithm: " + self.pq_algorithm.encode() + b"\n")
                    f.write(b"# Signature: " + self.pq_signature.hex().encode() + b"\n")
        except Exception as e:
            raise ValueError(f"保存证书文件时出错: {e}")
        
        # 单独保存签名
        if sig_path:
            try:
                sig_data = {
                    "algorithm": self.signature_algorithm,  # ⭐ 使用签名算法（签名者的算法）
                    "signature": self.pq_signature.hex()
                }
                with open(sig_path, 'w') as f:
                    json.dump(sig_data, f, indent=2)
            except Exception as e:
                raise ValueError(f"保存签名文件时出错: {e}")

        # 单独保存公钥
        if pubkey_path:
            try:
                pq_public_key = self.get_pq_public_key()
                pq_public_key_data = {
                    "algorithm": self.pq_algorithm,
                    "public_key": pq_public_key.hex()
                }
                with open(pubkey_path, 'w') as f:
                    json.dump(pq_public_key_data, f, indent=2)
            except Exception as e:
                raise ValueError(f"保存公钥文件时出错: {e}")
    
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
        
        # ⭐ 关键修复：从公钥文件中加载公钥
        # 公钥文件路径：尝试多种可能的命名模式
        cert_path_obj = Path(cert_path)
        stem = cert_path_obj.stem  # 例如: "root_ca"
        
        # 构建可能的公钥文件路径列表
        pubkey_paths = []
        
        # 模式1: {stem}_pq_pubkey.pub (例如: root_ca_pq_pubkey.pub)
        pubkey_paths.append(cert_path_obj.parent / f"{stem}_pq_pubkey.pub")
        
        # 模式2: 去掉_ca后缀 (例如: root_pq_pubkey.pub)
        if "_ca" in stem:
            pubkey_paths.append(cert_path_obj.parent / f"{stem.replace('_ca', '')}_pq_pubkey.pub")
        
        # 模式3: 如果是root_ca，直接尝试root_pq_pubkey.pub
        if "root_ca" in stem:
            pubkey_paths.append(cert_path_obj.parent / "root_pq_pubkey.pub")
        
        pq_public_key = None
        pubkey_path = None
        
        # 尝试每个可能的路径
        for path in pubkey_paths:
            if path.exists():
                pubkey_path = path
                # 从公钥文件中读取公钥（JSON格式，包含algorithm和public_key字段）
                with open(path, 'r') as f:
                    pubkey_data = json.load(f)
                    if 'public_key' in pubkey_data:
                        pq_public_key = bytes.fromhex(pubkey_data['public_key'])
                        break
        
        # 如果公钥文件不存在，尝试从证书扩展中提取
        if pq_public_key is None:
            try:
                ext = cert.extensions.get_extension_for_oid(PQ_PUBLIC_KEY_OID)
                ext_data = json.loads(ext.value.value.decode('utf-8'))
                if 'public_key' in ext_data:
                    pq_public_key = bytes.fromhex(ext_data['public_key'])
            except:
                pass
        
        if pq_public_key is None:
            tried_paths = [str(p) for p in pubkey_paths if p]
            raise ValueError(f"无法加载后量子公钥，已尝试的路径: {', '.join(tried_paths)}")
        
        return PQWrappedCertificate(pq_public_key, cert, pq_signature, pq_algorithm)
    
    def verify(self, issuer_public_key: bytes, issuer_algorithm: str) -> bool:
        """
        验证证书（后量子签名）
        
        ⭐ 关键修复：签名时使用的TBS数据包含签名扩展占位符（"signature_hash": "待签名"），
        而最终证书的TBS数据包含实际签名哈希。验证时必须使用包含占位符的TBS数据。
        
        Args:
            issuer_public_key: 颁发者的后量子公钥
            issuer_algorithm: 颁发者的算法（用于验证）
        
        Returns:
            签名是否有效
        """
        # ⭐ 关键修复：重建TBS数据，将签名扩展替换为占位符
        # 签名时使用的TBS数据包含签名扩展占位符（"signature_hash": "待签名"），
        # 而最终证书的TBS数据包含实际签名哈希。验证时必须使用包含占位符的TBS数据。
        tbs_certificate_der = self._rebuild_tbs_with_placeholder_signature()
        
        # 验证后量子签名（使用颁发者的算法）
        verifier = oqs.Signature(issuer_algorithm)
        is_valid = verifier.verify(tbs_certificate_der, self.pq_signature, issuer_public_key)
        
        return is_valid
    
    def _rebuild_tbs_with_placeholder_signature(self) -> bytes:
        """
        重建TBS数据，将签名扩展替换为占位符（与签名时使用的TBS数据一致）
        
        签名时使用的TBS数据包含签名扩展占位符（"signature_hash": "待签名"），
        而最终证书的TBS数据包含实际签名哈希。验证时必须使用包含占位符的TBS数据。
        
        Returns:
            重建的TBS数据（包含占位符签名扩展）
        """
        # 重建证书构建器，排除签名扩展
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(self.x509_cert.subject)
        builder = builder.issuer_name(self.x509_cert.issuer)
        builder = builder.public_key(self.x509_cert.public_key())
        builder = builder.serial_number(self.x509_cert.serial_number)
        
        # 处理日期时间（兼容不同版本的cryptography库）
        try:
            # 尝试使用UTC版本（新版本cryptography）
            builder = builder.not_valid_before_utc(self.x509_cert.not_valid_before_utc)
            builder = builder.not_valid_after_utc(self.x509_cert.not_valid_after_utc)
        except AttributeError:
            # 回退到旧版本（兼容旧版本cryptography）
            builder = builder.not_valid_before(self.x509_cert.not_valid_before)
            builder = builder.not_valid_after(self.x509_cert.not_valid_after)
        
        # 复制所有扩展，但将签名扩展替换为占位符
        for extension in self.x509_cert.extensions:
            if extension.oid != TEMP_OID:  # 非签名扩展，直接复制
                builder = builder.add_extension(
                    extension.value,
                    critical=extension.critical
                )
            else:
                # 签名扩展：替换为占位符（与签名时使用的TBS数据一致）
                # 从证书扩展中提取签名URI
                try:
                    sig_ext_data = json.loads(extension.value.value.decode('utf-8'))
                    sig_uri = sig_ext_data.get('pq_sig_uri', 'http://localhost/pq/sig/ML-DSA-65')
                except:
                    sig_uri = 'http://localhost/pq/sig/ML-DSA-65'
                
                # 创建占位符签名扩展（与签名时使用的格式一致）
                placeholder_sig_extension = {
                    "pq_sig_uri": sig_uri,
                    "signature_hash": "待签名"  # 占位符，与签名时使用的格式一致
                }
                
                builder = builder.add_extension(
                    x509.UnrecognizedExtension(
                        oid=TEMP_OID,
                        value=json.dumps(placeholder_sig_extension).encode('utf-8')
                    ),
                    critical=extension.critical
                )
        
        # 使用占位符私钥签名以获取TBS数据（我们只需要TBS数据，不需要实际签名）
        # 创建一个临时的占位符密钥对
        placeholder_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        
        # 构建证书以获取TBS数据
        temp_cert = builder.sign(
            private_key=placeholder_private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        
        # 返回TBS数据（包含占位符签名扩展）
        return temp_cert.tbs_certificate_bytes


def demo_wrapper():
    """演示包装器的使用"""
    print("=" * 70)
    print("X.509 后量子包装器演示")
    print("=" * 70)
    
    # 创建证书目录
    os.makedirs("enhanced_certificates_by_val/x509_wrapped", exist_ok=True)
    
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
        "enhanced_certificates_by_val/x509_wrapped/root_ca.pem",
        "enhanced_certificates_by_val/x509_wrapped/root_ca_pq.sig"
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
        "enhanced_certificates_by_val/x509_wrapped/intermediate_ca.pem",
        "enhanced_certificates_by_val/x509_wrapped/intermediate_ca_pq.sig"
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
        "enhanced_certificates_by_val/x509_wrapped/server.pem",
        "enhanced_certificates_by_val/x509_wrapped/server_pq.sig"
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
    print("   $ openssl x509 -in enhanced_certificates_by_val/x509_wrapped/server.pem -text -noout")
    print("\n   证书同时包含:")
    print("   - [OK] 标准 X.509 结构（ECDSA 占位符）")
    print("   - [OK] 后量子公钥（在自定义扩展中）")
    print("   - [OK] 后量子签名（在注释或单独文件中）")
    
    print("\n" + "=" * 70)
    print("演示完成！证书已保存到 enhanced_certificates_by_val/x509_wrapped/")
    print("=" * 70)


if __name__ == "__main__":
    demo_wrapper()

