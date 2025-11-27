#!/usr/bin/env python3
"""
信任存储管理器
客户端本地存储多个根CA，根据服务器证书链动态匹配验证
"""

import os
import sys
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# 添加项目路径
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from implementation.enhanced_v2.pq_certificates.x509_wrapper import PQWrappedCertificate
from implementation.enhanced_v2 import config as config_module
from core.crypto.enhanced_certificate.models.certificates import CertificateInfo, AlgorithmType, SecurityLevel
from core.crypto.enhanced_certificate.core.verifier import HybridCertificateVerifier

get_cert_config = config_module.get_cert_config
SUPPORTED_ALGORITHMS = config_module.SUPPORTED_ALGORITHMS


class TrustStoreManager:
    """
    信任存储管理器
    
    功能：
    1. 本地存储多个签名算法的根CA（信任锚）
    2. 根据服务器发来的证书链，动态匹配对应的根CA
    3. 使用enhanced_certificate验证逻辑，验证整个证书链的签名
    """
    
    def __init__(self, algorithms: Optional[List[str]] = None):
        """
        初始化信任存储
        
        Args:
            algorithms: 要加载的根CA算法列表，None表示加载所有可用
        """
        self.trust_anchors: Dict[str, CertificateInfo] = {}  # 算法 -> 根CA证书信息
        self.root_certs: Dict[str, x509.Certificate] = {}    # 算法 -> 根CA X.509证书
        self.root_public_keys: Dict[str, bytes] = {}          # 算法 -> 根CA公钥
        
        # 如果未指定算法，加载默认列表（包括所有支持的算法）
        if algorithms is None:
            algorithms = ["mldsa65", "mldsa44", "mldsa87", "falcon512", "falcon1024"]
        
        self._load_trust_anchors(algorithms)
    
    def _load_trust_anchors(self, algorithms: List[str]):
        """加载多个算法的根CA作为信任锚"""
        print("\n" + "=" * 80)
        print("信任存储管理器 - 加载根CA")
        print("=" * 80)
        
        loaded_count = 0
        for algo in algorithms:
            try:
                # 获取根CA路径
                cert_config = get_cert_config(algo)
                paths = cert_config.get_cert_paths()
                
                root_cert_path = paths['trust_store_cert']
                root_sig_path = paths['trust_store_sig']
                
                # 检查文件是否存在
                if not os.path.exists(root_cert_path):
                    print(f"[WARN]  跳过 {algo}: 根CA不存在")
                    continue
                
                # 加载根CA证书
                print(f"\n[{loaded_count + 1}] 加载 {algo} 根CA...")
                wrapped_root = PQWrappedCertificate.load_pem(root_cert_path, root_sig_path)
                
                root_cert = wrapped_root.x509_cert
                root_pq_public_key = wrapped_root.get_pq_public_key()
                root_pq_algorithm = wrapped_root.pq_algorithm
                
                # 创建CertificateInfo（用于enhanced_certificate验证）
                cert_info = CertificateInfo(
                    subject=str(root_cert.subject),
                    issuer=str(root_cert.issuer),
                    public_key=root_pq_public_key,
                    signature_algorithm=root_pq_algorithm,
                    signature=wrapped_root.pq_signature,
                    tbs_certificate=root_cert.tbs_certificate_bytes,
                    algorithm_type=AlgorithmType.POST_QUANTUM,
                    security_level=self._get_security_level(root_pq_algorithm),
                    is_ca=True
                )
                
                # 存储
                self.trust_anchors[algo] = cert_info
                self.root_certs[algo] = root_cert
                self.root_public_keys[algo] = root_pq_public_key
                
                print(f"  [OK] {algo}: {root_pq_algorithm}")
                print(f"    主题: {root_cert.subject}")
                print(f"    公钥: {len(root_pq_public_key)} 字节")
                
                loaded_count += 1
                
            except Exception as e:
                print(f"  [FAIL] 加载 {algo} 失败: {e}")
        
        print("\n" + "=" * 80)
        print(f"[SUCCESS] 加载完成: {loaded_count}/{len(algorithms)} 个根CA")
        print("=" * 80)
        
        if loaded_count == 0:
            raise RuntimeError("没有可用的根CA，请先生成证书")
        
        print(f"\n可用的信任锚: {', '.join(self.trust_anchors.keys())}")
    
    def _get_security_level(self, algorithm: str) -> SecurityLevel:
        """根据算法名称获取安全级别"""
        level_map = {
            "ML-DSA-44": SecurityLevel.LEVEL_2,
            "ML-DSA-65": SecurityLevel.LEVEL_3,
            "ML-DSA-87": SecurityLevel.LEVEL_5,
            "Falcon-512": SecurityLevel.LEVEL_2,
            "Falcon-1024": SecurityLevel.LEVEL_5,
            "Dilithium2": SecurityLevel.LEVEL_2,
            "Dilithium3": SecurityLevel.LEVEL_3,
            "Dilithium5": SecurityLevel.LEVEL_5,
        }
        return level_map.get(algorithm, SecurityLevel.LEVEL_3)
    
    def find_trust_anchor_for_chain(
        self, 
        intermediate_cert: x509.Certificate
    ) -> Optional[Tuple[str, CertificateInfo, x509.Certificate, bytes]]:
        """
        根据中间CA证书，找到对应的根CA
        
        Args:
            intermediate_cert: 中间CA证书
        
        Returns:
            (算法key, 根CA CertificateInfo, 根CA X.509证书, 根CA公钥) 或 None
        """
        # 遍历所有根CA，找到issuer匹配的
        for algo_key, root_cert in self.root_certs.items():
            if root_cert.subject == intermediate_cert.issuer:
                return (
                    algo_key,
                    self.trust_anchors[algo_key],
                    root_cert,
                    self.root_public_keys[algo_key]
                )
        
        print(f"[匹配] ✗ 未找到匹配的根CA")
        
        return None
    
    def verify_chain_with_enhanced_verifier(
        self,
        server_cert: x509.Certificate,
        server_pq_sig: bytes,
        server_pq_algo: str,
        intermediate_cert: x509.Certificate,
        intermediate_pq_sig: bytes,
        intermediate_pq_algo: str,
        server_pq_public_key: Optional[bytes] = None,
        inter_pq_public_key: Optional[bytes] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        使用enhanced_certificate验证器验证证书链
        
        验证逻辑：
        1. 根据中间CA的issuer找到对应的根CA
        2. 构建CertificateInfo列表
        3. 使用HybridCertificateVerifier验证整个链的签名
        
        Returns:
            (验证是否成功, 错误信息)
        """
        # 1. 找到对应的根CA
        match_result = self.find_trust_anchor_for_chain(intermediate_cert)
        
        if not match_result:
            return False, "未找到匹配的根CA"
        
        algo_key, root_info, root_cert, root_public_key = match_result
        
        # 2. 构建CertificateInfo列表
        
        # 服务器证书（叶子）
        # 优先使用传入的公钥，如果没有传入则尝试从证书扩展中提取
        if server_pq_public_key is None:
            server_pq_public_key = self._extract_pq_public_key(server_cert)
        
        # [NOTE] signature_algorithm应该是签名者（中间CA）的算法
        # 服务器证书是由中间CA签名的，所以应该使用中间CA的算法进行验证
        # server_pq_algo 参数传入的是服务器证书的签名者算法（中间CA的算法）
        
        # [NOTE] 关键修复：重建TBS数据，将签名扩展替换为占位符
        # 签名时使用的TBS数据包含签名扩展占位符（"signature_hash": "待签名"），
        # 而最终证书的TBS数据包含实际签名哈希。验证时应该使用包含占位符的TBS数据。
        server_tbs_data = self._rebuild_tbs_without_sig_extension(server_cert)
        
        server_info = CertificateInfo(
            subject=str(server_cert.subject),
            issuer=str(server_cert.issuer),
            public_key=server_pq_public_key,
            signature_algorithm=server_pq_algo,  # [NOTE] 使用server_pq_algo（中间CA的算法，签名者）
            signature=server_pq_sig,
            tbs_certificate=server_tbs_data,  # [NOTE] 使用重建的TBS数据（不包含签名扩展）
            algorithm_type=AlgorithmType.POST_QUANTUM,
            security_level=self._get_security_level(server_pq_algo),
            is_ca=False
        )
        print(f"  [OK] 服务器证书: {server_cert.subject}")
        print(f"    算法: {server_pq_algo} (签名者算法)")
        
        # 中间CA证书
        # 优先使用传入的公钥，如果没有传入则尝试从证书扩展中提取
        if inter_pq_public_key is None:
            inter_pq_public_key = self._extract_pq_public_key(intermediate_cert)
        
        # [NOTE] 关键修复：signature_algorithm应该是签名者（根CA）的算法，而不是证书主体的算法
        # 中间CA证书是由根CA签名的，所以应该使用根CA的算法进行验证
        # intermediate_pq_algo 参数传入的是中间CA证书的签名者算法（根CA的算法）
        
        # [NOTE] 关键修复：重建TBS数据，将签名扩展替换为占位符
        # 签名时使用的TBS数据包含签名扩展占位符（"signature_hash": "待签名"），
        # 而最终证书的TBS数据包含实际签名哈希。验证时应该使用包含占位符的TBS数据。
        intermediate_tbs_data = self._rebuild_tbs_without_sig_extension(intermediate_cert)
        
        intermediate_info = CertificateInfo(
            subject=str(intermediate_cert.subject),
            issuer=str(intermediate_cert.issuer),
            public_key=inter_pq_public_key,
            signature_algorithm=intermediate_pq_algo,  # [NOTE] 使用intermediate_pq_algo（根CA的算法，签名者）
            signature=intermediate_pq_sig,
            tbs_certificate=intermediate_tbs_data,  # [NOTE] 使用重建的TBS数据（不包含签名扩展）
            algorithm_type=AlgorithmType.POST_QUANTUM,
            security_level=self._get_security_level(intermediate_pq_algo),  # [NOTE] 使用根CA的安全级别
            is_ca=True
        )
        print(f"  [OK] 中间CA: {intermediate_cert.subject}")
        print(f"    算法: {intermediate_pq_algo} (签名者算法)")
        
        # 根CA（信任锚）
        print(f"  [OK] 根CA: {root_cert.subject}")
        print(f"    算法: {root_info.signature_algorithm}")
        
        # 3. 创建验证器并验证
        try:
            verifier = HybridCertificateVerifier(
                trust_anchors=[root_info]
            )
            
            # 验证证书链（叶子 → 中间 → 根）
            result = verifier.verify_certificate_chain(
                leaf_cert=server_info,
                intermediate_certs=[intermediate_info]
            )
            
            return True, None
            
        except Exception as e:
            return False, str(e)
    
    def _extract_pq_public_key(self, cert: x509.Certificate) -> bytes:
        """从证书扩展中提取后量子公钥"""
        from implementation.enhanced_v2.pq_certificates.x509_wrapper import PQ_PUBLIC_KEY_OID
        import json
        
        try:
            ext = cert.extensions.get_extension_for_oid(PQ_PUBLIC_KEY_OID)
            metadata = json.loads(ext.value.value.decode('utf-8'))
            
            # 检查扩展字段中是否有 public_key 字段（值模式）
            expected_hash = metadata.get('public_key_hash')
            
            if 'public_key' in metadata and metadata['public_key']:
                public_key_hex = metadata['public_key']
                self._validate_public_key_hash(public_key_hex, expected_hash, str(cert.subject))
                return bytes.fromhex(public_key_hex)
            else:
                # 引用模式：证书扩展中不包含公钥，需要从URI获取
                pq_pk_uri = metadata.get('pq_pk_uri', '')
                if pq_pk_uri:
                    # 在引用模式下，需要通过HTTP请求从URI获取公钥
                    import urllib.request
                    import urllib.error
                    
                    # 将URI中的域名替换为localhost
                    # if "jeanreed.online" in pq_pk_uri:
                    #     pq_pk_uri = pq_pk_uri.replace("jeanreed.online", "localhost")
                    
                    # 根据证书类型构造实际URL
                    if cert.issuer == cert.subject:  # 根CA证书
                        actual_uri = pq_pk_uri.replace("/pq/cert/", "/pq/cert/root/").replace("/pq/sig/", "/pq/sig/root/")
                    elif "intermediate" in str(cert.subject).lower() or "ca" in str(cert.subject).lower():  # 中间CA证书
                        actual_uri = pq_pk_uri.replace("/pq/cert/", "/pq/cert/intermediate/").replace("/pq/sig/", "/pq/sig/intermediate/")
                    else:  # 服务器证书
                        actual_uri = pq_pk_uri.replace("/pq/cert/", "/pq/cert/server/").replace("/pq/sig/", "/pq/sig/server/")
                    
                    # 确保URI以http://开头
                    if not actual_uri.startswith("http://"):
                        actual_uri = "http://" + actual_uri
                    
                    print(f"    [HTTP] 从URI获取公钥: {actual_uri}")

                    # 创建请求
                    headers = {
                        'User-Agent': 'Enhanced-TLS-Client/1.0'
                    }
                    req = urllib.request.Request(actual_uri, headers=headers)

                    # 发送请求
                    with urllib.request.urlopen(req, timeout=10) as response:
                        if response.status == 200:
                            public_key_data = response.read()
                            
                            # 尝试解析JSON格式的公钥数据
                            try:
                                public_key_json = json.loads(public_key_data.decode('utf-8'))
                                if 'public_key' in public_key_json:
                                    public_key_hex = public_key_json['public_key']
                                    public_key_bytes = bytes.fromhex(public_key_hex)
                                    self._validate_public_key_hash(public_key_hex, expected_hash, str(cert.subject))
                                    print(f"    [HTTP] [OK] 成功获取公钥: {len(public_key_bytes)} 字节")
                                    return public_key_bytes
                            except:
                                # 如果不是JSON格式，直接返回原始数据
                                public_key_hex = public_key_data.hex()
                                self._validate_public_key_hash(public_key_hex, expected_hash, str(cert.subject))
                                print(f"    [HTTP] [OK] 成功获取公钥: {len(public_key_data)} 字节")
                                return public_key_data
                        else:
                            raise ValueError(f"HTTP请求失败，状态码: {response.status}")
                
                # 如果以上方法都失败，抛出异常
                raise ValueError("证书扩展字段中未找到后量子公钥信息")
                
        except Exception as e:
            raise ValueError(f"无法提取后量子公钥: {e}")
    
    def _validate_public_key_hash(self, public_key_hex: str, expected_hash: Optional[str], cert_subject: str) -> None:
        """校验公钥哈希"""
        if not expected_hash:
            return
        computed_hash = hashlib.sha256(public_key_hex.encode('utf-8')).hexdigest()
        if computed_hash.lower() != expected_hash.lower():
            raise ValueError(
                f"{cert_subject} 的后量子公钥哈希不匹配（期望 {expected_hash}, 实际 {computed_hash}）"
            )
    
    def _rebuild_tbs_without_sig_extension(self, cert: x509.Certificate) -> bytes:
        """
        重建TBS数据，将签名扩展替换为占位符（与签名时使用的TBS数据一致）
        
        签名时使用的TBS数据包含签名扩展占位符（"signature_hash": "待签名"），
        而最终证书的TBS数据包含实际签名哈希。验证时应该使用包含占位符的TBS数据。
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        from implementation.enhanced_v2.pq_certificates.x509_wrapper import TEMP_OID
        
        # 重建证书构建器，排除签名扩展
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(cert.subject)
        builder = builder.issuer_name(cert.issuer)
        builder = builder.public_key(cert.public_key())
        builder = builder.serial_number(cert.serial_number)
        # 修复日期时间：使用UTC版本以避免弃用警告
        from datetime import timezone
        import warnings
        
        # 优先使用UTC版本（新版本cryptography）
        if hasattr(cert, 'not_valid_before_utc'):
            not_valid_before = cert.not_valid_before_utc
            not_valid_after = cert.not_valid_after_utc
        else:
            # 旧版本：手动将naive datetime转换为UTC aware datetime
            # 使用warnings抑制弃用警告
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                not_valid_before_naive = cert.not_valid_before
                not_valid_after_naive = cert.not_valid_after
            
            # 转换为UTC aware datetime
            if not_valid_before_naive.tzinfo is None:
                not_valid_before = not_valid_before_naive.replace(tzinfo=timezone.utc)
            else:
                not_valid_before = not_valid_before_naive
            if not_valid_after_naive.tzinfo is None:
                not_valid_after = not_valid_after_naive.replace(tzinfo=timezone.utc)
            else:
                not_valid_after = not_valid_after_naive
        
        # 使用UTC版本的方法设置日期时间
        if hasattr(builder, 'not_valid_before_utc'):
            builder = builder.not_valid_before_utc(not_valid_before)
            builder = builder.not_valid_after_utc(not_valid_after)
        else:
            # 旧版本builder：需要移除时区信息
            builder = builder.not_valid_before(not_valid_before.replace(tzinfo=None) if not_valid_before.tzinfo else not_valid_before)
            builder = builder.not_valid_after(not_valid_after.replace(tzinfo=None) if not_valid_after.tzinfo else not_valid_after)
        
        # 复制所有扩展，但将签名扩展替换为占位符
        import json
        for extension in cert.extensions:
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
        from cryptography.hazmat.primitives.asymmetric import ec
        placeholder_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        
        # 构建证书以获取TBS数据
        temp_cert = builder.sign(
            private_key=placeholder_private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        
        # 返回TBS数据（不包含签名扩展）
        rebuilt_tbs = temp_cert.tbs_certificate_bytes
        
        return rebuilt_tbs
    
    def list_trust_anchors(self) -> List[str]:
        """列出所有信任锚"""
        return list(self.trust_anchors.keys())


def test_trust_store_manager():
    """测试信任存储管理器"""
    print("\n[TEST] 测试信任存储管理器\n")
    
    # 1. 加载多个根CA
    manager = TrustStoreManager(algorithms=["mldsa65", "falcon512", "mldsa44"])
    
    # 2. 列出信任锚
    print(f"\n信任锚列表: {manager.list_trust_anchors()}")
    
    # 3. 测试匹配
    # 模拟一个中间CA的issuer
    for algo in manager.list_trust_anchors():
        root_cert = manager.root_certs[algo]
        print(f"\n{algo} 根CA:")
        print(f"  主题: {root_cert.subject}")
        print(f"  算法: {manager.trust_anchors[algo].signature_algorithm}")


if __name__ == "__main__":
    test_trust_store_manager()


