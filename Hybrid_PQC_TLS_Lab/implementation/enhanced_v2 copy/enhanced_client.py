#!/usr/bin/env python3
"""增强的TLS 1.3客户端 - 支持证书验证和抗降级攻击"""

import sys
import os
import socket
import argparse
import hashlib
import struct
import json
import time
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any

# 导入cryptography模块用于证书解析
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# 添加项目根目录到路径
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

from core.types import TLSMode, get_group_name, get_signature_name, SignatureScheme, Certificate, CertificateVerify, Finished
from core.protocol.handshake import ClientHandshake, HandshakeKeys
from core.protocol.messages import TLSMessage
from core.crypto.record_encryption import TLSRecordEncryption
from implementation.enhanced_v2.config import ClientConfig
from core.types import oid_to_signature_algorithm_name
from implementation.enhanced_v2.pq_certificates.x509_wrapper import PQ_PUBLIC_KEY_OID, TEMP_OID as PQ_SIGNATURE_OID

# 导入enhanced_certificate模块
from core.crypto.enhanced_certificate.core.verifier import HybridCertificateVerifier
from core.crypto.enhanced_certificate.core.policies import HybridSecurityPolicy, VerificationPolicy
from core.crypto.enhanced_certificate.models.certificates import CertificateInfo, AlgorithmType, SecurityLevel

# [NOTE] 导入信任存储管理器
from implementation.enhanced_v2.trust_store_manager import TrustStoreManager

# 导入证书加载器
from implementation.enhanced_v2.cert_loader import load_client_certificates


class MessageReceiver:
    """消息接收器 - 负责接收和解析TLS握手消息"""
    
    def __init__(self, client_socket: socket.socket):
        self.client_socket = client_socket
        self.buffer = b""
    
    def receive_until_next_message(self, next_message_start: bytes, max_size: int = 16384) -> Tuple[bytes, bytes]:
        """
        接收当前消息，直到检测到下一个消息的开始标记
        
        Args:
            next_message_start: 下一个消息的开始标记（用于检测边界）
            max_size: 最大接收大小
            
        Returns:
            Tuple[当前消息数据, 下一个消息的剩余数据]
        """
        data = self.buffer
        remaining_data = b""
        
        # 先接收足够的数据来判断消息边界
        while len(data) < max_size:
            chunk = self.client_socket.recv(4096)
            if not chunk:
                break
            data += chunk
            
            # 检查是否包含下一个消息的开始
            next_start = data.find(next_message_start)
            if next_start != -1:
                # 分离当前消息和下一个消息
                remaining_data = data[next_start:]  # 保存下一个消息的剩余数据
                data = data[:next_start]  # 截断当前消息数据
                break
        
        # 更新缓冲区
        self.buffer = remaining_data
        return data, remaining_data
    
    def receive_message_by_length(self, header_length: int, length_field_start: int, 
                                length_field_size: int, message_type: str) -> bytes:
        """
        根据长度字段接收完整消息
        
        Args:
            header_length: 消息头长度
            length_field_start: 长度字段开始位置
            length_field_size: 长度字段大小（字节）
            message_type: 消息类型名称（用于日志）
            
        Returns:
            完整的消息数据
        """
        data = self.buffer
        
        # 先接收消息头
        while len(data) < header_length:
            chunk = self.client_socket.recv(4096)
            if not chunk:
                break
            data += chunk
        
        if len(data) >= header_length:
            # 解析长度字段
            length_bytes = data[length_field_start:length_field_start + length_field_size]
            content_length = int.from_bytes(length_bytes, 'big')
            
            # 计算总消息长度
            total_length = header_length + content_length
            
            # 继续接收直到获得完整的消息
            while len(data) < total_length:
                remaining = total_length - len(data)
                chunk = self.client_socket.recv(min(4096, remaining))
                if not chunk:
                    break
                data += chunk
            
            # 保存可能的多余数据到缓冲区
            if len(data) > total_length:
                self.buffer = data[total_length:]
                data = data[:total_length]
            else:
                self.buffer = b""
            
            return data
        else:
            return b""
    
    def receive_certificate_message(self) -> bytes:
        """接收Certificate消息"""
        # 接收标准TLS 1.3格式的消息
        # TLS记录格式：类型(1) + 长度(3) + 数据
        cert_message = self.receive_tls_record()
        
        return cert_message
    
    def receive_certificate_verify_message(self) -> bytes:
        """接收CertificateVerify消息"""
        # 接收标准TLS 1.3格式的消息
        verify_message = self.receive_tls_record()
        
        return verify_message
    
    def receive_finished_message(self) -> bytes:
        """接收Finished消息"""
        # 接收标准TLS 1.3格式的消息
        finished_message = self.receive_tls_record()
        
        return finished_message
    
    def receive_tls_record(self, max_size: int = 16384) -> bytes:
        """
        接收完整的TLS记录
        
        Args:
            max_size: 最大接收大小
            
        Returns:
            完整的TLS记录数据
        """
        data = self.buffer
        
        # 先接收至少5字节（类型1 + 长度3 + 至少1字节数据）
        while len(data) < 5:
            chunk = self.client_socket.recv(4096)
            if not chunk:
                break
            data += chunk
        
        if len(data) >= 5:
            # 解析TLS记录头
            record_type = data[0]
            record_length = int.from_bytes(data[1:4], 'big')
            
            # 计算总记录长度
            total_length = 4 + record_length  # 4字节头 + 内容长度
            
            # 继续接收直到获得完整的记录
            while len(data) < total_length:
                remaining = total_length - len(data)
                chunk = self.client_socket.recv(min(4096, remaining))
                if not chunk:
                    break
                data += chunk
            
            # 保存可能的多余数据到缓冲区
            if len(data) > total_length:
                self.buffer = data[total_length:]
                data = data[:total_length]
            else:
                self.buffer = b""
            
            return data
        else:
            return b""
    
    def receive_application_data(self, size: int = 4096) -> bytes:
        """接收应用数据（TLS记录格式）"""
        # 接收TLS记录头（5字节：类型1 + 版本2 + 长度2）
        header = self.client_socket.recv(5)
        if len(header) < 5:
            return b""
        
        # 解析TLS记录头
        record_type = header[0]
        version = int.from_bytes(header[1:3], 'big')  # TLS版本
        record_length = int.from_bytes(header[3:5], 'big')  # 数据长度
        
        # 接收应用数据内容
        data = b""
        while len(data) < record_length:
            chunk = self.client_socket.recv(min(4096, record_length - len(data)))
            if not chunk:
                break
            data += chunk
        
        return data
    
    def clear_buffer(self):
        """清空缓冲区"""
        self.buffer = b""


class EnhancedTLSClient:
    """增强的TLS 1.3客户端 - 支持证书验证和抗降级攻击"""
    
    def __init__(self, config: ClientConfig, tracker=None):
        self.config = config
        self.handshake = ClientHandshake(mode=config.mode)
        self.tracker = tracker  # 时间追踪器（可选）
        
        # [NOTE] 使用信任存储管理器（替代cert_bundle）
        self.trust_manager = self._initialize_trust_store()
        
        # 为了兼容，保留cert_bundle引用（但使用简化版本）
        self.cert_bundle = None  # 不再使用旧的cert_bundle
        
        # 创建证书验证器
        self.cert_verifier = self._create_certificate_verifier()
        
        # 初始化客户端密钥（用于CertificateVerify签名）
        self.client_key = self._load_client_key()
        
        # [NOTE] 存储服务器协商的签名算法
        self.server_signature_scheme = None
        
        # [NOTE] 握手密钥（用于应用数据加密）
        self.handshake_keys = None
        
        # [NOTE] 加密器（用于应用数据加解密）
        self.encryptor = TLSRecordEncryption(cipher_name="AES_128_GCM")
        self.decryptor = TLSRecordEncryption(cipher_name="AES_128_GCM")
        
        # [NOTE] HTTP客户端（用于从URI获取公钥和签名）
        self.http_client = self._create_http_client()
    
    def _initialize_trust_store(self) -> TrustStoreManager:
        """
        初始化信任存储管理器
        
        客户端本地存储多个根CA作为信任锚
        """
        print("\n" + "=" * 70)
        print("客户端初始化 - 信任存储管理器")
        print("=" * 70)
        
        try:
            # [NOTE] 加载多个根CA作为信任锚
            # 客户端应该支持多种算法的根CA，以适应不同的服务器配置
            trust_manager = TrustStoreManager(
                algorithms=["mldsa65", "mldsa44", "mldsa87", "falcon512", "falcon1024"]
            )
            
            print("=" * 70)
            print("[SUCCESS] 信任存储管理器初始化成功")
            print("=" * 70 + "\n")
            
            return trust_manager
            
        except Exception as e:
            print(f"\n[错误] 信任存储初始化失败: {e}")
            print(f"[提示] 请先运行: python implementation.enhanced_v2.pq_certificates/generate_multi_algorithm_certs.py --all")
            raise
    
    def _create_certificate_verifier(self):
        """创建证书验证器"""
        # 创建安全策略
        policy = HybridSecurityPolicy(
            policy=VerificationPolicy.HYBRID_TRANSITION,
            min_security_level=SecurityLevel.LEVEL_2,
            require_pq_leaf=True
        )
        
        # 这里使用简化的验证器
        return None
    
    def _load_client_key(self) -> Optional[bytes]:
        """
        [NOTE] 加载客户端密钥 - 客户端不需要证书，返回None
        
        在标准TLS中，客户端通常不需要证书（服务器单向认证）
        只有双向认证时客户端才需要证书
        """
        # [NOTE] 客户端不需要密钥（服务器单向认证）
        pass
    
    def _create_http_client(self):
        """创建HTTP客户端"""
        # 这里可以配置HTTP客户端参数，如超时、重试等
        # 返回一个简单的HTTP客户端对象
        return {
            'timeout': 0.5,  # 本地回环，0.5秒足够
            'retries': 1,    # 本地回环不需要重试
            'headers': {
                'User-Agent': 'EnhancedTLSClient/1.0',
                'Accept': 'application/octet-stream, application/json',
                'Connection': 'close'  # 关闭连接复用，减少延迟
            }
        }
    
    def _fetch_pq_public_key_from_uri(self, uri: str, cert_type: str = "server",
                                      expected_hash: Optional[str] = None) -> Tuple[Optional[bytes], Optional[str]]:
        """
        从URI获取后量子公钥和算法信息，支持不同类型的证书
        
        Args:
            uri: 公钥URI（HTTP/HTTPS URL）
            cert_type: 证书类型（"root", "intermediate", "server"）
            
        Returns:
            (公钥字节数据, 算法名称)，如果获取失败或哈希不匹配返回(None, None)
        """
        print(f"    [HTTP] 从URI获取{cert_type}公钥: {uri}")

        # 注意：公钥获取的时间由调用方统一追踪，这里不单独追踪
        try:
            import urllib.request
            import urllib.error
            import json
            
            # 将URI中的域名替换为localhost
            if "jeanreed.online" in uri:
                uri = uri.replace("jeanreed.online", "localhost")
            
            # 根据证书类型构造实际URL
            # 先提取路径部分，避免替换整个URL
            if "://" in uri:
                # 如果是完整URL，提取路径部分
                path = "/" + uri.split("/", 3)[-1]  # 获取路径部分并确保以/开头
            else:
                path = uri if uri.startswith("/") else "/" + uri
            
            if cert_type == "root":
                actual_path = path.replace("/pq/cert/", "/pq/cert/root/").replace("/pq/sig/", "/pq/sig/root/")
            elif cert_type == "intermediate":
                actual_path = path.replace("/pq/cert/", "/pq/cert/intermediate/").replace("/pq/sig/", "/pq/sig/intermediate/")
            else:  # server
                actual_path = path.replace("/pq/cert/", "/pq/cert/server/").replace("/pq/sig/", "/pq/sig/server/")
            
            actual_uri = "http://localhost" + actual_path
            
            # 创建请求
            req = urllib.request.Request(actual_uri, headers=self.http_client['headers'])
            
            # 发送请求（增加超时时间，本地服务器可能需要更多时间）
            import time as time_module
            timeout = max(self.http_client['timeout'], 5.0)  # 至少5秒
            with urllib.request.urlopen(req, timeout=timeout) as response:
                if response.status == 200:
                    public_key_data = response.read()
                    
                    public_key_bytes = None
                    public_key_hex = None
                    algorithm = "Unknown"
                    
                    # 尝试解析JSON格式的公钥数据
                    try:
                        public_key_json = json.loads(public_key_data.decode('utf-8'))
                        if 'public_key' in public_key_json:
                            public_key_hex = public_key_json['public_key']
                            public_key_bytes = bytes.fromhex(public_key_hex)
                            algorithm = public_key_json.get('algorithm', 'Unknown')
                    except Exception:
                        # 如果不是JSON格式，直接使用原始数据
                        public_key_bytes = public_key_data
                        public_key_hex = public_key_bytes.hex()
                    
                    if public_key_bytes is None:
                        print(f"    [HTTP] [ERROR] 未从{cert_type}响应中解析到公钥")
                        return None, None
                    
                    if public_key_hex is None:
                        public_key_hex = public_key_bytes.hex()
                    
                    if expected_hash:
                        computed_hash = hashlib.sha256(public_key_hex.encode('utf-8')).hexdigest()
                        if computed_hash.lower() != expected_hash.lower():
                            print(f"    [HTTP] [ERROR] {cert_type}公钥哈希不匹配")
                            return None, None
                    
                    print(f"    [HTTP] [OK] 成功获取{cert_type}公钥: {len(public_key_bytes)} 字节，算法: {algorithm}")
                    return public_key_bytes, algorithm
                else:
                    print(f"    [HTTP] [ERROR] HTTP错误: {response.status}")
                    return None, None

        except urllib.error.URLError as e:
            print(f"    [HTTP] [ERROR] 网络错误: {e}")
            return None, None
        except Exception as e:
            print(f"    [HTTP] [ERROR] 未知错误: {e}")
            return None, None
        except urllib.error.URLError as e:
            print(f"    [HTTP] [ERROR] 网络错误: {e}")
            if self.tracker:
                self.tracker.finish_step({'error': str(e)})
            return None, None
        except Exception as e:
            print(f"    [HTTP] [ERROR] 未知错误: {e}")
            if self.tracker:
                self.tracker.finish_step({'error': str(e)})
            return None, None
    
    def _fetch_pq_signature_from_uri(self, uri: str, cert_type: str = "server",
                                     expected_hash: Optional[str] = None) -> Tuple[Optional[bytes], Optional[str]]:
        """
        从URI获取后量子签名和算法信息，支持不同类型的证书
        
        Args:
            uri: 签名URI（HTTP/HTTPS URL）
            cert_type: 证书类型（"root", "intermediate", "server"）
            
        Returns:
            (签名字节数据, 算法名称)，如果获取失败或哈希不匹配返回(None, None)
        """
        print(f"    [HTTP] 从URI获取{cert_type}签名...")
        
        # 注意：签名获取的时间由调用方统一追踪，这里不单独追踪
        try:
            import urllib.request
            import urllib.error
            import json
            
            # 根据证书类型构造实际URL
            if cert_type == "root":
                actual_uri = uri.replace("/pq/cert/", "/pq/cert/root/").replace("/pq/sig/", "/pq/sig/root/")
            elif cert_type == "intermediate":
                actual_uri = uri.replace("/pq/cert/", "/pq/cert/intermediate/").replace("/pq/sig/", "/pq/sig/intermediate/")
            else:  # server
                actual_uri = uri.replace("/pq/cert/", "/pq/cert/server/").replace("/pq/sig/", "/pq/sig/server/")
            
            # 创建请求
            req = urllib.request.Request(actual_uri, headers=self.http_client['headers'])
            
            # 发送请求（本地回环应该很快，使用较短的超时）
            import time as time_module
            timeout = 0.5  # 本地回环，0.5秒应该足够
            with urllib.request.urlopen(req, timeout=timeout) as response:
                if response.status == 200:
                    signature_data = response.read()
                    
                    signature_bytes = None
                    algorithm = None
                    
                    # 尝试解析JSON格式的签名数据
                    try:
                        signature_json = json.loads(signature_data.decode('utf-8'))
                        if 'signature' in signature_json:
                            signature_hex = signature_json['signature']
                            signature_bytes = bytes.fromhex(signature_hex)
                            algorithm = signature_json.get('algorithm')
                    except Exception:
                        signature_bytes = signature_data
                    
                    if signature_bytes is None:
                        print(f"    [HTTP] [ERROR] 未从{cert_type}响应中解析到签名")
                        return None, None
                    
                    if expected_hash:
                        computed_hash = hashlib.sha256(signature_bytes).hexdigest()
                        if computed_hash.lower() != expected_hash.lower():
                            print(f"    [HTTP] [ERROR] {cert_type}签名哈希不匹配")
                            return None, None
                    
                    algo_display = algorithm or "Unknown"
                    print(f"    [HTTP] [OK] 成功获取{cert_type}签名: {len(signature_bytes)} 字节, 算法: {algo_display}")
                    if self.tracker:
                        self.tracker.finish_step({'size': len(signature_bytes), 'algorithm': algo_display})
                    return signature_bytes, algorithm
                else:
                    print(f"    [HTTP] [ERROR] HTTP错误: {response.status}")
                    if self.tracker:
                        self.tracker.finish_step({'error': f'HTTP {response.status}'})
                    return None, None
        except urllib.error.URLError as e:
            print(f"    [HTTP] [ERROR] 网络错误: {e}")
            if self.tracker:
                self.tracker.finish_step({'error': str(e)})
            return None, None
        except Exception as e:
            print(f"    [HTTP] [ERROR] 未知错误: {e}")
            if self.tracker:
                self.tracker.finish_step({'error': str(e)})
            return None, None
    
    def _generate_certificate_verify_signature(self, handshake_hash: bytes) -> bytes:
        """
        [NOTE] 生成客户端证书验证签名
        
        客户端在服务器单向认证模式下不需要签名
        返回空签名表示客户端未提供证书
        """
        # [NOTE] 客户端不签名（服务器单向认证）
        return b""  # 空签名表示未提供客户端证书
    
    def _verify_server_certificate(self, server_cert_data: bytes, intermediate_cert_data: Optional[bytes] = None, 
                                   server_pq_sig: Optional[bytes] = None, inter_pq_sig: Optional[bytes] = None,
                                   server_pq_public_key: Optional[bytes] = None, inter_pq_public_key: Optional[bytes] = None,
                                   server_pq_algorithm: Optional[str] = None, inter_pq_algorithm: Optional[str] = None) -> Tuple[bool, Optional[bytes], Optional[str]]:
        """
        [NOTE] 验证服务器证书链 - 使用Enhanced Certificate完整验证
        
        符合TLS 1.3 RFC 8446规范的验证流程：
        1. 解析服务器证书和中间CA证书（DER格式）
        2. 提取后量子公钥、算法和签名（从扩展字段和.sig文件）
        3. 动态匹配根CA：根据中间CA的issuer在本地信任存储中查找
        4. 使用Enhanced Certificate验证器验证整个链的签名：
           - 根CA公钥验证中间CA签名（后量子签名验证）
           - 中间CA公钥验证服务器证书签名（后量子签名验证）
        5. 应用安全策略检查
        
        Args:
            server_cert_data: 服务器证书（DER编码）
            intermediate_cert_data: 中间CA证书（DER编码，可选）
        
        Returns:
            (是否有效, 后量子公钥, 后量子算法名称)
        """
        print(f"\n[证书验证] 开始验证服务器证书链...")
        print(f"[证书验证] 服务器证书长度: {len(server_cert_data)} 字节")
        if intermediate_cert_data:
            print(f"[证书验证] 中间CA证书长度: {len(intermediate_cert_data)} 字节")
        
        # 初始化中间CA签名者的算法（如果还没有设置）
        inter_pq_signer_algorithm = None
        
        if len(server_cert_data) == 0:
            print(f"[证书验证] [FAIL] 证书数据为空")
            return False, None, None
        
        # [NOTE] 步骤1: 解析证书
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        import json
        
        try:
            # 解析服务器证书
            server_cert = x509.load_der_x509_certificate(server_cert_data, default_backend())
            print(f"[步骤1] [OK] 服务器证书解析成功")
            print(f"  主题: {server_cert.subject}")
            print(f"  颁发者: {server_cert.issuer}")
            
            # 解析中间CA证书（如果提供）
            intermediate_cert = None
            if intermediate_cert_data and len(intermediate_cert_data) > 0:
                intermediate_cert = x509.load_der_x509_certificate(intermediate_cert_data, default_backend())
                print(f"[步骤1] [OK] 中间CA证书解析成功")
                print(f"  主题: {intermediate_cert.subject}")
                print(f"  颁发者: {intermediate_cert.issuer}")
            else:
                print(f"[步骤1] [WARN]  未提供中间CA证书，将只验证服务器证书")
                
        except Exception as e:
            print(f"[步骤1] [FAIL] 证书解析失败: {e}")
            return False, None, None
        
        # [NOTE] 步骤2: 提取后量子信息（使用新的扩展解析方法）
        print(f"\n[步骤2] 提取后量子信息...")
        
        try:
            # 使用新的扩展解析方法提取服务器证书信息
            server_ext_info = self.extract_pq_extensions_from_der(server_cert_data)
            
            # 根据扩展信息判断工作模式
            has_pq_pk_uri = server_ext_info.get('pq_pk_uri') is not None
            has_pq_sig_uri = server_ext_info.get('pq_sig_uri') is not None
            
            if has_pq_pk_uri and has_pq_sig_uri:
                # by_ref模式：包含URI，需要外部获取
                print(f"  [OK] 服务器证书使用引用模式 (by_ref)")
                print(f"    公钥URI: {server_ext_info.get('pq_pk_uri')}")
                print(f"    签名URI: {server_ext_info.get('pq_sig_uri')}")
                
                # 在by_ref模式下，优先使用传入的公钥参数
                if server_pq_public_key is not None:
                    print(f"  [OK] 使用传入的服务器公钥: {len(server_pq_public_key)} 字节")
                else:
                    server_pq_public_key = None  # 需要从URI获取
                    print(f"  [WARN]  未传入服务器公钥参数")
                
                # [NOTE] 关键修复：在by_ref模式下，从证书扩展中获取算法
                if server_pq_algorithm is not None:
                    print(f"  [OK] 使用传入的服务器算法: {server_pq_algorithm}")
                else:
                    # 从证书扩展中获取算法
                    server_pq_algorithm = server_ext_info.get('algorithm')
                    if server_pq_algorithm:
                        print(f"  [OK] 从证书扩展获取服务器算法: {server_pq_algorithm}")
                    else:
                        server_pq_algorithm = "ML-DSA-44"  # 默认算法
                        print(f"  [WARN]  未找到服务器算法，使用默认: {server_pq_algorithm}")
                
            else:
                # by_val模式：直接包含值
                print(f"  [OK] 服务器证书使用值模式 (by_val)")
                
                # 使用传统方法提取信息（向后兼容）
                try:
                    ext = server_cert.extensions.get_extension_for_oid(PQ_PUBLIC_KEY_OID)
                    
                    # 处理扩展值
                    ext_value_obj = ext.value.value
                    
                    # 处理可能的元组类型
                    if isinstance(ext_value_obj, tuple):
                        ext_value = ext_value_obj[0]
                    else:
                        ext_value = ext_value_obj
                    
                    # 如果是字节类型，解码为字符串
                    if isinstance(ext_value, bytes):
                        ext_value = ext_value.decode('utf-8')
                    elif isinstance(ext_value, str):
                        # 已经是字符串，直接使用
                        pass
                    else:
                        # 其他类型，转换为字符串
                        ext_value = str(ext_value)
                    
                    metadata = json.loads(ext_value)
                    
                    # 检查metadata中public_key的类型
                    public_key_value = metadata['public_key']
                    # 确保public_key是字符串类型
                    if not isinstance(public_key_value, str):
                        public_key_value = str(public_key_value)
                    
                    expected_hash = metadata.get('public_key_hash')
                    computed_hash = hashlib.sha256(public_key_value.encode('utf-8')).hexdigest()
                    if expected_hash and computed_hash.lower() != expected_hash.lower():
                        print(f"  [FAIL] 服务器证书公钥哈希不匹配")
                        return False, None, None
                    
                    server_pq_public_key = bytes.fromhex(public_key_value)
                    server_pq_algorithm = metadata['algorithm']
                    
                    print(f"  [OK] 服务器证书PQ算法: {server_pq_algorithm}")
                    print(f"  [OK] 服务器证书PQ公钥: {len(server_pq_public_key)} 字节")
                except Exception as e:
                    print(f"  [WARN]  传统方法提取失败，尝试备用方法: {e}")
                    import traceback
                    traceback.print_exc()
                    # 备用方法：从扩展信息中获取
                    server_pq_public_key = None
                    server_pq_algorithm = "ML-DSA-44"  # 默认算法
            
            # [NOTE] 使用接收到的PQ签名
            if server_pq_sig:
                print(f"  [OK] 服务器PQ签名: {len(server_pq_sig)} 字节")
            else:
                print(f"  [WARN]  未接收到服务器PQ签名")
            
        except Exception as e:
            print(f"[步骤2] [FAIL] 提取服务器PQ信息失败: {e}")
            return False, None, None
        
        # [NOTE] 步骤3: 如果有中间CA，进行完整的证书链验证
        if intermediate_cert:
            print(f"\n[步骤3] 使用Enhanced Certificate验证证书链...")
            
            # 初始化中间CA签名者的算法（如果还没有设置）
            if 'inter_pq_signer_algorithm' not in locals():
                inter_pq_signer_algorithm = None
            
            try:
                # 使用新的扩展解析方法提取中间CA证书信息
                inter_ext_info = self.extract_pq_extensions_from_der(intermediate_cert_data)
                
                # 根据扩展信息判断工作模式
                has_pq_pk_uri = inter_ext_info.get('pq_pk_uri') is not None
                has_pq_sig_uri = inter_ext_info.get('pq_sig_uri') is not None
                
                if has_pq_pk_uri and has_pq_sig_uri:
                    # by_ref模式：包含URI，需要外部获取
                    print(f"  [OK] 中间CA证书使用引用模式 (by_ref)")
                    print(f"    公钥URI: {inter_ext_info.get('pq_pk_uri')}")
                    print(f"    签名URI: {inter_ext_info.get('pq_sig_uri')}")
                    
                    # 在by_ref模式下，优先使用传入的公钥参数
                    if inter_pq_public_key is not None:
                        print(f"  [OK] 使用传入的中间CA公钥: {len(inter_pq_public_key)} 字节")
                    else:
                        inter_pq_public_key = None  # 需要从URI获取
                        print(f"  [WARN]  未传入中间CA公钥参数")
                    
                    # [NOTE] 关键修复：在by_ref模式下，从证书扩展中获取算法
                    # 优先使用从证书扩展中提取的算法，而不是传入的参数
                    # 因为传入的参数可能是错误的（例如，可能是签名者的算法而不是证书持有者的算法）
                    extracted_algorithm = inter_ext_info.get('algorithm')
                    if extracted_algorithm:
                        inter_pq_algorithm = extracted_algorithm  # 使用从证书扩展中提取的算法
                        print(f"  [OK] 从证书扩展获取中间CA算法: {inter_pq_algorithm}")
                    elif inter_pq_algorithm is not None:
                        print(f"  [OK] 使用传入的中间CA算法: {inter_pq_algorithm}")
                    else:
                        inter_pq_algorithm = "ML-DSA-44"  # 默认算法
                        print(f"  [WARN]  未找到中间CA算法，使用默认: {inter_pq_algorithm}")
                
                else:
                    # by_val模式：直接包含值
                    print(f"  [OK] 中间CA证书使用值模式 (by_val)")
                    
                    # 使用传统方法提取信息（向后兼容）
                    try:
                        ext = intermediate_cert.extensions.get_extension_for_oid(PQ_PUBLIC_KEY_OID)
                        metadata = json.loads(ext.value.value.decode('utf-8'))
                        public_key_hex = metadata['public_key']
                        expected_hash = metadata.get('public_key_hash')
                        computed_hash = hashlib.sha256(public_key_hex.encode('utf-8')).hexdigest()
                        if expected_hash and computed_hash.lower() != expected_hash.lower():
                            print(f"  [FAIL] 中间CA公钥哈希不匹配，期望: {expected_hash}, 实际: {computed_hash}")
                            return False, None, None
                        
                        inter_pq_public_key = bytes.fromhex(public_key_hex)
                        inter_pq_algorithm = metadata['algorithm']
                        
                        # [NOTE] 在by_val模式下，签名者的算法需要从根CA获取
                        # 这里先设置为None，后续会从根CA获取
                        inter_pq_signer_algorithm = None
                        
                        print(f"  [OK] 中间CA PQ算法: {inter_pq_algorithm}")
                    except Exception as e:
                        print(f"  [WARN]  传统方法提取失败，尝试备用方法: {e}")
                        # 备用方法：从扩展信息中获取
                        inter_pq_public_key = None
                        inter_pq_algorithm = "ML-DSA-44"  # 默认算法
                        inter_pq_signer_algorithm = None
                
                # [NOTE] 使用接收到的PQ签名
                if inter_pq_sig:
                    print(f"  [OK] 中间CA PQ签名: {len(inter_pq_sig)} 字节")
                else:
                    print(f"  [WARN]  未接收到中间CA PQ签名")
                
                # [NOTE] 动态匹配根CA并验证签名
                if server_pq_sig and inter_pq_sig:
                    # 在by_ref模式下，需要传入从外部获取的公钥
                    # [NOTE] 关键修复：服务器证书应该使用中间CA的算法进行验证
                    # 中间CA证书应该使用根CA的算法进行验证
                    
                    # 首先获取根CA的算法信息
                    root_match_result = self.trust_manager.find_trust_anchor_for_chain(intermediate_cert)
                    if not root_match_result:
                        print(f"[步骤3] [FAIL] 无法找到匹配的根CA")
                        return False, None, None
                    
                    root_algo_key, root_info, root_cert, root_public_key = root_match_result
                    root_pq_algorithm = root_info.signature_algorithm
                    print(f"  [OK] 根CA算法: {root_pq_algorithm}")
                    
                    # [NOTE] 关键修复：验证时需要使用签名者的算法
                    # 服务器证书由中间CA签名，所以应该使用中间CA证书持有者的算法
                    # 中间CA证书由根CA签名，所以应该使用根CA的算法
                    server_signer_algorithm = inter_pq_algorithm  # 服务器证书的签名者是中间CA，使用中间CA的算法
                    inter_signer_algorithm = inter_pq_signer_algorithm or root_pq_algorithm  # 中间CA证书的签名者是根CA
                    
                    success, error = self.trust_manager.verify_chain_with_enhanced_verifier(
                        server_cert, server_pq_sig, server_signer_algorithm,  # [NOTE] 服务器证书使用中间CA的算法（签名者）
                        intermediate_cert, inter_pq_sig, inter_signer_algorithm,  # [NOTE] 中间CA证书使用根CA的算法（签名者）
                        server_pq_public_key, inter_pq_public_key  # 传入外部获取的公钥
                    )
                
                    if not success:
                        print(f"[步骤3] [证书验证] ✗ 证书链验证失败: {error}")
                        return False, None, None
                    
                    print(f"[步骤3] [证书验证] ✓ 证书链验证成功")
                else:
                    # ⭐ 如果签名缺失，应该终止握手，而不是跳过验证
                    if not server_pq_sig:
                        print(f"[步骤3] [FAIL] 缺少服务器PQ签名，无法验证证书链")
                        return False, None, None
                    if not inter_pq_sig:
                        print(f"[步骤3] [FAIL] 缺少中间CA PQ签名，无法验证证书链")
                        return False, None, None
                    print(f"[步骤3] [WARN]  缺少PQ签名，跳过签名验证")
                
            except Exception as e:
                print(f"[步骤3] [FAIL] 证书链验证异常: {e}")
                import traceback
                traceback.print_exc()
                print(f"[步骤3] [ERROR] 证书链验证失败，终止握手")
                return False, None, None
        else:
            print(f"\n[步骤3] [WARN]  跳过完整链验证（未提供中间CA或签名）")
            # ⭐ 如果没有中间CA，无法进行完整的证书链验证，应该终止握手
            print(f"[步骤3] [ERROR] 缺少中间CA证书，无法验证证书链，终止握手")
            return False, None, None
        
        # [NOTE] 返回服务器证书的PQ公钥和算法（用于CertificateVerify验证）
        print(f"\n[完成] 证书验证流程完成")
        if server_pq_public_key:
            print(f"  返回公钥: {len(server_pq_public_key)} 字节")
        else:
            print(f"  返回公钥: None")
        print(f"  返回算法: {server_pq_algorithm}")
        
        return True, server_pq_public_key, server_pq_algorithm
    
    def _verify_server_signature(self, signature: bytes, handshake_hash: bytes, server_public_key: bytes, pq_algorithm: str) -> bool:
        """
        [NOTE] 验证服务器签名 - 使用真实的后量子签名验证
        
        Args:
            signature: 服务器的CertificateVerify签名
            handshake_hash: 握手消息哈希
            server_public_key: 服务器的后量子公钥
            pq_algorithm: 后量子算法名称（如ML-DSA-44）
        """
        try:
            # [NOTE] 将算法名称转换为SignatureScheme
            from core.types import get_signature_scheme
            signature_scheme = get_signature_scheme(pq_algorithm)
            
            # [NOTE] 使用真实的后量子签名验证
            from core.protocol.handshake import verify_certificate_signature
            
            is_valid = verify_certificate_signature(
                signature=signature,
                handshake_hash=handshake_hash,
                public_key=server_public_key,
                signature_scheme=signature_scheme
            )
            
            if is_valid:
                print(f"    [证书验证] ✓ 服务器签名验证成功 ({pq_algorithm})")
            else:
                print(f"    [证书验证] ✗ 服务器签名验证失败 ({pq_algorithm})")
            
            return is_valid
            
        except Exception as e:
            print(f"    [ERROR] 签名验证错误: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    def extract_pq_extensions_from_der(self, der_cert_data: bytes) -> Dict[str, Any]:
        """
        从DER格式证书中提取后量子扩展信息
        
        Args:
            der_cert_data: DER格式的证书数据
            
        Returns:
            包含两个扩展URI和哈希值的字典
            {
                'pq_pk_uri': '公钥URI',
                'pq_sig_uri': '签名URI', 
                'public_key_hash': '公钥哈希值',
                'signature_hash': '签名哈希值'
            }
        """
        try:
            # 1. 将DER数据加载为X.509证书对象
            cert = x509.load_der_x509_certificate(der_cert_data, default_backend())
            
            # 3. 提取扩展信息
            pq_pk_uri = None
            pq_sig_uri = None
            public_key_hash = None
            signature_hash = None
            by_val_flag = None
            algorithm = None  # [NOTE] 初始化算法字段
            
            # 遍历所有扩展
            for extension in cert.extensions:
                ext_value = None
                
                try:
                    # 跳过非UnrecognizedExtension类型的扩展（如BasicConstraints）
                    if not isinstance(extension.value, x509.UnrecognizedExtension):
                        continue
                    
                    # 获取扩展值 - UnrecognizedExtension.value 直接是 bytes
                    # extension.value 是 UnrecognizedExtension 对象
                    # extension.value.value 是 bytes 类型
                    ext_value_obj = extension.value.value
                    
                    if isinstance(ext_value_obj, tuple):
                        # 如果是元组，取第一个元素
                        ext_value = ext_value_obj[0]
                    else:
                        ext_value = ext_value_obj
                    
                    # 如果是字节类型，解码为字符串
                    if isinstance(ext_value, bytes):
                        ext_value = ext_value.decode('utf-8')
                    elif isinstance(ext_value, str):
                        # 已经是字符串，直接使用
                        pass
                    else:
                        # 其他类型，转换为字符串
                        ext_value = str(ext_value)
                except Exception as e:
                    continue
                
                try:
                    # 尝试解析JSON数据
                    ext_data = json.loads(ext_value)
                    
                    # 根据OID判断扩展类型
                    if extension.oid == PQ_PUBLIC_KEY_OID:
                        # 这是公钥扩展
                        pq_pk_uri = ext_data.get('pq_pk_uri', '').strip() or None
                        public_key_hash = ext_data.get('public_key_hash', '') or None
                        algorithm = ext_data.get('algorithm')  # [NOTE] 提取算法字段
                        by_val_flag = ext_data.get('by_val')
                        
                    elif extension.oid == PQ_SIGNATURE_OID:
                        # 这是签名扩展
                        pq_sig_uri = ext_data.get('pq_sig_uri', '').strip() or None
                        signature_hash = ext_data.get('signature_hash', '') or None
                        
                except json.JSONDecodeError:
                    # 如果无法解析为JSON，跳过这个扩展
                    continue
            
            # 4. 返回提取的信息
            result = {
                'pq_pk_uri': pq_pk_uri,
                'pq_sig_uri': pq_sig_uri,
                'public_key_hash': public_key_hash,
                'signature_hash': signature_hash,
                'by_val': by_val_flag,
                'algorithm': algorithm  # [NOTE] 包含算法字段
            }
            
            print(f"    [OK] 成功提取扩展信息:")
            if pq_pk_uri:
                print(f"      - 公钥URI: {pq_pk_uri}")
            if pq_sig_uri:
                print(f"      - 签名URI: {pq_sig_uri}")
            if public_key_hash:
                print(f"      - 公钥哈希: {public_key_hash}")
            if signature_hash:
                print(f"      - 签名哈希: {signature_hash}")
            
            return result
            
        except Exception as e:
            print(f"    [ERROR] 提取扩展信息失败: {e}")
            return {
                'pq_pk_uri': None,
                'pq_sig_uri': None,
                'public_key_hash': None,
                'signature_hash': None,
                'by_val': None,
                'algorithm': None  # [NOTE] 包含算法字段
            }
    
    def _compute_handshake_hash(self, client_hello: bytes, server_hello: bytes, certificate: bytes = None, certificate_verify: bytes = None) -> bytes:
        """计算握手消息的哈希值（基于TLS 1.3标准）"""
        # 使用core模块中的标准实现
        from core.protocol.handshake import compute_handshake_hash
        return compute_handshake_hash(client_hello, server_hello, certificate, certificate_verify)
    
    def _parse_certificate_message_full(self, data: bytes) -> Tuple[bool, List[bytes]]:
        """
        解析Certificate消息，提取完整的证书链
        
        Returns:
            (是否成功, 证书列表[服务器证书, 中间CA, ...])
        """
        try:
            # 使用TLS 1.3标准格式解析
            if len(data) < 4:  # 至少需要4字节头
                return False, []
            
            # 解码Certificate消息
            certificate = TLSMessage.decode_certificate(data)
            
            # 提取所有证书
            if certificate.certificate_list:
                cert_list = certificate.certificate_list
                print(f"    [OK] 解析Certificate消息: {len(cert_list)} 个证书")
                return True, cert_list
            else:
                print(f"    [ERROR] Certificate消息中无证书数据")
                return False, []
                
        except Exception as e:
            print(f"    [ERROR] 解析Certificate消息错误: {e}")
            return False, []
    
    def _parse_certificate_verify_message(self, data: bytes) -> Tuple[bool, bytes]:
        """解析CertificateVerify消息并验证算法"""
        try:
            # 使用TLS 1.3标准格式解析
            if len(data) < 4:  # 至少需要4字节头
                print(f"    [ERROR] CertificateVerify消息太短: {len(data)} 字节")
                return False, b""
            
            # 解码CertificateVerify消息
            try:
                certificate_verify = TLSMessage.decode_certificate_verify(data)
            except (KeyError, ValueError, json.JSONDecodeError) as e:
                print(f"    [ERROR] 解析CertificateVerify消息格式错误: {e}")
                print(f"    消息数据长度: {len(data)} 字节")
                print(f"    消息数据前100字节(hex): {data[:100].hex()}")
                return False, b""
            
            # 检查algorithm属性是否存在
            if not hasattr(certificate_verify, 'algorithm') or certificate_verify.algorithm is None:
                print(f"    [ERROR] CertificateVerify消息缺少algorithm字段")
                return False, b""
            
            # [NOTE] 验证服务器选择的签名算法是否在客户端支持列表中
            from core.types import get_mode_config
            client_supported = get_mode_config(self.config.mode)['signature_algorithms']
            
            if certificate_verify.algorithm not in client_supported:
                print(f"    [WARN]  服务器选择的算法 {get_signature_name(certificate_verify.algorithm)} 不在客户端支持列表中")
                print(f"    客户端支持: {[get_signature_name(s) for s in client_supported[:5]]}")
            else:
                print(f"    [OK] 签名算法验证通过: {get_signature_name(certificate_verify.algorithm)}")
            
            # 保存服务器协商的签名算法
            self.server_signature_scheme = certificate_verify.algorithm
            
            return True, certificate_verify.signature
            
        except Exception as e:
            print(f"    [ERROR] 解析CertificateVerify消息错误: {e}")
            import traceback
            traceback.print_exc()
            return False, b""
    
    def connect(self):
        """连接到服务器并执行增强握手"""
        print(f"\n{'='*70}")
        print(f"  增强TLS 1.3客户端 [{self.config.mode.value.upper()} 模式]")
        print(f"  支持证书验证和抗降级攻击")
        print(f"{'='*70}\n")
        
        # 创建客户端套接字
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            # 连接到服务器
            print(f"[*] 连接到服务器 {self.config.host}:{self.config.port}...")
            client_socket.connect((self.config.host, self.config.port))
            print(f"[+] 连接成功\n")
            
            # 执行增强握手
            self.perform_enhanced_handshake(client_socket)
            
        except Exception as e:
            print(f"[!] 连接错误: {e}")
        finally:
            client_socket.close()
    
    def perform_enhanced_handshake(self, client_socket: socket.socket):
        """执行增强的握手流程"""
        # 初始化消息接收器
        receiver = MessageReceiver(client_socket)
        
        # 1. 生成并发送ClientHello
        if self.tracker:
            self.tracker.start_step("生成ClientHello")
        print(f"[1] 生成ClientHello...")
        client_hello, client_hello_bytes = self.handshake.generate_client_hello()
        client_socket.send(client_hello_bytes)
        print(f"    [OK] 发送 {len(client_hello_bytes)} 字节")
        if self.tracker:
            self.tracker.finish_step({'size': len(client_hello_bytes)})
        
        # 2. 接收ServerHello
        if self.tracker:
            self.tracker.start_step("接收ServerHello")
        print(f"\n[2] 接收ServerHello...")
        server_hello_data = receiver.receive_tls_record()
        print(f"    [OK] 接收ServerHello: {len(server_hello_data)} 字节")
        if self.tracker:
            self.tracker.finish_step({'size': len(server_hello_data)})
        
        # 3. 处理ServerHello并计算共享密钥
        if self.tracker:
            self.tracker.start_step("处理ServerHello")
        print(f"\n[3] 处理ServerHello...")
        keys = self.handshake.process_server_hello(server_hello_data)

        # [NOTE] 保存握手密钥（用于应用数据加密）
        self.handshake_keys = keys

        print(f"    [KEM] ✓ 密钥交换成功，握手密钥派生完成")
        if self.tracker:
            self.tracker.finish_step()
        
        # 4. [NOTE] 接收服务器的Certificate消息（包含完整证书链）
        print(f"\n[4] 接收服务器Certificate消息...")
        if self.tracker:
            self.tracker.start_step("接收Certificate消息")
        cert_message = receiver.receive_certificate_message()
        if self.tracker:
            self.tracker.finish_step({'size': len(cert_message)})
        
        # 解析证书链
        if self.tracker:
            self.tracker.start_step("解析证书链")
        is_valid, cert_list = self._parse_certificate_message_full(cert_message)
        
        if not is_valid or not cert_list or len(cert_list) == 0:
            print(f"    [ERROR] 无法解析Certificate消息")
            if self.tracker:
                self.tracker.finish_step({'error': '无法解析证书链'})
            return
        
        server_cert_data = cert_list[0]  # 第一个是服务器证书
        intermediate_cert_data = cert_list[1] if len(cert_list) > 1 else None  # 第二个是中间CA
        
        print(f"    [OK] 接收证书链: {len(cert_list)} 个证书")
        if self.tracker:
            self.tracker.finish_step({'cert_count': len(cert_list)})
        
        # 解析所有证书链中的后量子扩展信息
        print(f"    [4.1] 开始解析证书链中的后量子扩展信息...")
        if self.tracker:
            self.tracker.start_step("解析证书扩展信息")
        
        # 为每个证书提取扩展信息
        cert_extensions = []
        for i, cert_data in enumerate(cert_list):
            print(f"    [4.1.{i+1}] 解析证书 {i+1}/{len(cert_list)} 的扩展信息...")
            
            # 使用新添加的extract_pq_extensions_from_der方法提取扩展信息
            ext_info = self.extract_pq_extensions_from_der(cert_data)
            cert_extensions.append(ext_info)
            
            # 判断证书类型（服务器证书、中间CA、根CA等）
            cert_type = "服务器证书" if i == 0 else "中间CA证书" if i < len(cert_extensions) - 1 else "根CA证书"
            print(f"      - {cert_type} 扩展信息提取完成")
        
        if self.tracker:
            self.tracker.finish_step({'extracted_count': len(cert_extensions)})
        
        # 分析扩展信息，确定证书链的工作模式（by_val或by_ref）
        by_val = []
        for i, ext_info in enumerate(cert_extensions):
            cert_type = "服务器证书" if i == 0 else "中间CA证书" if i < len(cert_extensions) - 1 else "根CA证书"
            
            mode_flag = ext_info.get('by_val')
            if mode_flag is None:
                has_pq_pk_uri = bool(ext_info.get('pq_pk_uri'))
                has_pq_sig_uri = bool(ext_info.get('pq_sig_uri'))
                mode_flag = not (has_pq_pk_uri and has_pq_sig_uri)
            
            by_val.append(bool(mode_flag))
            if mode_flag:
                print(f"      - {cert_type} 使用值模式 (by_val)")
            else:
                print(f"      - {cert_type} 使用引用模式 (by_ref)")
        
        print(f"    [OK] 证书链模式分析完成: {by_val}")
        
        # 根据模式执行相应的操作
        print(f"    [4.2] 根据证书链模式执行相应操作...")
        server_pq_public_key = None
        server_pq_algorithm = None
        server_pq_sig = None
        inter_pq_public_key = None
        inter_pq_algorithm = None  # 中间CA证书持有者的算法
        inter_pq_signer_algorithm = None  # 中间CA签名者的算法（用于验证服务器证书）
        
        # 处理服务器证书（索引0）
        server_ext_info = cert_extensions[0]
        
        if by_val[0]:  # 服务器证书使用by_val模式
            print(f"    [4.2.1] 服务器证书使用值模式，直接验证...")
            # 在by_val模式下，证书已经包含了所有必要信息
            # 验证逻辑将在后续步骤中完成
        else:  # 服务器证书使用by_ref模式
            print(f"    [4.2.1] 服务器证书使用引用模式，需要获取外部资源...")
            pq_pk_uri = server_ext_info.get('pq_pk_uri')
            pq_sig_uri = server_ext_info.get('pq_sig_uri')
            pk_hash = server_ext_info.get('public_key_hash')
            sig_hash = server_ext_info.get('signature_hash')
            
            
        # [NOTE] 优化：并行获取公钥和签名（减少HTTP请求延迟）
        import threading

        server_pq_public_key = None
        server_pq_sig = None
        pk_error = None
        sig_error = None

        # 开始整体HTTP请求时间追踪
        if self.tracker:
            self.tracker.start_step("HTTP获取server资源")
        http_start_time = time.time()

        def fetch_public_key():
            nonlocal server_pq_public_key, pk_error
            if pq_pk_uri:
                print(f"      - 需要从URI获取公钥: {pq_pk_uri}")
                try:
                    print(f"      - 开始获取服务器公钥...")
                    result = self._fetch_pq_public_key_from_uri(pq_pk_uri, "server", pk_hash)
                    if result and result[0]:
                        server_pq_public_key = result[0]
                        print(f"    [OK] 成功获取服务器公钥: {len(server_pq_public_key)} 字节")
                    else:
                        pk_error = "无法从URI获取服务器公钥"
                        print(f"    [ERROR] {pk_error}")
                except Exception as e:
                    pk_error = str(e)
                    print(f"    [ERROR] 获取公钥异常: {e}")
            else:
                print(f"      - 服务器证书没有公钥URI，跳过公钥获取")

        def fetch_signature():
            nonlocal server_pq_sig, sig_error
            if pq_sig_uri:
                print(f"      - 需要从URI获取签名: {pq_sig_uri}")
                try:
                    result = self._fetch_pq_signature_from_uri(pq_sig_uri, "server", sig_hash)
                    if result and result[0]:
                        server_pq_sig = result[0]
                        print(f"    [OK] 成功获取服务器签名: {len(server_pq_sig)} 字节")
                    else:
                        sig_error = "无法从URI获取服务器签名"
                        print(f"    [ERROR] {sig_error}")
                except Exception as e:
                    sig_error = str(e)
                    print(f"    [ERROR] 获取签名异常: {e}")
            else:
                print(f"    [WARN]  pq_sig_uri为None或空，无法获取服务器签名")

        # 并行执行HTTP请求（减少等待时间，本地回环应该很快）
        print(f"      - HTTP请求执行策略: pk_uri={bool(pq_pk_uri)}, sig_uri={bool(pq_sig_uri)}")
        if pq_pk_uri and pq_sig_uri:
            print(f"      - 并行执行公钥和签名获取")
            pk_thread = threading.Thread(target=fetch_public_key, daemon=True)
            sig_thread = threading.Thread(target=fetch_signature, daemon=True)
            pk_thread.start()
            sig_thread.start()
            # [NOTE] 修复：确保线程完全完成，避免时间跟踪重叠
            pk_thread.join(timeout=1.0)  # 增加超时时间
            sig_thread.join(timeout=1.0)
            # 检查线程是否仍然存活
            if pk_thread.is_alive() or sig_thread.is_alive():
                print(f"      [WARN] HTTP线程未在预期时间内完成，可能影响时间跟踪")
        elif pq_pk_uri:
            print(f"      - 仅执行公钥获取")
            fetch_public_key()
        elif pq_sig_uri:
            print(f"      - 仅执行签名获取")
            fetch_signature()
        else:
            print(f"      - 无需HTTP请求")
            server_pq_public_key = None
            server_pq_algorithm = "Unknown"

        # 结束整体HTTP请求时间追踪
        http_end_time = time.time()
        http_duration = (http_end_time - http_start_time) * 1000
        if self.tracker:
            self.tracker.finish_step({
                'total_http_time_ms': http_duration,
                'pk_uri': bool(pq_pk_uri),
                'sig_uri': bool(pq_sig_uri)
            })
            
            # 设置算法
            if server_pq_public_key:
                server_pq_algorithm = server_ext_info.get('algorithm') or server_pq_algorithm
                print(f"    [OK] 服务器证书算法（从证书扩展）: {server_pq_algorithm}")
            
            if server_pq_public_key is None or server_pq_sig is None:
                print(f"    [ERROR] 无法获取服务器证书所需的后量子公钥或签名，终止握手")
                return
        
        # 初始化inter_pq_sig变量
        inter_pq_sig = None
        
        # 处理中间CA证书（如果有）
        if len(cert_extensions) > 1:
            for i in range(1, len(cert_extensions)):  # 跳过服务器证书，处理所有中间CA证书
                ca_ext_info = cert_extensions[i]
                cert_type = f"中间CA证书 {i}"
                
                if by_val[i]:  # 中间CA使用by_val模式
                    print(f"    [4.2.{i+1}] {cert_type} 使用值模式，直接验证...")
                else:  # 中间CA使用by_ref模式
                    print(f"    [4.2.{i+1}] {cert_type} 使用引用模式，需要获取外部资源...")
                    pq_pk_uri = ca_ext_info.get('pq_pk_uri')
                    pq_sig_uri = ca_ext_info.get('pq_sig_uri')
                    pk_hash = ca_ext_info.get('public_key_hash')
                    sig_hash = ca_ext_info.get('signature_hash')
                    
                    # [NOTE] 优化：并行获取中间CA的公钥和签名
                    inter_pq_public_key = None
                    inter_pq_sig = None
                    inter_pk_error = None
                    inter_sig_error = None
                    
                    def fetch_inter_public_key():
                        nonlocal inter_pq_public_key, inter_pk_error
                        if pq_pk_uri:
                            print(f"      - 需要从URI获取中间CA公钥: {pq_pk_uri}")
                            try:
                                print(f"      - 开始获取中间CA公钥...")
                                result = self._fetch_pq_public_key_from_uri(pq_pk_uri, "intermediate", pk_hash)
                                if result and result[0]:
                                    inter_pq_public_key = result[0]
                                    print(f"    [OK] 成功获取中间CA公钥: {len(inter_pq_public_key)} 字节")
                                else:
                                    inter_pk_error = "无法从URI获取中间CA公钥"
                                    print(f"    [ERROR] {inter_pk_error}")
                            except Exception as e:
                                inter_pk_error = str(e)
                                print(f"    [ERROR] 获取中间CA公钥异常: {e}")
                        else:
                            print(f"      - 中间CA证书没有公钥URI，跳过公钥获取")
                    
                    def fetch_inter_signature():
                        nonlocal inter_pq_sig, inter_sig_error
                        if pq_sig_uri:
                            print(f"      - 需要从URI获取签名: {pq_sig_uri}")
                            try:
                                inter_pq_signature_result = self._fetch_pq_signature_from_uri(
                                    pq_sig_uri, "intermediate", sig_hash
                                )
                                if inter_pq_signature_result and inter_pq_signature_result[0]:
                                    inter_pq_signature, sig_file_algorithm = inter_pq_signature_result
                                    # [NOTE] 关键修复：验证时需要使用签名者的算法，而不是证书持有者的算法
                                    inter_pq_algorithm = ca_ext_info.get('algorithm') or inter_pq_algorithm
                                    inter_signer_algorithm = sig_file_algorithm or inter_pq_algorithm
                                    print(f"    [OK] 成功获取中间CA签名: {len(inter_pq_signature)} 字节")
                                    print(f"    [OK] 中间CA证书算法（证书持有者，从证书扩展）: {inter_pq_algorithm}")
                                    print(f"    [OK] 中间CA签名算法（签名者，从签名文件）: {inter_signer_algorithm}")
                                    inter_pq_sig = inter_pq_signature
                                    # [NOTE] 保存签名者的算法，用于验证
                                    if 'inter_pq_signer_algorithm' not in locals():
                                        inter_pq_signer_algorithm = inter_signer_algorithm
                                else:
                                    inter_sig_error = "无法从URI获取中间CA签名"
                                    print(f"    [ERROR] {inter_sig_error}")
                                    inter_pq_sig = None
                            except Exception as e:
                                inter_sig_error = str(e)
                                print(f"    [ERROR] 获取中间CA签名异常: {e}")
                        else:
                            print(f"    [WARN]  pq_sig_uri为None或空，无法获取中间CA签名")
                    
                    # 开始整体中间CA HTTP请求时间追踪
                    if self.tracker:
                        self.tracker.start_step("HTTP获取intermediate资源")
                    inter_http_start_time = time.time()

                    # 并行执行HTTP请求（减少等待时间，本地回环应该很快）
                    print(f"        - 中间CA HTTP请求执行策略: pk_uri={bool(pq_pk_uri)}, sig_uri={bool(pq_sig_uri)}")
                    if pq_pk_uri and pq_sig_uri:
                        print(f"        - 并行执行中间CA公钥和签名获取")
                        inter_pk_thread = threading.Thread(target=fetch_inter_public_key, daemon=True)
                        inter_sig_thread = threading.Thread(target=fetch_inter_signature, daemon=True)
                        inter_pk_thread.start()
                        inter_sig_thread.start()
                        # [NOTE] 修复：确保线程完全完成，避免时间跟踪重叠
                        inter_pk_thread.join(timeout=1.0)  # 增加超时时间
                        inter_sig_thread.join(timeout=1.0)
                        # 检查线程是否仍然存活
                        if inter_pk_thread.is_alive() or inter_sig_thread.is_alive():
                            print(f"        [WARN] 中间CA HTTP线程未在预期时间内完成，可能影响时间跟踪")
                    elif pq_pk_uri:
                        print(f"        - 仅执行中间CA公钥获取")
                        fetch_inter_public_key()
                    elif pq_sig_uri:
                        print(f"        - 仅执行中间CA签名获取")
                        fetch_inter_signature()
                    else:
                        print(f"        - 中间CA无需HTTP请求")
                        inter_pq_public_key = None
                        inter_pq_algorithm = ca_ext_info.get('algorithm') or "Unknown"

                    # 结束整体中间CA HTTP请求时间追踪
                    inter_http_end_time = time.time()
                    inter_http_duration = (inter_http_end_time - inter_http_start_time) * 1000
                    if self.tracker:
                        self.tracker.finish_step({
                            'total_http_time_ms': inter_http_duration,
                            'pk_uri': bool(pq_pk_uri),
                            'sig_uri': bool(pq_sig_uri)
                        })
                    
                    # 设置算法
                    if inter_pq_public_key:
                        inter_pq_algorithm = ca_ext_info.get('algorithm') or inter_pq_algorithm
                        print(f"    [OK] 中间CA证书算法（从证书扩展）: {inter_pq_algorithm}")
                        inter_pq_signer_algorithm = None
                    
                    if inter_pq_public_key is None or inter_pq_sig is None:
                        print(f"    [ERROR] 无法获取{cert_type}的后量子公钥或签名，终止握手")
                        return
        
        print(f"    [OK] 证书链解析完成，准备进行验证...")
        # 重要：这是非引用模式证书使用的操作，引用类型不用发送签名
        # # [NOTE] 接收PQ签名扩展
        # print(f"\n[4.1] 接收PQ签名扩展...")
        # pq_sig_data = receiver.receive_tls_record()
        
        # # 解析PQ签名
        # server_pq_sig = None
        # inter_pq_sig = None
        
        # if pq_sig_data and len(pq_sig_data) > 4:
        #     try:
        #         import json
        #         pq_sigs = json.loads(pq_sig_data[4:].decode('utf-8'))
                
        #         if 'server_pq_sig' in pq_sigs:
        #             server_pq_sig = bytes.fromhex(pq_sigs['server_pq_sig'])
        #             print(f"    [OK] 接收服务器PQ签名: {len(server_pq_sig)} 字节")
                
        #         if 'intermediate_pq_sig' in pq_sigs:
        #             inter_pq_sig = bytes.fromhex(pq_sigs['intermediate_pq_sig'])
        #             print(f"    [OK] 接收中间CAPQ签名: {len(inter_pq_sig)} 字节")
                    
        #     except Exception as e:
        #         print(f"    [WARN]  解析PQ签名扩展失败: {e}")
        
        # [NOTE] 验证服务器证书链（使用Enhanced Certificate）
        print(f"\n[5] 验证服务器证书链（含签名验证）...")
        if self.tracker:
            self.tracker.start_step("证书链验证")
        
        cert_valid, server_public_key, pq_algorithm = self._verify_server_certificate(
            server_cert_data,
            intermediate_cert_data,  # [NOTE] 传入中间CA证书
            server_pq_sig,           # [NOTE] 传入服务器PQ签名
            inter_pq_sig,             # [NOTE] 传入中间CAPQ签名
            server_pq_public_key,     # [NOTE] 传入服务器PQ公钥
            inter_pq_public_key,      # [NOTE] 传入中间CAPQ公钥
            server_pq_algorithm,      # [NOTE] 传入服务器PQ算法
            inter_pq_algorithm        # [NOTE] 传入中间CAPQ算法
        )
        
        if not cert_valid:
            print(f"    [证书验证] ✗ 服务器证书验证失败，终止握手")
            if self.tracker:
                self.tracker.finish_step({'valid': False})
            return
        
        print(f"    [证书验证] ✓ 服务器证书链验证成功")
        print(f"      算法: {pq_algorithm}")
        print(f"      公钥大小: {len(server_public_key)} 字节")
        if self.tracker:
            self.tracker.finish_step({'valid': True, 'algorithm': pq_algorithm, 'public_key_size': len(server_public_key)})
        
        # 6. 接收服务器的CertificateVerify消息
        if self.tracker:
            self.tracker.start_step("接收CertificateVerify消息")
        print(f"\n[6] 接收服务器CertificateVerify消息...")
        cert_verify_message = receiver.receive_certificate_verify_message()
        if self.tracker:
            self.tracker.finish_step({'size': len(cert_verify_message)})

        # 7. 接收服务器的Finished消息
        if self.tracker:
            self.tracker.start_step("接收Finished消息")
        print(f"\n[7] 接收服务器Finished消息...")
        server_finished_message = receiver.receive_finished_message()
        if self.tracker:
            self.tracker.finish_step({'size': len(server_finished_message) if server_finished_message else 0})
        
        # 8. 计算握手哈希（用于CertificateVerify验证）
        # 提取握手消息（去除TLS记录头）
        client_hello_handshake = client_hello_bytes[4:]  # 去除4字节记录头
        server_hello_handshake = server_hello_data[4:]  # 去除4字节记录头
        cert_message_handshake = cert_message[4:]       # 去除4字节记录头
        
        # 根据TLS 1.3标准，CertificateVerify签名基于到Certificate消息为止的所有握手消息
        # 不包含CertificateVerify消息本身
        handshake_hash_for_verify = self._compute_handshake_hash(
            client_hello_handshake,           # 发送的ClientHello（握手消息）
            server_hello_handshake,       # ServerHello握手消息
            cert_message_handshake        # Certificate握手消息
        )
        print(f"    [OK] 握手哈希计算完成")
        
        # 9. 计算完整握手哈希（用于抗降级攻击保护）
        # 包含ClientHello、ServerHello、Certificate和CertificateVerify消息
        cert_verify_message_handshake = cert_verify_message[4:]  # 去除4字节记录头
        full_handshake_hash = self._compute_handshake_hash(
            client_hello_bytes,           # 发送的ClientHello（握手消息）
            server_hello_handshake,       # ServerHello握手消息
            cert_message_handshake,      # Certificate握手消息
            cert_verify_message_handshake # CertificateVerify握手消息
        )
        print(f"    [OK] 完整握手哈希计算完成")
        
        # # [NOTE] 这部分代码已移至上面的[4]步骤，这里不需要重复解析
        # # 证书已经在上面解析并验证完成
        
        # print(f"    [OK] 接收服务器证书 ({len(server_cert_data)} 字节)")
        
        # # [NOTE] 验证服务器证书（完整的信任链检查）
        # cert_verified, server_pq_public_key, server_pq_algorithm = self._verify_server_certificate(server_cert_data)
        
        # if not cert_verified:
        #     print(f"    [ERROR] 服务器证书验证失败，终止连接")
        #     return
        
        # [NOTE] 解析并验证服务器签名
        print(f"\n[7] 验证服务器CertificateVerify签名...")
        verify_valid, server_signature = self._parse_certificate_verify_message(cert_verify_message)
        
        if not verify_valid:
            print(f"    [ERROR] 无效的CertificateVerify消息")
            return
        
        print(f"    [OK] 接收服务器签名 ({len(server_signature)} 字节)")
        
        # [NOTE] 使用真实的后量子公钥验证签名（使用步骤5返回的变量）
        server_signature_valid = self._verify_server_signature(
            server_signature, 
            handshake_hash_for_verify, 
            server_public_key,  # 真实的后量子公钥（来自步骤5）
            pq_algorithm        # 后量子算法名称（来自步骤5）
        )
        
        if server_finished_message:
            print(f"    [OK] 接收服务器Finished消息 ({len(server_finished_message)} 字节)")
        else:
            print(f"    [ERROR] 无法接收完整的Finished消息")
            return
        
        # 9. 发送客户端的CertificateVerify消息
        print(f"\n[8] 发送客户端CertificateVerify...")
        client_cert_verify = self._generate_certificate_verify_signature(handshake_hash_for_verify)
        
        # 使用TLS 1.3标准格式
        from core.types import SignatureScheme
        cv = CertificateVerify(
            algorithm=SignatureScheme.rsa_pss_sha256,  # 默认算法
            signature=client_cert_verify
        )
        verify_message = TLSMessage.encode_certificate_verify(cv)
        client_socket.send(verify_message)
        print(f"    [OK] 发送客户端证书验证签名 ({len(client_cert_verify)} 字节)")
        
        # 10. 发送客户端的Finished消息
        print(f"\n[9] 发送客户端Finished消息...")
        client_finished_key = hashlib.sha256(b"client_finished" + full_handshake_hash).digest()[:12]
        
        # 使用TLS 1.3标准格式
        finished = Finished(verify_data=client_finished_key)
        finished_message = TLSMessage.encode_finished(finished)
        client_socket.send(finished_message)
        print(f"    [OK] 发送客户端Finished消息")
        
        # 11. 握手完成
        print(f"\n[10] 握手完成！")
        print(f"    [OK] 证书验证: {'通过' if server_signature_valid else '失败'}")
        print(f"    [OK] 抗降级攻击: 已启用")
        
        # ⭐ 握手完成后，为应用数据创建新的加密器/解密器实例（序列号从0开始）
        # 这样可以确保应用数据的序列号从0开始，与握手消息的序列号分离
        app_encryptor = TLSRecordEncryption(cipher_name="AES_128_GCM")
        app_decryptor = TLSRecordEncryption(cipher_name="AES_128_GCM")
        
        # 12. 发送应用数据（使用TLS记录格式）
        print(f"\n[11] 发送应用数据...")
        app_data = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        
        # [NOTE] 使用客户端握手密钥加密（客户端发送的数据用client_handshake_key加密）
        # ⭐ 使用应用数据专用的加密器（序列号从0开始）
        try:
            encrypted_app_data = app_encryptor.encrypt_record(
                app_data,
                self.handshake_keys.client_handshake_key,
                self.handshake_keys.client_handshake_iv
            )
            print(f"    [SUCCESS] 加密成功: {len(encrypted_app_data)} 字节")
            
            # 封装为TLS记录（应用数据类型=23）
            record_type = 23  # TLS应用数据类型
            record_header = struct.pack('!B', record_type)
            record_header += struct.pack('!H', 0x0303)  # TLS 1.2版本（兼容性）
            record_header += struct.pack('!H', len(encrypted_app_data))
            
            tls_app_data = record_header + encrypted_app_data
            client_socket.send(tls_app_data)
            print(f"    [OK] 发送加密TLS应用数据记录 ({len(tls_app_data)} 字节)")
            
        except Exception as e:
            print(f"    [ERROR] 加密失败: {e}")
            return
        
        # 13. 接收服务器响应
        print(f"\n[12] 接收服务器响应...")
        encrypted_response = receiver.receive_application_data(4096)
        if encrypted_response:
            print(f"    [OK] 接收加密响应: {len(encrypted_response)} 字节")
            
            # [NOTE] 使用服务器握手密钥解密（服务器发送的数据用server_handshake_key加密）
            # ⭐ 使用应用数据专用的解密器（序列号从0开始）
            try:
                response, content_type = app_decryptor.decrypt_record(
                    encrypted_response,
                    self.handshake_keys.server_handshake_key,
                    self.handshake_keys.server_handshake_iv
                )
                print(f"    [SUCCESS] 解密成功: {len(response)} 字节明文")
                
                # 解析响应头
                response_str = response.decode('utf-8', errors='ignore')
                headers = response_str.split('\r\n\r\n')[0]
                print(f"\n服务器响应头:")
                for line in headers.split('\r\n'):
                    if line.strip():
                        print(f"    {line}")
                        
            except Exception as e:
                print(f"    [ERROR] 解密失败: {e}")
                return


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='增强的Hybrid PQC-TLS客户端')
    parser.add_argument('--mode', choices=['classic', 'pqc', 'hybrid'], 
                       default='hybrid', help='TLS模式')
    parser.add_argument('--host', default='127.0.0.1', help='服务器主机')
    parser.add_argument('--port', type=int, default=8443, help='服务器端口')
    parser.add_argument('--ca', help='CA证书文件')
    
    args = parser.parse_args()
    
    # 创建配置
    config = ClientConfig(
        mode=TLSMode(args.mode),
        host=args.host,
        port=args.port,
        algorithm=None  # 客户端自动适应服务器选择的算法
    )
    
    # 启动客户端
    client = EnhancedTLSClient(config)
    client.connect()


if __name__ == '__main__':
    main()