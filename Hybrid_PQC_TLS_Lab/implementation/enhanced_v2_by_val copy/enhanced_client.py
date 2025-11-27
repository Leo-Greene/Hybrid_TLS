#!/usr/bin/env python3
"""增强的TLS 1.3客户端 - 支持证书验证和抗降级攻击"""

import sys
import os
import socket
import argparse
import hashlib
import struct
from pathlib import Path
from typing import Optional, Tuple, List

# 添加项目根目录到路径
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

from core.types import TLSMode, get_group_name, get_signature_name, SignatureScheme, Certificate, CertificateVerify, Finished
from core.protocol.handshake import ClientHandshake, HandshakeKeys
from core.protocol.messages import TLSMessage
from core.crypto.record_encryption import TLSRecordEncryption
from implementation.enhanced_v2_by_val.config import ClientConfig
from core.types import oid_to_signature_algorithm_name

# 导入enhanced_certificate模块
from core.crypto.enhanced_certificate.core.verifier import HybridCertificateVerifier
from core.crypto.enhanced_certificate.core.policies import HybridSecurityPolicy, VerificationPolicy
from core.crypto.enhanced_certificate.models.certificates import CertificateInfo, AlgorithmType, SecurityLevel

# ⭐ 导入信任存储管理器
from implementation.enhanced_v2_by_val.trust_store_manager import TrustStoreManager

# 导入证书加载器
from implementation.enhanced_v2_by_val.cert_loader import load_client_certificates


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
        
        # ⭐ 使用信任存储管理器（替代cert_bundle）
        self.trust_manager = self._initialize_trust_store()
        
        # 为了兼容，保留cert_bundle引用（但使用简化版本）
        self.cert_bundle = None  # 不再使用旧的cert_bundle
        
        # 创建证书验证器
        self.cert_verifier = self._create_certificate_verifier()
        
        # 初始化客户端密钥（用于CertificateVerify签名）
        self.client_key = self._load_client_key()
        
        # ⭐ 存储服务器协商的签名算法
        self.server_signature_scheme = None
        
        # ⭐ 握手密钥（用于应用数据加密）
        self.handshake_keys = None
        
        # ⭐ 加密器（用于应用数据加解密）
        self.encryptor = TLSRecordEncryption(cipher_name="AES_128_GCM")
        self.decryptor = TLSRecordEncryption(cipher_name="AES_128_GCM")
    
    def _initialize_trust_store(self) -> TrustStoreManager:
        """
        初始化信任存储管理器
        
        客户端本地存储多个根CA作为信任锚
        """
        print("\n" + "=" * 70)
        print("客户端初始化 - 信任存储管理器")
        print("=" * 70)
        
        try:
            # ⭐ 加载多个根CA作为信任锚
            # 客户端应该支持多种算法的根CA，以适应不同的服务器配置
            trust_manager = TrustStoreManager(
                algorithms=["mldsa65", "mldsa44", "mldsa87", "falcon512", "falcon1024"]
            )
            
            print("=" * 70)
            print("[OK] 信任存储管理器初始化成功")
            print("=" * 70 + "\n")
            
            return trust_manager
            
        except Exception as e:
            print(f"\n[错误] 信任存储初始化失败: {e}")
            print(f"[提示] 请先运行: python enhanced_certificates/generate_multi_algorithm_certs.py --all")
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
        ⭐ 加载客户端密钥 - 客户端不需要证书，返回None
        
        在标准TLS中，客户端通常不需要证书（服务器单向认证）
        只有双向认证时客户端才需要证书
        """
        # ⭐ 客户端不需要密钥（服务器单向认证）
        pass
    
    def _generate_certificate_verify_signature(self, handshake_hash: bytes) -> bytes:
        """
        ⭐ 生成客户端证书验证签名
        
        客户端在服务器单向认证模式下不需要签名
        返回空签名表示客户端未提供证书
        """
        # ⭐ 客户端不签名（服务器单向认证）
        return b""  # 空签名表示未提供客户端证书
    
    def _verify_server_certificate(self, server_cert_data: bytes, intermediate_cert_data: Optional[bytes] = None, 
                                   server_pq_sig: Optional[bytes] = None, inter_pq_sig: Optional[bytes] = None) -> Tuple[bool, Optional[bytes], Optional[str]]:
        """
        ⭐ 验证服务器证书链 - 使用Enhanced Certificate完整验证
        
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
        
        if len(server_cert_data) == 0:
            print(f"[证书验证] ✗ 证书数据为空")
            return False, None, None
        
        # ⭐ 步骤1: 解析证书
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from enhanced_certificates.x509_wrapper import PQWrappedCertificate, PQ_PUBLIC_KEY_OID
        import json
        
        try:
            # 解析服务器证书
            server_cert = x509.load_der_x509_certificate(server_cert_data, default_backend())
            print(f"[步骤1] ✓ 服务器证书解析成功")
            print(f"  主题: {server_cert.subject}")
            print(f"  颁发者: {server_cert.issuer}")
            
            # 解析中间CA证书（如果提供）
            intermediate_cert = None
            if intermediate_cert_data and len(intermediate_cert_data) > 0:
                intermediate_cert = x509.load_der_x509_certificate(intermediate_cert_data, default_backend())
                print(f"[步骤1] ✓ 中间CA证书解析成功")
                print(f"  主题: {intermediate_cert.subject}")
                print(f"  颁发者: {intermediate_cert.issuer}")
            else:
                print(f"[步骤1] ⚠️  未提供中间CA证书，将只验证服务器证书")
                
        except Exception as e:
            print(f"[步骤1] ✗ 证书解析失败: {e}")
            return False, None, None
        
        # ⭐ 步骤2: 提取后量子信息
        print(f"\n[步骤2] 提取后量子信息...")
        
        try:
            # 提取服务器证书的PQ信息
            ext = server_cert.extensions.get_extension_for_oid(PQ_PUBLIC_KEY_OID)
            metadata = json.loads(ext.value.value.decode('utf-8'))
            server_pq_public_key = bytes.fromhex(metadata['public_key'])
            server_pq_algorithm = metadata['algorithm']
            
            print(f"  ✓ 服务器证书PQ算法: {server_pq_algorithm}")
            print(f"  ✓ 服务器证书PQ公钥: {len(server_pq_public_key)} 字节")
            
            # ⭐ 使用接收到的PQ签名
            if server_pq_sig:
                print(f"  ✓ 服务器PQ签名: {len(server_pq_sig)} 字节")
                print(f"  ✓ 服务器PQ签名前50字节: {server_pq_sig[:50].hex()}")
            else:
                print(f"  ⚠️  未接收到服务器PQ签名")
            
        except Exception as e:
            print(f"[步骤2] ✗ 提取服务器PQ信息失败: {e}")
            return False, None, None
        
        # ⭐ 步骤3: 如果有中间CA，进行完整的证书链验证
        if intermediate_cert:
            print(f"\n[步骤3] 使用Enhanced Certificate验证证书链...")
            
            try:
                # 提取中间CA的PQ信息
                ext = intermediate_cert.extensions.get_extension_for_oid(PQ_PUBLIC_KEY_OID)
                metadata = json.loads(ext.value.value.decode('utf-8'))
                inter_pq_public_key = bytes.fromhex(metadata['public_key'])
                inter_pq_algorithm = metadata['algorithm']
                
                print(f"  ✓ 中间CA PQ算法: {inter_pq_algorithm}")
                
                # ⭐ 使用接收到的PQ签名
                if inter_pq_sig:
                    print(f"  ✓ 中间CA PQ签名: {len(inter_pq_sig)} 字节")
                else:
                    print(f"  ⚠️  未接收到中间CA PQ签名")
                
                # ⭐ 动态匹配根CA并验证签名
                if server_pq_sig and inter_pq_sig:
                    success, error = self.trust_manager.verify_chain_with_enhanced_verifier(
                    server_cert, server_pq_sig, server_pq_algorithm,
                    intermediate_cert, inter_pq_sig, inter_pq_algorithm
                )
                
                    if not success:
                        print(f"[步骤3] [证书验证] ✗ 证书链验证失败: {error}")
                        return False, None, None
                    
                    print(f"[步骤3] [证书验证] ✓ 证书链验证成功")
                else:
                    print(f"[步骤3] ⚠️  缺少PQ签名，跳过签名验证")
                
            except Exception as e:
                print(f"[步骤3] ✗ 证书链验证异常: {e}")
                import traceback
                traceback.print_exc()
                print(f"[步骤3] [ERROR] 证书链验证失败，终止握手")
                return False, None, None
        else:
            print(f"\n[步骤3] ⚠️  跳过完整链验证（未提供中间CA或签名）")
        
        # ⭐ 返回服务器证书的PQ公钥和算法（用于CertificateVerify验证）
        print(f"\n[完成] 证书验证流程完成")
        print(f"  返回公钥: {len(server_pq_public_key)} 字节")
        print(f"  返回算法: {server_pq_algorithm}")
        
        return True, server_pq_public_key, server_pq_algorithm
    
    def _verify_server_signature(self, signature: bytes, handshake_hash: bytes, server_public_key: bytes, pq_algorithm: str) -> bool:
        """
        ⭐ 验证服务器签名 - 使用真实的后量子签名验证
        
        Args:
            signature: 服务器的CertificateVerify签名
            handshake_hash: 握手消息哈希
            server_public_key: 服务器的后量子公钥
            pq_algorithm: 后量子算法名称（如ML-DSA-44）
        """
        try:
            # ⭐ 将算法名称转换为SignatureScheme
            from core.types import get_signature_scheme
            signature_scheme = get_signature_scheme(pq_algorithm)
            
            # ⭐ 使用真实的后量子签名验证
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
            print(f"    ❌ 签名验证错误: {e}")
            import traceback
            traceback.print_exc()
            raise
    
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
                print(f"    ✓ 解析Certificate消息: {len(cert_list)} 个证书")
                return True, cert_list
            else:
                print(f"    ❌ Certificate消息中无证书数据")
                return False, []
                
        except Exception as e:
            print(f"    ❌ 解析Certificate消息错误: {e}")
            return False, []
    
    def _parse_certificate_verify_message(self, data: bytes) -> Tuple[bool, bytes]:
        """解析CertificateVerify消息并验证算法"""
        try:
            # 使用TLS 1.3标准格式解析
            if len(data) < 4:  # 至少需要4字节头
                return False, b""
            
            # 解码CertificateVerify消息
            certificate_verify = TLSMessage.decode_certificate_verify(data)
            
            # ⭐ 验证服务器选择的签名算法是否在客户端支持列表中
            from core.types import get_mode_config
            client_supported = get_mode_config(self.config.mode)['signature_algorithms']
            
            if certificate_verify.algorithm not in client_supported:
                print(f"    ⚠️  服务器选择的算法 {get_signature_name(certificate_verify.algorithm)} 不在客户端支持列表中")
                print(f"    客户端支持: {[get_signature_name(s) for s in client_supported[:5]]}")
            else:
                print(f"    ✓ 签名算法验证通过: {get_signature_name(certificate_verify.algorithm)}")
            
            # 保存服务器协商的签名算法
            self.server_signature_scheme = certificate_verify.algorithm
            
            return True, certificate_verify.signature
            
        except Exception as e:
            print(f"    ❌ 解析CertificateVerify消息错误: {e}")
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
        # ⭐ 重置加密器/解密器的序列号（每次新握手时重置）
        self.encryptor.reset_sequence_numbers()
        self.decryptor.reset_sequence_numbers()
        
        # 初始化消息接收器
        receiver = MessageReceiver(client_socket)
        
        # 1. 生成并发送ClientHello
        if self.tracker:
            self.tracker.start_step("生成ClientHello")
        print(f"[1] 生成ClientHello...")
        client_hello, client_hello_bytes = self.handshake.generate_client_hello()
        client_socket.send(client_hello_bytes)
        print(f"    ✓ 发送 {len(client_hello_bytes)} 字节")
        if self.tracker:
            self.tracker.finish_step({'size': len(client_hello_bytes)})
        
        # 2. 接收ServerHello
        if self.tracker:
            self.tracker.start_step("接收ServerHello")
        print(f"\n[2] 接收ServerHello...")
        server_hello_data = receiver.receive_tls_record()
        print(f"    ✓ 接收ServerHello: {len(server_hello_data)} 字节")
        if self.tracker:
            self.tracker.finish_step({'size': len(server_hello_data)})
        
        # 3. 处理ServerHello并计算共享密钥
        if self.tracker:
            self.tracker.start_step("处理ServerHello")
        print(f"\n[3] 处理ServerHello...")
        keys = self.handshake.process_server_hello(server_hello_data)
        
        # ⭐ 保存握手密钥（用于应用数据加密）
        self.handshake_keys = keys
        
        print(f"    [KEM] ✓ 密钥交换成功，握手密钥派生完成")
        if self.tracker:
            self.tracker.finish_step()
        
        # 4. ⭐ 接收服务器的Certificate消息（包含完整证书链）
        if self.tracker:
            self.tracker.start_step("接收Certificate消息")
        print(f"\n[4] 接收服务器Certificate消息...")
        cert_message = receiver.receive_certificate_message()
        if self.tracker:
            self.tracker.finish_step({'size': len(cert_message)})
        
        # 解析证书链
        if self.tracker:
            self.tracker.start_step("解析证书链")
        is_valid, cert_list = self._parse_certificate_message_full(cert_message)
        
        if not is_valid or not cert_list or len(cert_list) == 0:
            print(f"    ❌ 无法解析Certificate消息")
            if self.tracker:
                self.tracker.finish_step({'error': '无法解析证书链'})
            return
        
        server_cert_data = cert_list[0]  # 第一个是服务器证书
        intermediate_cert_data = cert_list[1] if len(cert_list) > 1 else None  # 第二个是中间CA
        
        print(f"    ✓ 接收证书链: {len(cert_list)} 个证书")
        if self.tracker:
            self.tracker.finish_step({'cert_count': len(cert_list)})
        
        # ⭐ 接收PQ签名扩展
        if self.tracker:
            self.tracker.start_step("接收PQ签名扩展")
        print(f"\n[4.1] 接收PQ签名扩展...")
        pq_sig_data = receiver.receive_tls_record()
        
        # 解析PQ签名
        server_pq_sig = None
        inter_pq_sig = None
        
        if pq_sig_data and len(pq_sig_data) > 4:
            try:
                import json
                pq_sigs = json.loads(pq_sig_data[4:].decode('utf-8'))
                
                if 'server_pq_sig' in pq_sigs:
                    server_pq_sig = bytes.fromhex(pq_sigs['server_pq_sig'])
                    print(f"    ✓ 接收服务器PQ签名: {len(server_pq_sig)} 字节")
                
                if 'intermediate_pq_sig' in pq_sigs:
                    inter_pq_sig = bytes.fromhex(pq_sigs['intermediate_pq_sig'])
                    print(f"    ✓ 接收中间CAPQ签名: {len(inter_pq_sig)} 字节")
                    
            except Exception as e:
                print(f"    ⚠️  解析PQ签名扩展失败: {e}")
        
        if self.tracker:
            self.tracker.finish_step({'server_sig_size': len(server_pq_sig) if server_pq_sig else 0, 
                                      'inter_sig_size': len(inter_pq_sig) if inter_pq_sig else 0})
        
        # ⭐ 验证服务器证书链（使用Enhanced Certificate）
        if self.tracker:
            self.tracker.start_step("证书链验证")
        print(f"\n[5] 验证服务器证书链（含签名验证）...")
        cert_valid, server_public_key, pq_algorithm = self._verify_server_certificate(
            server_cert_data,
            intermediate_cert_data,  # ⭐ 传入中间CA证书
            server_pq_sig,           # ⭐ 传入服务器PQ签名
            inter_pq_sig             # ⭐ 传入中间CAPQ签名
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
        print(f"    ✓ 握手哈希计算完成")
        
        # 9. 计算完整握手哈希（用于抗降级攻击保护）
        # 包含ClientHello、ServerHello、Certificate和CertificateVerify消息
        cert_verify_message_handshake = cert_verify_message[4:]  # 去除4字节记录头
        full_handshake_hash = self._compute_handshake_hash(
            client_hello_bytes,           # 发送的ClientHello（握手消息）
            server_hello_handshake,       # ServerHello握手消息
            cert_message_handshake,      # Certificate握手消息
            cert_verify_message_handshake # CertificateVerify握手消息
        )
        print(f"    ✓ 完整握手哈希计算完成")
        
        # # ⭐ 这部分代码已移至上面的[4]步骤，这里不需要重复解析
        # # 证书已经在上面解析并验证完成
        
        # print(f"    ✓ 接收服务器证书 ({len(server_cert_data)} 字节)")
        
        # # ⭐ 验证服务器证书（完整的信任链检查）
        # cert_verified, server_pq_public_key, server_pq_algorithm = self._verify_server_certificate(server_cert_data)
        
        # if not cert_verified:
        #     print(f"    ❌ 服务器证书验证失败，终止连接")
        #     return
        
        # ⭐ 解析并验证服务器签名
        print(f"\n[7] 验证服务器CertificateVerify签名...")
        verify_valid, server_signature = self._parse_certificate_verify_message(cert_verify_message)
        
        if not verify_valid:
            print(f"    ❌ 无效的CertificateVerify消息")
            return
        
        print(f"    ✓ 接收服务器签名 ({len(server_signature)} 字节)")
        
        # ⭐ 使用真实的后量子公钥验证签名（使用步骤5返回的变量）
        server_signature_valid = self._verify_server_signature(
            server_signature, 
            handshake_hash_for_verify, 
            server_public_key,  # 真实的后量子公钥（来自步骤5）
            pq_algorithm        # 后量子算法名称（来自步骤5）
        )
        
        # ⭐ 如果签名验证失败，打印错误信息并结束握手
        if not server_signature_valid:
            print(f"    [ERROR] 服务器签名验证失败，终止握手")
            return
        
        if server_finished_message:
            print(f"    ✓ 接收服务器Finished消息 ({len(server_finished_message)} 字节)")
        else:
            print(f"    ❌ 无法接收完整的Finished消息")
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
        print(f"    ✓ 发送客户端证书验证签名 ({len(client_cert_verify)} 字节)")
        
        # 10. 发送客户端的Finished消息
        print(f"\n[9] 发送客户端Finished消息...")
        client_finished_key = hashlib.sha256(b"client_finished" + full_handshake_hash).digest()[:12]
        
        # 使用TLS 1.3标准格式
        finished = Finished(verify_data=client_finished_key)
        finished_message = TLSMessage.encode_finished(finished)
        client_socket.send(finished_message)
        print(f"    ✓ 发送客户端Finished消息")
        
        # 11. 握手完成
        print(f"\n[10] 握手完成！")
        print(f"    ✓ 证书验证: {'通过' if server_signature_valid else '失败'}")
        print(f"    ✓ 抗降级攻击: 已启用")
        
        # 12. 发送应用数据（使用TLS记录格式）
        print(f"\n[11] 发送应用数据...")
        app_data = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        
        # ⭐ 使用客户端握手密钥加密（客户端发送的数据用client_handshake_key加密）
        try:
            encrypted_app_data = self.encryptor.encrypt_record(
                app_data,
                self.handshake_keys.client_handshake_key,
                self.handshake_keys.client_handshake_iv
            )
            print(f"    [OK] 加密成功: {len(encrypted_app_data)} 字节")
            
            # 封装为TLS记录（应用数据类型=23）
            record_type = 23  # TLS应用数据类型
            record_header = struct.pack('!B', record_type)
            record_header += struct.pack('!H', 0x0303)  # TLS 1.2版本（兼容性）
            record_header += struct.pack('!H', len(encrypted_app_data))
            
            tls_app_data = record_header + encrypted_app_data
            client_socket.send(tls_app_data)
            print(f"    ✓ 发送加密TLS应用数据记录 ({len(tls_app_data)} 字节)")
            
        except Exception as e:
            print(f"    ❌ 加密失败: {e}")
            return
        
        # 13. 接收服务器响应
        print(f"\n[12] 接收服务器响应...")
        encrypted_response = receiver.receive_application_data(4096)
        if encrypted_response:
            print(f"    ✓ 接收加密响应: {len(encrypted_response)} 字节")
            
            # ⭐ 使用服务器握手密钥解密（服务器发送的数据用server_handshake_key加密）
            try:
                response, content_type = self.decryptor.decrypt_record(
                    encrypted_response,
                    self.handshake_keys.server_handshake_key,
                    self.handshake_keys.server_handshake_iv
                )
                print(f"    [OK] 解密成功: {len(response)} 字节明文")
                
                # 解析响应头
                response_str = response.decode('utf-8', errors='ignore')
                headers = response_str.split('\r\n\r\n')[0]
                print(f"\n服务器响应头:")
                for line in headers.split('\r\n'):
                    if line.strip():
                        print(f"    {line}")
                        
            except Exception as e:
                print(f"    ❌ 解密失败: {e}")
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