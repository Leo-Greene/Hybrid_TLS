"""TLS 1.3握手逻辑"""

import os
import hashlib
import hmac
from typing import Optional, Dict, Tuple
import socket

from ..types import (
    ClientHello, ServerHello, KeyShareEntry,
    NamedGroup, CipherSuite, SignatureScheme, TLSMode,
    get_mode_config, get_group_name
)
from ..crypto.key_exchange import create_key_exchange, KeyExchange
from ..crypto.signature import create_signature
from .messages import encode_client_hello, encode_server_hello, decode_client_hello, decode_server_hello


class HandshakeKeys:
    """握手密钥"""
    def __init__(self):
        self.client_handshake_key = None
        self.server_handshake_key = None
        self.client_handshake_iv = None
        self.server_handshake_iv = None
        self.shared_secret = None


def derive_handshake_keys(
    shared_secret: bytes,
    client_random: bytes,
    server_random: bytes
) -> HandshakeKeys:
    """从共享密钥派生握手密钥（简化版HKDF）"""
    keys = HandshakeKeys()
    keys.shared_secret = shared_secret
    
    # 组合随机数
    context = client_random + server_random
    
    # 派生客户端密钥
    keys.client_handshake_key = hashlib.sha256(
        b"client_key_" + shared_secret + context
    ).digest()[:16]  # AES-128需要16字节
    
    keys.client_handshake_iv = hashlib.sha256(
        b"client_iv_" + shared_secret + context
    ).digest()[:12]  # GCM需要12字节
    
    # 派生服务器密钥
    keys.server_handshake_key = hashlib.sha256(
        b"server_key_" + shared_secret + context
    ).digest()[:16]
    
    keys.server_handshake_iv = hashlib.sha256(
        b"server_iv_" + shared_secret + context
    ).digest()[:12]
    
    return keys


class ClientHandshake:
    """客户端握手处理"""

    def __init__(self, mode: TLSMode = TLSMode.HYBRID, selected_kem: Optional[NamedGroup] = None):
        self.mode = mode
        self.config = get_mode_config(mode)
        self.key_exchanges: Dict[NamedGroup, KeyExchange] = {}
        self.client_random = None
        self.server_random = None
        self.handshake_keys: Optional[HandshakeKeys] = None
        self.selected_kem = selected_kem  # 选定的主要KEM

        # 如果指定了selected_kem，只保留该KEM作为主要支持组
        if selected_kem:
            self.config = self.config.copy()
            # 只保留选定的KEM和经典回退选项
            fallback_groups = []
            if mode == TLSMode.HYBRID:
                fallback_groups = [NamedGroup.x25519, NamedGroup.secp256r1]
            elif mode == TLSMode.PQC:
                fallback_groups = []

            self.config['supported_groups'] = [selected_kem] + fallback_groups
    
    def generate_client_hello(self) -> Tuple[ClientHello, bytes]:
        """生成ClientHello消息
        
        Returns:
            (ClientHello对象, 编码后的字节)
        """
        # 生成随机数
        self.client_random = os.urandom(32)
        
        # 只为支持的组生成密钥对（避免消息过大）
        key_shares = []
        for group in self.config['supported_groups']:
            kex = create_key_exchange(group, is_server=False)
            kex.generate_keypair()
            self.key_exchanges[group] = kex

            key_shares.append(KeyShareEntry(
                group=group,
                key_exchange=kex.get_public_key()
            ))
        
        # 构建ClientHello
        client_hello = ClientHello(
            random=self.client_random,
            cipher_suites=self.config['cipher_suites'],
            key_shares=key_shares,
            supported_groups=self.config['supported_groups'],
            signature_algorithms=self.config['signature_algorithms'],
        )
        
        # 编码
        encoded = encode_client_hello(client_hello)
        
        return client_hello, encoded
    
    def process_server_hello(
        self,
        server_hello_data: bytes
    ) -> HandshakeKeys:
        """处理ServerHello并计算共享密钥
        
        Args:
            server_hello_data: ServerHello消息字节
        
        Returns:
            握手密钥
        """
        # 解码ServerHello
        server_hello = decode_server_hello(server_hello_data)
        self.server_random = server_hello.random
        
        # 获取服务器选择的组
        selected_group = server_hello.key_share.group
        server_key_share = server_hello.key_share.key_exchange
        
        # 使用对应的密钥交换计算共享密钥
        if selected_group not in self.key_exchanges:
            raise ValueError(f"Server selected unsupported group: {selected_group}")
        
        kex = self.key_exchanges[selected_group]
        shared_secret = kex.compute_shared_secret(server_key_share)
        
        # 派生握手密钥
        self.handshake_keys = derive_handshake_keys(
            shared_secret,
            self.client_random,
            self.server_random
        )
        
        return self.handshake_keys


class ServerHandshake:
    """服务器握手处理"""
    
    def __init__(self, mode: TLSMode = TLSMode.HYBRID):
        self.mode = mode
        self.config = get_mode_config(mode)
        self.client_random = None
        self.server_random = None
        self.selected_group: Optional[NamedGroup] = None
        self.handshake_keys: Optional[HandshakeKeys] = None
    
    def process_client_hello(
        self,
        client_hello_data: bytes
    ) -> Tuple[ServerHello, bytes, HandshakeKeys]:
        """处理ClientHello并生成ServerHello
        
        Args:
            client_hello_data: ClientHello消息字节
        
        Returns:
            (ServerHello对象, 编码后的字节, 握手密钥)
        """
        # 解码ClientHello
        client_hello = decode_client_hello(client_hello_data)
        self.client_random = client_hello.random
        
        # 选择密钥交换算法（优先选择第一个匹配的）
        selected_group = None
        for group in self.config['supported_groups']:
            if group in client_hello.supported_groups:
                selected_group = group
                break
        
        if selected_group is None:
            raise ValueError("No common supported group")
        
        self.selected_group = selected_group
        
        # 查找客户端对应的key_share
        client_key_share = None
        for ks in client_hello.key_shares:
            if ks.group == selected_group:
                client_key_share = ks.key_exchange
                break
        
        if client_key_share is None:
            raise ValueError(f"Client did not provide key_share for {selected_group}")
        
        # 执行服务器端密钥交换
        server_kex = create_key_exchange(selected_group, is_server=True)
        server_kex.generate_keypair()
        
        shared_secret = server_kex.compute_shared_secret(client_key_share)
        server_key_share = server_kex.get_public_key()
        
        # 生成服务器随机数
        self.server_random = os.urandom(32)
        
        # 选择加密套件（使用第一个匹配的）
        selected_cipher = None
        for cipher in self.config['cipher_suites']:
            if cipher in client_hello.cipher_suites:
                selected_cipher = cipher
                break
        
        if selected_cipher is None:
            selected_cipher = self.config['cipher_suites'][0]
        
        # 构建ServerHello
        server_hello = ServerHello(
            random=self.server_random,
            cipher_suite=selected_cipher,
            key_share=KeyShareEntry(
                group=selected_group,
                key_exchange=server_key_share
            )
        )
        
        # 编码
        encoded = encode_server_hello(server_hello)
        
        # 派生握手密钥
        self.handshake_keys = derive_handshake_keys(
            shared_secret,
            self.client_random,
            self.server_random
        )
        
        return server_hello, encoded, self.handshake_keys


def compute_finished_mac(
    base_key: bytes,
    handshake_messages: bytes
) -> bytes:
    """计算Finished消息的MAC
    
    Args:
        base_key: 握手流量密钥
        handshake_messages: 所有握手消息的拼接
    
    Returns:
        verify_data (32字节)
    """
    # 派生finished密钥
    finished_key = hashlib.sha256(b"finished_" + base_key).digest()
    
    # 计算握手消息的哈希
    transcript_hash = hashlib.sha256(handshake_messages).digest()
    
    # HMAC
    verify_data = hmac.new(finished_key, transcript_hash, hashlib.sha256).digest()
    
    return verify_data


def compute_handshake_hash(
    client_hello: bytes,
    server_hello: bytes,
    certificate: bytes = None,
    certificate_verify: bytes = None
) -> bytes:
    """计算握手消息的哈希值（基于TLS 1.3标准）
    
    Args:
        client_hello: ClientHello消息字节
        server_hello: ServerHello消息字节
        certificate: Certificate消息字节（可选）
        certificate_verify: CertificateVerify消息字节（可选）
    
    Returns:
        握手哈希值（32字节）
    """
    # TLS 1.3标准：握手哈希包含所有握手消息
    handshake_context = client_hello + server_hello
    
    # 如果提供了证书和证书验证消息，则包含它们
    if certificate:
        handshake_context += certificate
    if certificate_verify:
        handshake_context += certificate_verify
    
    # 使用SHA-256计算哈希（TLS 1.3标准）
    return hashlib.sha256(handshake_context).digest()


def generate_certificate_verify_signature(
    handshake_hash: bytes,
    private_key: bytes = None,
    signature_scheme: SignatureScheme = None,
    signer_object = None
) -> bytes:
    """
    ⭐ 生成证书验证签名 - 使用真实的后量子签名算法
    
    Args:
        handshake_hash: 握手消息哈希
        private_key: 私钥数据（后量子私钥字节）
        signature_scheme: 签名算法
        signer_object: 预先初始化的签名器对象（推荐使用）
    
    Returns:
        真实的后量子签名数据
    """
    # ⭐ 如果提供了签名器对象，直接使用（这是最准确的方式）
    if signer_object:
        signature = signer_object.sign(handshake_hash)
        return signature
    
    # ⭐ 如果提供了私钥，使用真实的签名算法
    if private_key and signature_scheme:
        from ..crypto.signature import create_signature
        
        signer = create_signature(signature_scheme)
        signer.set_private_key(private_key)
        signature = signer.sign(handshake_hash)
        
        return signature
    
    # ⭐ 如果都没提供，报错而不是使用模拟
    raise ValueError("必须提供 signer_object 或 (private_key + signature_scheme)，不允许使用模拟签名")


def verify_certificate_signature(
    signature: bytes,
    handshake_hash: bytes,
    public_key: bytes,
    signature_scheme: SignatureScheme
) -> bool:
    """
    ⭐ 验证证书签名 - 使用真实的后量子签名验证
    
    Args:
        signature: 待验证的签名（必须提供）
        handshake_hash: 握手消息哈希
        public_key: 公钥（必须提供，用于验证）
        signature_scheme: 签名算法（必须提供）
    
    Returns:
        验证结果（True/False）
    """
    # ⭐ 使用真实的签名验证实现
    from ..crypto.signature import create_signature
    
    try:
        # 创建验证器
        verifier = create_signature(signature_scheme)
        
        # ⭐ 执行真实的签名验证（后量子算法）
        is_valid = verifier.verify(handshake_hash, signature, public_key)
        
        return is_valid
        
    except Exception as e:
        raise  # 不要隐藏错误，直接抛出


def verify_server_signature(
    signature: bytes,
    handshake_hash: bytes,
    server_public_key: bytes,
    signature_scheme: SignatureScheme
) -> bool:
    """验证服务器签名（基于TLS 1.3标准）
    
    Args:
        signature: 服务器签名
        handshake_hash: 握手消息哈希
        server_public_key: 服务器公钥
        signature_scheme: 签名算法
    
    Returns:
        验证结果
    """
    # 使用core模块中的标准签名验证逻辑
    return verify_certificate_signature(
        signature=signature,
        handshake_hash=handshake_hash,
        public_key=server_public_key,
        signature_scheme=signature_scheme
    )



def test_handshake():
    """测试握手逻辑"""
    print("测试TLS握手逻辑\n")
    
    # 客户端
    client = ClientHandshake(mode=TLSMode.HYBRID)
    client_hello, client_hello_bytes = client.generate_client_hello()
    print(f"ClientHello大小: {len(client_hello_bytes)} 字节")
    
    # 服务器
    server = ServerHandshake(mode=TLSMode.HYBRID)
    server_hello, server_hello_bytes, server_keys = server.process_client_hello(client_hello_bytes)
    print(f"ServerHello大小: {len(server_hello_bytes)} 字节")
    
    # 客户端处理
    client_keys = client.process_server_hello(server_hello_bytes)
    
    # 验证
    if client_keys.shared_secret == server_keys.shared_secret:
        print("[OK] 握手成功！共享密钥一致")
    else:
        print("❌ 握手失败！共享密钥不匹配")
    
    print()


if __name__ == '__main__':
    test_handshake()

