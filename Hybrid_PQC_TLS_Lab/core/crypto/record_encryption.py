#!/usr/bin/env python3
"""TLS 1.3 记录层加密/解密模块

实现符合TLS 1.3标准的AEAD加密，用于保护应用数据和握手后消息。
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from typing import Tuple
import struct


class TLSRecordEncryption:
    """TLS 1.3记录层加密/解密
    
    支持的密码套件：
    - AES-128-GCM (默认)
    - ChaCha20-Poly1305
    
    特性：
    - AEAD认证加密
    - 序列号保护（防重放攻击）
    - 符合TLS 1.3 RFC 8446标准
    """
    
    def __init__(self, cipher_name: str = "AES_128_GCM"):
        """
        初始化加密器
        
        Args:
            cipher_name: 加密算法名称
                - "AES_128_GCM": AES-128-GCM (默认)
                - "CHACHA20_POLY1305": ChaCha20-Poly1305
        """
        self.cipher_name = cipher_name
        self.seq_num_send = 0  # 发送序列号
        self.seq_num_recv = 0  # 接收序列号
    
    def _construct_nonce(self, iv: bytes, seq_num: int) -> bytes:
        """
        构造AEAD nonce (符合TLS 1.3标准)
        
        TLS 1.3标准：nonce = iv XOR (padding || seq_num)
        
        Args:
            iv: 初始化向量 (12字节)
            seq_num: 序列号 (递增计数器)
            
        Returns:
            12字节nonce
            
        Reference:
            RFC 8446 Section 5.3: Per-Record Nonce
        """
        # 将序列号编码为8字节大端序
        seq_bytes = struct.pack('>Q', seq_num)
        
        # 补齐到12字节 (前4字节为0)
        padded_seq = b'\x00' * 4 + seq_bytes
        
        # XOR运算
        nonce = bytes(a ^ b for a, b in zip(iv, padded_seq))
        
        return nonce
    
    def encrypt_record(
        self,
        plaintext: bytes,
        key: bytes,
        iv: bytes,
        content_type: int = 23  # 应用数据类型
    ) -> bytes:
        """
        加密TLS记录 (AEAD加密)
        
        TLS 1.3加密格式：
        1. 构造明文：plaintext || content_type || zeros (可选padding)
        2. AEAD加密：ciphertext = AEAD-Encrypt(key, nonce, plaintext)
        3. 自动添加认证标签（16字节）
        
        Args:
            plaintext: 明文数据
            key: 加密密钥 (16字节用于AES-128-GCM, 32字节用于ChaCha20)
            iv: 初始化向量 (12字节)
            content_type: 内容类型 (23=应用数据, 22=握手消息)
            
        Returns:
            加密后的记录数据 (包含16字节认证标签)
            
        Reference:
            RFC 8446 Section 5.2: Record Payload Protection
        """
        # 构造nonce
        nonce = self._construct_nonce(iv, self.seq_num_send)
        
        # TLS 1.3: plaintext后面追加content_type (1字节)
        plaintext_with_type = plaintext + bytes([content_type])
        
        # 执行AEAD加密
        if self.cipher_name == "AES_128_GCM":
            aesgcm = AESGCM(key)
            # additional_data为空（TLS 1.3标准）
            ciphertext = aesgcm.encrypt(nonce, plaintext_with_type, b"")
        elif self.cipher_name == "CHACHA20_POLY1305":
            chacha = ChaCha20Poly1305(key)
            ciphertext = chacha.encrypt(nonce, plaintext_with_type, b"")
        else:
            raise ValueError(f"Unsupported cipher: {self.cipher_name}")
        
        # 增加序列号（每条记录递增）
        self.seq_num_send += 1
        
        return ciphertext
    
    def decrypt_record(
        self,
        ciphertext: bytes,
        key: bytes,
        iv: bytes
    ) -> Tuple[bytes, int]:
        """
        解密TLS记录 (AEAD解密)
        
        TLS 1.3解密流程：
        1. 验证认证标签（AEAD自动验证）
        2. 解密得到：plaintext || content_type
        3. 提取content_type并返回明文
        
        Args:
            ciphertext: 密文数据 (包含16字节认证标签)
            key: 解密密钥
            iv: 初始化向量
            
        Returns:
            (明文数据, 内容类型)
            
        Raises:
            Exception: 解密失败或认证失败（数据被篡改）
            
        Reference:
            RFC 8446 Section 5.2: Record Payload Protection
        """
        # 构造nonce（与发送方使用相同序列号）
        nonce = self._construct_nonce(iv, self.seq_num_recv)
        
        # 执行AEAD解密（自动验证认证标签）
        try:
            if self.cipher_name == "AES_128_GCM":
                aesgcm = AESGCM(key)
                plaintext_with_type = aesgcm.decrypt(nonce, ciphertext, b"")
            elif self.cipher_name == "CHACHA20_POLY1305":
                chacha = ChaCha20Poly1305(key)
                plaintext_with_type = chacha.decrypt(nonce, ciphertext, b"")
            else:
                raise ValueError(f"Unsupported cipher: {self.cipher_name}")
            
            # 增加序列号
            self.seq_num_recv += 1
            
            # 提取content_type (最后一个字节)
            if len(plaintext_with_type) < 1:
                raise ValueError("Invalid plaintext length")
            
            content_type = plaintext_with_type[-1]
            plaintext = plaintext_with_type[:-1]
            
            return plaintext, content_type
            
        except Exception as e:
            raise Exception(f"TLS记录解密失败: {e}")
    
    def reset_sequence_numbers(self):
        """重置序列号（用于测试或密钥更新）"""
        self.seq_num_send = 0
        self.seq_num_recv = 0


def encrypt_application_data(
    data: bytes,
    key: bytes,
    iv: bytes,
    seq_num: int = 0,
    cipher_name: str = "AES_128_GCM"
) -> bytes:
    """
    简化接口：加密应用数据（单次使用）
    
    Args:
        data: 要加密的数据
        key: 加密密钥
        iv: 初始化向量
        seq_num: 序列号
        cipher_name: 加密算法
        
    Returns:
        加密后的数据（包含认证标签）
    """
    encryptor = TLSRecordEncryption(cipher_name)
    encryptor.seq_num_send = seq_num
    return encryptor.encrypt_record(data, key, iv)


def decrypt_application_data(
    ciphertext: bytes,
    key: bytes,
    iv: bytes,
    seq_num: int = 0,
    cipher_name: str = "AES_128_GCM"
) -> Tuple[bytes, int]:
    """
    简化接口：解密应用数据（单次使用）
    
    Args:
        ciphertext: 密文（包含认证标签）
        key: 解密密钥
        iv: 初始化向量
        seq_num: 序列号
        cipher_name: 加密算法
        
    Returns:
        (明文数据, 内容类型)
        
    Raises:
        Exception: 解密失败或认证失败
    """
    decryptor = TLSRecordEncryption(cipher_name)
    decryptor.seq_num_recv = seq_num
    return decryptor.decrypt_record(ciphertext, key, iv)


def test_record_encryption():
    """测试TLS记录加密/解密功能"""
    print("🧪 测试TLS 1.3记录层加密/解密\n")
    
    # 生成测试密钥和IV
    import os
    test_key = os.urandom(16)  # AES-128
    test_iv = os.urandom(12)   # GCM标准IV长度
    
    # 测试数据
    test_data = b"Hello, TLS 1.3 with Post-Quantum Cryptography!"
    
    print(f"明文: {test_data}")
    print(f"明文长度: {len(test_data)} 字节")
    print(f"密钥: {test_key.hex()}")
    print(f"IV: {test_iv.hex()}\n")
    
    # 测试AES-128-GCM
    print("=" * 70)
    print("测试 AES-128-GCM")
    print("=" * 70)
    
    encryptor = TLSRecordEncryption("AES_128_GCM")
    ciphertext = encryptor.encrypt_record(test_data, test_key, test_iv)
    print(f"✓ 加密成功")
    print(f"密文长度: {len(ciphertext)} 字节 (包含16字节认证标签)")
    print(f"密文前32字节: {ciphertext[:32].hex()}\n")
    
    decryptor = TLSRecordEncryption("AES_128_GCM")
    plaintext, content_type = decryptor.decrypt_record(ciphertext, test_key, test_iv)
    print(f"✓ 解密成功")
    print(f"明文: {plaintext}")
    print(f"内容类型: {content_type}")
    
    # 验证
    if plaintext == test_data and content_type == 23:
        print("[OK] AES-128-GCM 测试通过！\n")
    else:
        print("❌ AES-128-GCM 测试失败！\n")
        return False
    
    # 测试序列号递增
    print("=" * 70)
    print("测试序列号递增（防重放攻击）")
    print("=" * 70)
    
    enc = TLSRecordEncryption("AES_128_GCM")
    dec = TLSRecordEncryption("AES_128_GCM")
    
    for i in range(3):
        ct = enc.encrypt_record(f"Message {i}".encode(), test_key, test_iv)
        pt, _ = dec.decrypt_record(ct, test_key, test_iv)
        print(f"消息 {i}: {pt.decode()} (序列号: {i})")
    
    print("[OK] 序列号测试通过！\n")
    
    # 测试认证失败
    print("=" * 70)
    print("测试认证失败检测（篡改检测）")
    print("=" * 70)
    
    enc2 = TLSRecordEncryption("AES_128_GCM")
    ct = enc2.encrypt_record(b"Original message", test_key, test_iv)
    
    # 篡改密文
    tampered_ct = bytearray(ct)
    tampered_ct[0] ^= 0xFF
    
    try:
        dec2 = TLSRecordEncryption("AES_128_GCM")
        dec2.decrypt_record(bytes(tampered_ct), test_key, test_iv)
        print("❌ 未检测到篡改！")
        return False
    except Exception:
        print("[OK] 成功检测到数据篡改！\n")
    
    print("=" * 70)
    print("[OK] 所有测试通过！")
    print("=" * 70)
    return True


if __name__ == '__main__':
    test_record_encryption()

