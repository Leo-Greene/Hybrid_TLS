"""TLS消息编解码"""

import struct
import json
from typing import Dict, Any, List
from ..types import (
    ClientHello, ServerHello, Certificate, CertificateVerify, Finished,
    NamedGroup, CipherSuite, SignatureScheme, HandshakeType, KeyShareEntry
)


class TLSMessage:
    """TLS消息编解码器（简化实现）"""
    
    @staticmethod
    def encode_client_hello(ch: ClientHello) -> bytes:
        """编码ClientHello消息"""
        # 验证random字段格式
        if len(ch.random) != 32:
            raise ValueError(f"random字段长度异常: {len(ch.random)} (期望32)")
        
        # 确保hex转换的一致性
        random_hex = ch.random.hex()
        if len(random_hex) != 64:
            raise ValueError(f"random hex长度异常: {len(random_hex)} (期望64)")
        
        data = {
            'msg_type': HandshakeType.client_hello,
            'random': random_hex,
            'cipher_suites': [cs.value for cs in ch.cipher_suites],
            'key_shares': [
                {
                    'group': ks.group.value,
                    'key_exchange': ks.key_exchange.hex()
                }
                for ks in ch.key_shares
            ],
            'supported_groups': [g.value for g in ch.supported_groups],
            'signature_algorithms': [s.value for s in ch.signature_algorithms],
        }
        
        if ch.server_name:
            data['server_name'] = ch.server_name
        if ch.alpn_protocols:
            data['alpn_protocols'] = ch.alpn_protocols
        
        # 增强JSON编码的稳定性
        try:
            json_str = json.dumps(data, ensure_ascii=False)
            json_data = json_str.encode('utf-8')
        except Exception as e:
            print(f"[ERROR] ClientHello编码失败: {e}")
            raise
        
        # TLS记录格式：类型(1) + 长度(3) + 数据
        msg = struct.pack('!B', 22)  # 握手消息
        msg += struct.pack('!I', len(json_data))[1:]  # 3字节长度
        msg += json_data
        
        return msg
    
    @staticmethod
    def decode_client_hello(data: bytes) -> ClientHello:
        """解码ClientHello消息"""
        # 跳过TLS记录头（4字节）
        json_data = data[4:]
        
        # 增强错误处理和调试信息
        try:
            json_str = json_data.decode('utf-8')
            msg_dict = json.loads(json_str)
            
            # 验证random字段的hex字符串格式
            random_hex = msg_dict['random']
            if not isinstance(random_hex, str):
                raise ValueError(f"random字段不是字符串类型: {type(random_hex)}")
            
            # 确保hex字符串长度为64（32字节）
            if len(random_hex) != 64:
                raise ValueError(f"random字段hex长度异常: {len(random_hex)} (期望64)")
            
            # 验证hex字符串格式
            if not all(c in '0123456789abcdef' for c in random_hex.lower()):
                raise ValueError(f"random字段包含非法字符: {random_hex}")
            
            random_bytes = bytes.fromhex(random_hex)
            
            # 验证转换后的字节长度
            if len(random_bytes) != 32:
                raise ValueError(f"random字节长度异常: {len(random_bytes)} (期望32)")
                
        except Exception as e:
            print(f"[ERROR] ClientHello解码失败: {e}")
            print(f"[DEBUG] JSON数据: {json_data[:200]}")
            raise
        
        return ClientHello(
            random=random_bytes,
            cipher_suites=[CipherSuite(cs) for cs in msg_dict['cipher_suites']],
            key_shares=[
                KeyShareEntry(
                    group=NamedGroup(ks['group']),
                    key_exchange=bytes.fromhex(ks['key_exchange'])
                )
                for ks in msg_dict['key_shares']
            ],
            supported_groups=[NamedGroup(g) for g in msg_dict['supported_groups']],
            signature_algorithms=[SignatureScheme(s) for s in msg_dict['signature_algorithms']],
            server_name=msg_dict.get('server_name'),
            alpn_protocols=msg_dict.get('alpn_protocols'),
        )
    
    @staticmethod
    def encode_server_hello(sh: ServerHello) -> bytes:
        """编码ServerHello消息"""
        data = {
            'msg_type': HandshakeType.server_hello,
            'random': sh.random.hex(),
            'cipher_suite': sh.cipher_suite.value,
            'key_share': {
                'group': sh.key_share.group.value,
                'key_exchange': sh.key_share.key_exchange.hex()
            }
        }
        
        json_data = json.dumps(data).encode('utf-8')
        
        msg = struct.pack('!B', 22)
        msg += struct.pack('!I', len(json_data))[1:]
        msg += json_data
        
        return msg
    
    @staticmethod
    def decode_server_hello(data: bytes) -> ServerHello:
        """解码ServerHello消息"""
        json_data = data[4:]
        msg_dict = json.loads(json_data.decode('utf-8'))
        
        return ServerHello(
            random=bytes.fromhex(msg_dict['random']),
            cipher_suite=CipherSuite(msg_dict['cipher_suite']),
            key_share=KeyShareEntry(
                group=NamedGroup(msg_dict['key_share']['group']),
                key_exchange=bytes.fromhex(msg_dict['key_share']['key_exchange'])
            )
        )
    
    @staticmethod
    def encode_certificate(cert: Certificate) -> bytes:
        """编码Certificate消息"""
        data = {
            'msg_type': HandshakeType.certificate,
            'certificate_list': [cert.hex() for cert in cert.certificate_list]
        }
        
        json_data = json.dumps(data).encode('utf-8')
        
        msg = struct.pack('!B', 22)
        msg += struct.pack('!I', len(json_data))[1:]
        msg += json_data
        
        return msg
    
    @staticmethod
    def encode_certificate_verify(cv: CertificateVerify) -> bytes:
        """编码CertificateVerify消息"""
        data = {
            'msg_type': HandshakeType.certificate_verify,
            'algorithm': cv.algorithm.value,
            'signature': cv.signature.hex()
        }
        
        json_data = json.dumps(data).encode('utf-8')
        
        msg = struct.pack('!B', 22)
        msg += struct.pack('!I', len(json_data))[1:]
        msg += json_data
        
        return msg
    
    @staticmethod
    def encode_finished(finished: Finished) -> bytes:
        """编码Finished消息"""
        data = {
            'msg_type': HandshakeType.finished,
            'verify_data': finished.verify_data.hex()
        }
        
        json_data = json.dumps(data).encode('utf-8')
        
        msg = struct.pack('!B', 22)
        msg += struct.pack('!I', len(json_data))[1:]
        msg += json_data
        
        return msg

    @staticmethod
    def decode_certificate(data: bytes) -> Certificate:
        """解码Certificate消息"""
        # 跳过TLS记录头（4字节）
        json_data = data[4:]
        msg_dict = json.loads(json_data.decode('utf-8'))
        
        return Certificate(
            certificate_list=[bytes.fromhex(cert) for cert in msg_dict['certificate_list']]
        )

    @staticmethod
    def decode_certificate_verify(data: bytes) -> CertificateVerify:
        """解码CertificateVerify消息"""
        # 跳过TLS记录头（4字节）
        if len(data) < 4:
            raise ValueError(f"CertificateVerify消息太短: {len(data)} 字节")
        
        json_data = data[4:]
        try:
            msg_dict = json.loads(json_data.decode('utf-8'))
        except json.JSONDecodeError as e:
            raise ValueError(f"CertificateVerify消息JSON解析失败: {e}, 数据: {json_data[:100]}")
        
        # 检查必需字段
        if 'algorithm' not in msg_dict:
            raise KeyError(f"CertificateVerify消息缺少'algorithm'字段，可用字段: {list(msg_dict.keys())}")
        if 'signature' not in msg_dict:
            raise KeyError(f"CertificateVerify消息缺少'signature'字段，可用字段: {list(msg_dict.keys())}")
        
        try:
            algorithm = SignatureScheme(msg_dict['algorithm'])
        except (ValueError, KeyError) as e:
            raise ValueError(f"无效的签名算法值: {msg_dict.get('algorithm')}, 错误: {e}")
        
        try:
            signature = bytes.fromhex(msg_dict['signature'])
        except (ValueError, KeyError) as e:
            raise ValueError(f"无效的签名数据: {e}")
        
        return CertificateVerify(
            algorithm=algorithm,
            signature=signature
        )

    @staticmethod
    def decode_finished(data: bytes) -> Finished:
        """解码Finished消息"""
        # 跳过TLS记录头（4字节）
        json_data = data[4:]
        msg_dict = json.loads(json_data.decode('utf-8'))
        
        return Finished(
            verify_data=bytes.fromhex(msg_dict['verify_data'])
        )


# 便捷函数
def encode_client_hello(ch: ClientHello) -> bytes:
    return TLSMessage.encode_client_hello(ch)

def encode_server_hello(sh: ServerHello) -> bytes:
    return TLSMessage.encode_server_hello(sh)

def decode_client_hello(data: bytes) -> ClientHello:
    return TLSMessage.decode_client_hello(data)

def decode_server_hello(data: bytes) -> ServerHello:
    return TLSMessage.decode_server_hello(data)

def encode_certificate(cert: Certificate) -> bytes:
    return TLSMessage.encode_certificate(cert)

def encode_certificate_verify(cv: CertificateVerify) -> bytes:
    return TLSMessage.encode_certificate_verify(cv)

def encode_finished(finished: Finished) -> bytes:
    return TLSMessage.encode_finished(finished)

def decode_certificate(data: bytes) -> Certificate:
    return TLSMessage.decode_certificate(data)

def decode_certificate_verify(data: bytes) -> CertificateVerify:
    return TLSMessage.decode_certificate_verify(data)

def decode_finished(data: bytes) -> Finished:
    return TLSMessage.decode_finished(data)

