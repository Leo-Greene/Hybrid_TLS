#!/usr/bin/env python3
"""
HTTPS服务器 - 使用自定义混合TLS协议实现HTTPS
支持浏览器访问，通过代理将标准HTTPS转换为自定义TLS
"""

import sys
import os
import socket
import threading
import argparse
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# 添加项目根目录到路径
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

from implementation.enhanced_v2.enhanced_server import EnhancedTLSServer, MessageReceiver
from implementation.enhanced_v2.enhanced_client import EnhancedTLSClient, MessageReceiver as ClientMessageReceiver
from implementation.enhanced_v2.config import ServerConfig, ClientConfig
from core.types import TLSMode
from core.crypto.record_encryption import TLSRecordEncryption
import struct


class CustomTLSHTTPServer:
    """使用自定义TLS协议的HTTPS服务器"""
    
    def __init__(self, host, port, tls_config):
        self.host = host
        self.port = port
        self.tls_config = tls_config
        self.server_socket = None
    
    def start(self):
        """启动服务器"""
        # 创建服务器套接字
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        
        print(f"[HTTPS] 服务器监听在 {self.host}:{self.port}")
        print(f"[HTTPS] 等待连接...\n")
        
        try:
            while True:
                client_socket, addr = self.server_socket.accept()
                print(f"[HTTPS] 客户端连接: {addr[0]}:{addr[1]}")
                
                # 为每个连接创建线程
                thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, addr),
                    daemon=True
                )
                thread.start()
        except KeyboardInterrupt:
            print(f"\n[HTTPS] 服务器关闭...")
        finally:
            if self.server_socket:
                self.server_socket.close()
    
    def handle_client(self, client_socket, addr):
        """处理客户端连接"""
        try:
            # 创建TLS服务器实例
            tls_server = EnhancedTLSServer(self.tls_config)
            
            # 执行TLS握手
            tls_server.handle_client(client_socket)
            
            # 握手完成后，处理HTTP请求
            self.handle_http_requests(client_socket, tls_server)
            
        except Exception as e:
            print(f"[HTTPS] ❌ 处理客户端错误: {e}")
            import traceback
            traceback.print_exc()
        finally:
            client_socket.close()
            print(f"[HTTPS] 连接关闭: {addr[0]}:{addr[1]}\n")
    
    def handle_http_requests(self, client_socket, tls_server):
        """处理HTTP请求（握手后）"""
        # 为应用数据创建新的加密器/解密器
        connection_encryptor = TLSRecordEncryption(cipher_name="AES_128_GCM")
        connection_decryptor = TLSRecordEncryption(cipher_name="AES_128_GCM")
        
        receiver = MessageReceiver(client_socket)
        
        while True:
            try:
                # 接收加密的HTTP请求
                encrypted_request = receiver.receive_application_data(4096)
                
                if not encrypted_request:
                    break
                
                # 解密请求
                app_data, content_type = connection_decryptor.decrypt_record(
                    encrypted_request,
                    tls_server.handshake_keys.client_handshake_key,
                    tls_server.handshake_keys.client_handshake_iv
                )
                
                # 解析HTTP请求
                request_str = app_data.decode('utf-8', errors='ignore')
                print(f"[HTTP] 请求: {request_str.split(chr(13))[0]}")
                
                # 解析HTTP请求
                lines = request_str.split('\r\n')
                if not lines:
                    break
                
                request_line = lines[0]
                parts = request_line.split()
                if len(parts) < 2:
                    break
                
                method = parts[0]
                path = parts[1]
                
                # 生成HTTP响应
                response_body = self.generate_response(method, path)
                response = self.build_http_response(response_body)
                
                # 加密响应
                encrypted_response = connection_encryptor.encrypt_record(
                    response.encode('utf-8'),
                    tls_server.handshake_keys.server_handshake_key,
                    tls_server.handshake_keys.server_handshake_iv
                )
                
                # 封装为TLS记录
                record_type = 23
                record_header = struct.pack('!B', record_type)
                record_header += struct.pack('!H', 0x0303)
                record_header += struct.pack('!H', len(encrypted_response))
                
                tls_response = record_header + encrypted_response
                client_socket.send(tls_response)
                
                print(f"[HTTP] ✓ 发送响应: {len(response_body)} 字节")
                
                # 如果Connection: close，退出循环
                if 'Connection: close' in request_str or 'connection: close' in request_str.lower():
                    break
                    
            except Exception as e:
                print(f"[HTTP] ❌ 处理请求错误: {e}")
                break
    
    def generate_response(self, method: str, path: str) -> str:
        """生成HTTP响应内容"""
        if path == '/' or path == '/index.html':
            return self.get_index_page()
        elif path == '/api/status':
            return self.get_status_json()
        else:
            return self.get_404_page()
    
    def build_http_response(self, body: str) -> str:
        """构建HTTP响应"""
        response = f"HTTP/1.1 200 OK\r\n"
        response += f"Content-Type: text/html; charset=utf-8\r\n"
        response += f"Content-Length: {len(body.encode('utf-8'))}\r\n"
        response += f"Connection: close\r\n"
        response += f"\r\n"
        response += body
        return response
    
    def get_index_page(self) -> str:
        """获取首页HTML"""
        return """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>混合PQC-TLS HTTPS演示</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .container {
            background: rgba(255, 255, 255, 0.1);
            padding: 30px;
            border-radius: 10px;
            backdrop-filter: blur(10px);
        }
        h1 { text-align: center; }
        .info {
            background: rgba(255, 255, 255, 0.2);
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .status {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 3px;
            background: #10b981;
            color: white;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 混合PQC-TLS HTTPS演示</h1>
        <div class="info">
            <h2>连接信息</h2>
            <p><strong>协议:</strong> <span class="status">HTTPS (自定义混合TLS)</span></p>
            <p><strong>TLS版本:</strong> TLS 1.3 (混合后量子)</p>
            <p><strong>加密算法:</strong> AES-128-GCM</p>
            <p><strong>密钥交换:</strong> 混合PQC (P-256 + Kyber768)</p>
            <p><strong>签名算法:</strong> ML-DSA-65 (后量子)</p>
        </div>
        <div class="info">
            <h2>安全特性</h2>
            <ul>
                <li>✓ 后量子密码学 (PQC) 支持</li>
                <li>✓ 混合密钥交换 (经典 + 后量子)</li>
                <li>✓ 后量子数字签名</li>
                <li>✓ 端到端加密</li>
                <li>✓ 抗降级攻击保护</li>
            </ul>
        </div>
        <div class="info">
            <h2>说明</h2>
            <p>此网站使用自定义的混合PQC-TLS协议实现HTTPS通信。</p>
            <p>所有数据都经过加密传输，可以使用抓包工具（如Wireshark）查看加密的数据包。</p>
        </div>
    </div>
</body>
</html>"""
    
    def get_status_json(self) -> str:
        """获取状态JSON"""
        import json
        status = {
            "status": "online",
            "protocol": "HTTPS (Custom Hybrid PQC-TLS)",
            "tls_version": "TLS 1.3",
            "cipher": "AES-128-GCM",
            "key_exchange": "Hybrid PQC (P-256 + Kyber768)",
            "signature": "ML-DSA-65"
        }
        return json.dumps(status, indent=2, ensure_ascii=False)
    
    def get_404_page(self) -> str:
        """获取404页面"""
        return """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>404 - 页面未找到</title>
</head>
<body>
    <h1>404 - 页面未找到</h1>
    <p>请求的页面不存在。</p>
</body>
</html>"""
    
    def log_message(self, format, *args):
        """禁用默认日志"""
        pass


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='HTTPS服务器 - 使用自定义混合TLS协议')
    parser.add_argument('--host', default='0.0.0.0', help='绑定主机')
    parser.add_argument('--port', type=int, default=8443, help='绑定端口')
    parser.add_argument('--mode', choices=['classic', 'pqc', 'hybrid'], 
                       default='hybrid', help='TLS模式')
    parser.add_argument('--algorithm', type=str, help='签名算法')
    
    args = parser.parse_args()
    
    # 创建TLS配置
    tls_config = ServerConfig(
        mode=TLSMode(args.mode),
        host=args.host,
        port=args.port,
        algorithm=args.algorithm
    )
    
    # 创建HTTPS服务器
    server = CustomTLSHTTPServer(
        args.host,
        args.port,
        tls_config
    )
    
    print(f"\n{'='*70}")
    print(f"  混合PQC-TLS HTTPS服务器")
    print(f"{'='*70}")
    print(f"  地址: https://{args.host}:{args.port}")
    print(f"  模式: {args.mode}")
    if args.algorithm:
        print(f"  算法: {args.algorithm}")
    print(f"{'='*70}\n")
    print(f"[*] 服务器启动中...")
    print(f"[*] 注意: 需要使用支持自定义TLS的客户端连接")
    print(f"[*] 可以使用Wireshark等工具抓包查看加密数据")
    print(f"[*] 推荐使用代理服务器: python https_proxy.py\n")
    
    try:
        server.start()
    except KeyboardInterrupt:
        print(f"\n[*] 服务器关闭...")


if __name__ == '__main__':
    main()

