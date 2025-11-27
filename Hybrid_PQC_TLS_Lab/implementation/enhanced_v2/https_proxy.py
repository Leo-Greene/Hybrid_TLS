#!/usr/bin/env python3
"""
HTTPS代理服务器 - 将浏览器的标准HTTPS请求转换为自定义TLS协议
浏览器 -> 标准HTTPS -> 代理 -> 自定义TLS -> 后端服务器
"""

import sys
import os
import socket
import ssl
import threading
import argparse
import ipaddress
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# 添加项目根目录到路径
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

from implementation.enhanced_v2_by_val.enhanced_client import EnhancedTLSClient, MessageReceiver as ClientMessageReceiver
from implementation.enhanced_v2_by_val.config import ClientConfig
from core.types import TLSMode
from core.crypto.record_encryption import TLSRecordEncryption
import struct


class HTTPSProxyHandler(BaseHTTPRequestHandler):
    """HTTPS代理处理器 - 将标准HTTPS转换为自定义TLS"""
    
    def __init__(self, request, client_address, server):
        # 从server对象获取配置
        self.backend_host = server.backend_host
        self.backend_port = server.backend_port
        self.tls_config = server.tls_config
        self.allow_other_connections = server.allow_other_connections
        super().__init__(request, client_address, server)
    
    def _generate_fixed_cert(self, context, cert_file_path, key_file_path):
        """生成固定的自签名证书并保存到文件"""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime
            
            # 生成私钥
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # 创建证书
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Local"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Local"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PQC-TLS Proxy"),
                x509.NameAttribute(NameOID.COMMON_NAME, "pqc-tls.local"),
            ])
            
            from datetime import timezone
            now = datetime.datetime.now(timezone.utc)
            
            # 创建证书构建器
            builder = x509.CertificateBuilder()
            builder = builder.subject_name(subject)
            builder = builder.issuer_name(issuer)
            builder = builder.public_key(private_key.public_key())
            builder = builder.serial_number(x509.random_serial_number())
            builder = builder.not_valid_before(now)
            builder = builder.not_valid_after(now + datetime.timedelta(days=365))
            
            # 添加扩展
            builder = builder.add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("pqc-tls.local"),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            )
            
            # 添加基本约束（CA证书）
            builder = builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            
            # 添加密钥用途
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            
            # 添加扩展密钥用途
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([
                    x509.ExtendedKeyUsageOID.SERVER_AUTH,
                ]),
                critical=False,
            )
            
            cert = builder.sign(private_key, hashes.SHA256())
            
            # 将证书和私钥保存到文件
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # 保存证书和私钥到文件
            with open(cert_file_path, 'wb') as f:
                f.write(cert_pem)
            with open(key_file_path, 'wb') as f:
                f.write(key_pem)
            
            # 加载到上下文
            context.load_cert_chain(cert_file_path, key_file_path)
                
        except Exception as e:
            print(f"[PROXY] ⚠️  生成证书失败: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    def handle(self):
        """处理请求 - 添加调试信息"""
        try:
            # 先调用父类handle，它会解析请求
            # 注意：不要在解析请求之前打印，因为可能还没有解析完成
            super().handle()
        except (ConnectionResetError, OSError) as e:
            # 连接重置是正常的（浏览器关闭连接）
            # 静默处理，不打印日志
            pass
        except Exception as e:
            # 只打印非预期的错误
            if "10054" not in str(e) and "10053" not in str(e):
                print(f"[PROXY] ❌ 处理请求错误: {e}")
                import traceback
                traceback.print_exc()
    
    def do_GET(self):
        """处理HTTP GET请求"""
        # 检查是否是证书获取请求（证书引用模式）
        if self.path.startswith('/pq/cert/') or self.path.startswith('/pq/sig/'):
            print(f"[PROXY] 📋 证书获取请求: {self.path}")
            print(f"[PROXY] 💡 提示: 证书引用模式需要单独的证书服务器")
            print(f"[PROXY] 💡 客户端将使用fallback模式继续握手")
            # 这些请求来自客户端（代理内部），不应该通过代理
            # 直接返回404，因为证书服务器没有运行
            # 客户端有fallback机制，即使获取失败也能继续
            self.send_error(404, "Certificate server not available - Using fallback mode")
        else:
            print(f"[PROXY] ⚠️  收到HTTP GET请求: {self.path}")
            print(f"[PROXY] 💡 提示: 请使用 HTTPS 访问 (https://pqc-tls.local:8443)")
            self.send_error(400, "Bad Request - Please use HTTPS")
    
    def do_POST(self):
        """处理HTTP POST请求 - 提示使用HTTPS"""
        print(f"[PROXY] ⚠️  收到HTTP POST请求: {self.path}")
        print(f"[PROXY] 💡 提示: 请使用 HTTPS 访问 (https://pqc-tls.local:8443)")
        self.send_error(400, "Bad Request - Please use HTTPS")
    
    def parse_request(self):
        """解析请求 - 只记录后端服务器相关的请求"""
        try:
            result = super().parse_request()
            if result and hasattr(self, 'raw_requestline'):
                try:
                    request_line = self.raw_requestline.decode('utf-8', errors='ignore').strip()
                    # 只记录CONNECT请求，并且只记录后端服务器相关的
                    if request_line.startswith('CONNECT'):
                        # 解析目标地址
                        parts = request_line.split()
                        if len(parts) >= 2:
                            target = parts[1].split(':')
                            if len(target) == 2:
                                target_host, target_port = target[0], int(target[1])
                                # 检查是否是后端服务器
                                backend_hosts = [self.backend_host, '127.0.0.1', 'localhost', 'pqc-tls.local']
                                if self.backend_host == '0.0.0.0':
                                    backend_hosts.extend(['127.0.0.1', 'localhost', '0.0.0.0', 'pqc-tls.local'])
                                is_backend = target_host in backend_hosts and target_port == self.backend_port
                                
                                # 只打印后端服务器相关的连接
                                if is_backend:
                                    print(f"[PROXY] 📥 收到连接: {self.client_address[0]}:{self.client_address[1]}")
                                    print(f"[PROXY] 📋 请求行: {request_line}")
                                # 其他连接静默处理，不打印日志
                except:
                    pass
            return result
        except Exception as e:
            # 如果解析失败，可能是连接已关闭
            # 静默处理，不打印日志
            return False
    
    def log_message(self, format, *args):
        """重写日志方法，只记录重要信息"""
        # 静默处理标准HTTP日志
        pass
    
    def do_CONNECT(self):
        """处理HTTPS CONNECT请求（用于HTTPS代理）"""
        # 解析目标地址
        target = self.path.split(':')
        if len(target) == 2:
            target_host, target_port = target[0], int(target[1])
        else:
            self.send_error(400, "Bad Request")
            return
        
        # 如果目标是后端服务器，使用自定义TLS
        # 支持多种格式：127.0.0.1, localhost, 以及通过hosts映射的域名
        backend_hosts = [self.backend_host, '127.0.0.1', 'localhost', 'pqc-tls.local']
        # 标准化比较（处理0.0.0.0的情况）
        if self.backend_host == '0.0.0.0':
            backend_hosts.extend(['127.0.0.1', 'localhost', '0.0.0.0', 'pqc-tls.local'])
        
        # 检查是否是后端服务器
        is_backend = target_host in backend_hosts and target_port == self.backend_port
        
        if is_backend:
            # ⭐ 只打印实验相关的连接信息
            print(f"\n{'='*70}")
            print(f"[PROXY] 🔗 CONNECT请求: {self.path}")
            print(f"[PROXY] 🔐 检测到后端服务器连接: {target_host}:{target_port}")
            print(f"[PROXY] 📍 客户端: {self.client_address[0]}:{self.client_address[1]}")
            print(f"{'='*70}\n")
            self.handle_custom_tls_connection()
        else:
            # 其他目标连接的处理
            if self.allow_other_connections:
                # 如果允许其他连接，使用标准HTTPS转发（静默处理）
                self.handle_standard_https_connection(target_host, target_port, silent=True)
            else:
                # 默认：直接拒绝非后端连接
                # 这样可以避免代理处理无关流量，保持日志清洁
                # 静默拒绝，不打印日志（减少噪音）
                try:
                    self.send_error(403, "Forbidden - This proxy only handles backend server connections")
                except:
                    pass  # 连接可能已关闭，静默处理
    
    def handle_custom_tls_connection(self):
        """处理自定义TLS连接"""
        backend_socket = None
        browser_ssl_socket = None
        try:
            print(f"[PROXY] 🔐 开始处理自定义TLS连接...")
            print(f"[PROXY] ✓ HTTPS隧道建立: {self.client_address[0]} -> {self.backend_host}:{self.backend_port}")
            
            # ⭐ 步骤1: 先发送200 Connection Established给浏览器（在建立后端连接之前）
            # 这样浏览器可以立即开始发送TLS握手数据
            self.wfile.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            self.wfile.flush()
            
            # ⭐ 步骤2: 完成与浏览器的标准TLS握手（代理作为TLS服务器）
            print(f"[PROXY] [1/3] 与浏览器建立标准TLS连接...")
            try:
                # 创建SSL上下文（用于与浏览器通信）
                # 使用PROTOCOL_TLS_SERVER，这是Python 3.7+推荐的方式
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # 设置最低协议版本为TLS 1.2（现代浏览器支持）
                try:
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
                except AttributeError:
                    # Python 3.6及以下版本不支持minimum_version
                    pass
                
                # 设置密码套件（支持现代浏览器）
                try:
                    context.set_ciphers('DEFAULT:@SECLEVEL=1')
                except:
                    # 如果设置失败，使用默认密码套件
                    pass
                
                # 尝试加载自签名证书（如果存在）
                certs_dir = os.path.join(project_root, 'certs')
                os.makedirs(certs_dir, exist_ok=True)  # 确保目录存在
                
                cert_file = os.path.join(certs_dir, 'proxy_cert.pem')
                key_file = os.path.join(certs_dir, 'proxy_key.pem')
                
                cert_loaded = False
                if os.path.exists(cert_file) and os.path.exists(key_file):
                    try:
                        context.load_cert_chain(cert_file, key_file)
                        print(f"[PROXY] ✓ 加载代理证书: {cert_file}")
                        cert_loaded = True
                    except Exception as e:
                        print(f"[PROXY] ⚠️  加载代理证书失败: {e}，将生成新证书")
                
                if not cert_loaded:
                    print(f"[PROXY] ⚠️  未找到代理证书，生成固定证书...")
                    self._generate_fixed_cert(context, cert_file, key_file)
                    print(f"[PROXY] ✓ 证书已保存到: {cert_file}")
                    print(f"[PROXY] 💡 请将此证书添加到浏览器信任列表:")
                    print(f"[PROXY]    Chrome/Edge: 设置 -> 隐私和安全 -> 安全 -> 管理证书 -> 受信任的根证书颁发机构 -> 导入")
                    print(f"[PROXY]    Firefox: 设置 -> 隐私和安全 -> 证书 -> 查看证书 -> 导入")
                
                # 包装浏览器连接为SSL连接
                # 使用do_handshake_on_connect=False以便更好地控制握手过程
                browser_ssl_socket = context.wrap_socket(
                    self.connection, 
                    server_side=True,
                    do_handshake_on_connect=False
                )
                
                # 手动执行握手，设置超时
                browser_ssl_socket.settimeout(10)
                try:
                    browser_ssl_socket.do_handshake()
                    print(f"[PROXY] ✓ 与浏览器TLS握手完成")
                except ssl.SSLError as e:
                    # 如果是证书相关的错误，尝试继续（浏览器可能会显示警告但允许继续）
                    if 'certificate' in str(e).lower() or 'unknown' in str(e).lower():
                        print(f"[PROXY] ⚠️  浏览器拒绝证书: {e}")
                        print(f"[PROXY] 💡 这是正常的（自签名证书），浏览器会显示警告")
                        print(f"[PROXY] 💡 请在浏览器中点击'高级'->'继续访问'")
                        # 对于某些浏览器，即使证书被拒绝，握手也可能继续
                        # 但这里我们需要让用户手动接受证书
                        raise e
                    else:
                        raise e
                except Exception as e:
                    raise e
            except ssl.SSLError as e:
                # SSL错误，可能是证书问题
                if 'certificate' in str(e).lower() or 'unknown' in str(e).lower():
                    print(f"[PROXY] ❌ 浏览器TLS握手失败（证书被拒绝）: {e}")
                    print(f"[PROXY] 💡 解决方案:")
                    print(f"[PROXY]    1. 浏览器会显示证书警告，点击'高级'->'继续访问'")
                    print(f"[PROXY]    2. 或者使用 https_server.py 直接运行（不使用代理）")
                else:
                    print(f"[PROXY] ❌ 与浏览器TLS握手失败: {e}")
                    import traceback
                    traceback.print_exc()
                return
            except Exception as e:
                print(f"[PROXY] ❌ 与浏览器TLS握手失败: {e}")
                import traceback
                traceback.print_exc()
                return
            
            # ⭐ 步骤3: 建立与后端服务器的自定义TLS连接
            print(f"[PROXY] [2/3] 与后端服务器建立自定义TLS连接...")
            backend_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backend_socket.settimeout(10)  # 设置超时
            backend_socket.connect((self.backend_host, self.backend_port))
            
            # 执行自定义TLS握手
            client = EnhancedTLSClient(self.tls_config)
            client.perform_enhanced_handshake(backend_socket)
            
            print(f"[PROXY] ✓ 与后端自定义TLS握手成功")
            
            # ⭐ 步骤4: 使用客户端实例的加密器/解密器（by_val模式）
            # 注意：客户端在握手完成后会发送测试数据，这会消耗序列号
            # 我们需要使用客户端实例的加密器/解密器，因为它们已经与后端同步了序列号
            # 但是客户端发送了测试数据，所以序列号已经前进了
            # 我们需要创建新的加密器，但需要考虑客户端已经发送的数据
            app_encryptor = TLSRecordEncryption(cipher_name="AES_128_GCM")
            app_decryptor = TLSRecordEncryption(cipher_name="AES_128_GCM")
            
            # ⚠️ 重要：客户端在握手完成后发送了测试数据，消耗了序列号
            # 我们需要同步序列号。客户端发送了1条应用数据，接收了1条响应
            # 所以客户端的encryptor.seq_num_send应该是1，decryptor.seq_num_recv应该是1
            # 我们需要将代理的加密器/解密器同步到这个状态
            if hasattr(client, 'encryptor') and hasattr(client, 'decryptor'):
                # 同步序列号（客户端已经发送了测试数据）
                app_encryptor.seq_num_send = client.encryptor.seq_num_send
                app_decryptor.seq_num_recv = client.decryptor.seq_num_recv
                print(f"[PROXY] 🔄 同步序列号: send={app_encryptor.seq_num_send}, recv={app_decryptor.seq_num_recv}")
            else:
                # 如果无法访问客户端的加密器，重置序列号（可能不准确，但可以尝试）
                app_encryptor.reset_sequence_numbers()
                app_decryptor.reset_sequence_numbers()
                print(f"[PROXY] ⚠️  无法访问客户端加密器，重置序列号")
            
            print(f"[PROXY] [3/3] 开始双向数据转发...")
            
            # 双向转发数据
            def forward_browser_to_backend():
                """转发浏览器数据到后端"""
                try:
                    # 设置超时，避免无限等待
                    browser_ssl_socket.settimeout(30.0)
                    while True:
                        # 从浏览器接收标准TLS加密的数据（已解密）
                        try:
                            data = browser_ssl_socket.recv(4096)
                            if not data:
                                print(f"[PROXY] 📥 浏览器连接关闭")
                                break
                        except socket.timeout:
                            # 超时是正常的，浏览器可能还没有发送数据
                            continue
                        
                        print(f"[PROXY] 📥 从浏览器接收数据: {len(data)} 字节")
                        
                        # 使用自定义TLS加密并发送到后端
                        encrypted = app_encryptor.encrypt_record(
                            data,
                            client.handshake_keys.client_handshake_key,
                            client.handshake_keys.client_handshake_iv
                        )
                        
                        # 封装为TLS记录
                        record_header = struct.pack('!B', 23)
                        record_header += struct.pack('!H', 0x0303)
                        record_header += struct.pack('!H', len(encrypted))
                        backend_socket.send(record_header + encrypted)
                        print(f"[PROXY] 📤 转发到后端: {len(data)} 字节 -> {len(encrypted)} 字节")
                        
                except Exception as e:
                    # 连接关闭是正常的
                    if "10054" not in str(e) and "10053" not in str(e) and "timed out" not in str(e).lower():
                        print(f"[PROXY] ❌ 转发浏览器->后端错误: {e}")
                        import traceback
                        traceback.print_exc()
            
            def forward_backend_to_browser():
                """转发后端数据到浏览器"""
                try:
                    receiver = ClientMessageReceiver(backend_socket)
                    backend_socket.settimeout(30.0)  # 设置超时
                    while True:
                        # 从后端接收自定义TLS加密的数据（receive_application_data返回的是去除TLS记录头的纯加密数据）
                        try:
                            encrypted = receiver.receive_application_data(4096)
                            if not encrypted:
                                print(f"[PROXY] 📥 后端连接关闭")
                                break
                        except socket.timeout:
                            # 超时是正常的，后端可能还没有发送数据
                            continue
                        
                        print(f"[PROXY] 📥 从后端接收数据: {len(encrypted)} 字节")
                        
                        # 使用自定义TLS解密（encrypted是纯加密数据，不包含TLS记录头）
                        try:
                            data, _ = app_decryptor.decrypt_record(
                                encrypted,
                                client.handshake_keys.server_handshake_key,
                                client.handshake_keys.server_handshake_iv
                            )
                            print(f"[PROXY] ✓ 解密后端数据成功: {len(encrypted)} 字节 -> {len(data)} 字节")
                        except Exception as decrypt_error:
                            print(f"[PROXY] ❌ 解密后端数据失败: {decrypt_error}")
                            print(f"[PROXY] 💡 提示: 可能是序列号不同步或密钥错误")
                            import traceback
                            traceback.print_exc()
                            break
                        
                        # 使用标准TLS加密并发送到浏览器
                        # browser_ssl_socket会自动添加TLS记录头
                        browser_ssl_socket.send(data)
                        print(f"[PROXY] 📤 转发到浏览器: {len(data)} 字节")
                        
                except Exception as e:
                    # 连接关闭是正常的
                    if "10054" not in str(e) and "10053" not in str(e) and "timed out" not in str(e).lower():
                        print(f"[PROXY] ❌ 转发后端->浏览器错误: {e}")
                        import traceback
                        traceback.print_exc()
            
            # 启动转发线程
            t1 = threading.Thread(target=forward_browser_to_backend, daemon=True)
            t2 = threading.Thread(target=forward_backend_to_browser, daemon=True)
            t1.start()
            t2.start()
            
            # 等待线程完成
            t1.join()
            t2.join()
            
            print(f"[PROXY] ✓ 连接关闭")
            
        except Exception as e:
            print(f"[PROXY] ❌ 处理自定义TLS连接错误: {e}")
            import traceback
            traceback.print_exc()
        finally:
            try:
                if browser_ssl_socket:
                    browser_ssl_socket.close()
                if backend_socket:
                    backend_socket.close()
                self.connection.close()
            except:
                pass
    
    def handle_standard_https_connection(self, target_host, target_port, silent=False):
        """处理标准HTTPS连接"""
        try:
            # 先发送200 Connection Established（在连接之前）
            # 这样浏览器可以立即开始发送TLS握手数据
            self.send_response(200, 'Connection Established')
            self.end_headers()
            
            # 连接到目标服务器
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.settimeout(10)  # 设置超时
            target_socket.connect((target_host, target_port))
            
            # 建立SSL连接
            context = ssl.create_default_context()
            ssl_socket = context.wrap_socket(target_socket, server_hostname=target_host)
            
            # 只在非静默模式下打印日志
            if not silent:
                print(f"[PROXY] ✓ 标准HTTPS隧道建立: {self.client_address[0]} -> {target_host}:{target_port}")
            
            # 双向转发
            def forward():
                try:
                    while True:
                        data = self.connection.recv(4096)
                        if not data:
                            break
                        ssl_socket.send(data)
                        
                        response = ssl_socket.recv(4096)
                        if not response:
                            break
                        self.connection.send(response)
                except Exception as e:
                    # 静默处理连接关闭
                    pass
            
            forward()
            
        except socket.timeout:
            # 只在非静默模式下打印超时日志
            if not silent:
                print(f"[PROXY] ⚠️  连接超时: {target_host}:{target_port}")
        except Exception as e:
            # 只在非静默模式下记录非预期的错误
            if not silent and "10054" not in str(e) and "10060" not in str(e):
                print(f"[PROXY] ❌ 处理标准HTTPS连接错误: {e}")
        finally:
            try:
                if 'ssl_socket' in locals():
                    ssl_socket.close()
                self.connection.close()
            except:
                pass
    
    def log_message(self, format, *args):
        """自定义日志"""
        pass


class HTTPSProxyServer(HTTPServer):
    """HTTPS代理服务器"""
    
    def __init__(self, server_address, RequestHandlerClass, backend_host, backend_port, tls_config, allow_other_connections=False):
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.tls_config = tls_config
        self.allow_other_connections = allow_other_connections
        super().__init__(server_address, RequestHandlerClass)
    
    def server_bind(self):
        """绑定服务器地址"""
        super().server_bind()
        print(f"[PROXY] ✓ 代理服务器已绑定到 {self.server_address[0]}:{self.server_address[1]}")
    
    def finish_request(self, request, client_address):
        """完成请求处理"""
        # HTTPServer会自动调用RequestHandlerClass，配置通过server对象传递
        super().finish_request(request, client_address)


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='HTTPS代理服务器 - 将标准HTTPS转换为自定义TLS')
    parser.add_argument('--proxy-host', default='0.0.0.0', help='代理服务器主机')
    parser.add_argument('--proxy-port', type=int, default=8080, help='代理服务器端口')
    parser.add_argument('--backend-host', default='127.0.0.1', help='后端服务器主机')
    parser.add_argument('--backend-port', type=int, default=8443, help='后端服务器端口')
    parser.add_argument('--mode', choices=['classic', 'pqc', 'hybrid'], 
                       default='hybrid', help='TLS模式')
    parser.add_argument('--algorithm', type=str, help='签名算法')
    parser.add_argument('--allow-other-connections', action='store_true', 
                       help='允许处理非后端服务器的连接（默认：只处理后端服务器）')
    
    args = parser.parse_args()
    
    # 创建TLS配置
    tls_config = ClientConfig(
        mode=TLSMode(args.mode),
        host=args.backend_host,
        port=args.backend_port,
        algorithm=args.algorithm
    )
    
    # 创建代理服务器（直接使用HTTPSProxyHandler类）
    proxy = HTTPSProxyServer(
        (args.proxy_host, args.proxy_port),
        HTTPSProxyHandler,
        args.backend_host,
        args.backend_port,
        tls_config,
        allow_other_connections=args.allow_other_connections
    )
    
    print(f"\n{'='*70}")
    print(f"  HTTPS代理服务器")
    print(f"{'='*70}")
    print(f"  代理地址: http://{args.proxy_host}:{args.proxy_port}")
    print(f"  后端地址: {args.backend_host}:{args.backend_port}")
    print(f"  模式: {args.mode}")
    if args.algorithm:
        print(f"  算法: {args.algorithm}")
    print(f"{'='*70}\n")
    print(f"[*] 代理服务器启动中...")
    print(f"[*] 监听地址: {args.proxy_host}:{args.proxy_port}")
    
    # 显示正确的代理地址（如果是0.0.0.0，显示127.0.0.1）
    proxy_display_host = '127.0.0.1' if args.proxy_host == '0.0.0.0' else args.proxy_host
    print(f"[*] 浏览器代理设置:")
    print(f"    HTTP代理: {proxy_display_host}:{args.proxy_port}")
    print(f"    HTTPS代理: {proxy_display_host}:{args.proxy_port}")
    print(f"\n[!] 重要提示:")
    print(f"    1. 确保浏览器代理设置正确（HTTP和HTTPS都设置为 {proxy_display_host}:{args.proxy_port}）")
    print(f"    2. 在'不使用代理'列表中，移除 '127.*' 或 '127.0.0.1'")
    print(f"    3. 访问 https://pqc-tls.local:8443/ （使用域名，不要用IP）")
    print(f"    4. 如果看到证书警告，点击'高级'->'继续访问'")
    if not args.allow_other_connections:
        print(f"    5. ⚠️  代理只处理后端服务器连接，其他连接将被拒绝")
        print(f"       如需处理其他连接，使用 --allow-other-connections 参数")
    print(f"\n[*] 等待连接...")
    print(f"[*] 只显示后端服务器（pqc-tls.local:8443）的连接日志\n")
    
    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[*] 代理服务器关闭...")
        proxy.shutdown()


if __name__ == '__main__':
    main()

