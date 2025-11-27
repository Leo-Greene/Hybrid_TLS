#!/usr/bin/env python3
"""
本地证书文件服务器
为enhanced_client.py提供本地HTTP服务，替代jeanreed.online
"""

import http.server
import socketserver
import json
import os
from pathlib import Path

class LocalCertServer(http.server.SimpleHTTPRequestHandler):
    """本地证书文件服务器处理器"""
    
    def log_message(self, format, *args):
        """记录请求日志（简化版本）"""
        # 只记录请求路径，不记录完整日志以减少开销
        if args and len(args) > 0:
            print(f"[HTTP Server] {args[0]} {self.path}")
    
    def do_GET(self):
        """处理GET请求（优化版本，减少延迟）"""
        # 解析请求路径
        path_parts = self.path.strip('/').split('/')
        
        # 检查是否是证书相关请求
        if len(path_parts) >= 4 and path_parts[0] == 'pq':
            cert_type = path_parts[1]  # cert/sig
            file_type = path_parts[2]  # server/intermediate/root
            algorithm = path_parts[3]  # ML-DSA-65等
            
            # 构建本地文件路径（新结构：implementation/enhanced_v2/pq_certificates/算法名称/证书类型/文件名）
            base_dir = Path(__file__).parent / "pq_certificates"
            
            # 算法名称映射：将ML-DSA-65等格式转换为mldsa65等格式
            algorithm_mapping = {
                "ML-DSA-65": "mldsa65",
                "ML-DSA-44": "mldsa44", 
                "ML-DSA-87": "mldsa87",
                "Falcon512": "falcon512",
                "Falcon1024": "falcon1024"
            }
            
            # 使用映射后的算法名称
            mapped_algorithm = algorithm_mapping.get(algorithm, algorithm.lower())
            
            # 根据证书类型和文件类型确定正确的文件名
            if cert_type == 'cert':
                # 公钥文件：server_pq_pubkey.pub, intermediate_pq_pubkey.pub, root_pq_pubkey.pub
                file_path = base_dir / mapped_algorithm / file_type / f"{file_type}_pq_pubkey.pub"
            else:
                # 签名文件：server_pq.sig, intermediate_ca_pq.sig, root_ca_pq.sig
                if file_type == 'server':
                    file_path = base_dir / mapped_algorithm / file_type / f"{file_type}_pq.sig"
                else:
                    file_path = base_dir / mapped_algorithm / file_type / f"{file_type}_ca_pq.sig"
            
            if file_path.exists():
                # 返回文件内容（优化：减少不必要的操作）
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                    
                    # 记录成功响应
                    print(f"[HTTP Server] ✓ 返回 {cert_type}/{file_type}/{algorithm}: {len(content)} 字节")
                    
                    # 设置响应头（最小化，减少延迟）
                    self.send_response(200)
                    self.send_header('Content-type', 'application/octet-stream')
                    self.send_header('Content-length', str(len(content)))
                    self.end_headers()
                    
                    # 发送内容
                    self.wfile.write(content)
                    return
                    
                except Exception as e:
                    print(f"[HTTP Server] ❌ 读取文件失败: {file_path}, 错误: {e}")
            else:
                print(f"[HTTP Server] ❌ 文件不存在: {file_path}")
            
        # 默认返回404（快速失败）
        self.send_response(404)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"File not found")

def start_server(port=80):
    """启动HTTP服务器"""
    with socketserver.TCPServer(("", port), LocalCertServer) as httpd:
        print(f"[HTTP Server] 启动本地证书服务器，端口: {port}")
        print(f"[HTTP Server] 服务地址: http://localhost:{port}/")
        print("[HTTP Server] 按 Ctrl+C 停止服务器")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[HTTP Server] 服务器已停止")

if __name__ == "__main__":
    # 检查是否在Windows上需要管理员权限
    import sys
    if sys.platform == "win32":
        print("注意: 在Windows上运行可能需要管理员权限才能绑定80端口")
        print("如果遇到权限错误，请以管理员身份运行此脚本")
    
    start_server(80)