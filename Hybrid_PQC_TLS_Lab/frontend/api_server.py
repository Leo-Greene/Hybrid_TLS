#!/usr/bin/env python3
"""
TLS握手前端API服务器
支持by_ref和by_val模式的真实握手执行和性能对比
基于enhanced_v2和enhanced_v2_by_val实现
"""

import asyncio
import json
import time
import socket
import threading
import subprocess
import sys
import os
import tempfile
import signal
import atexit
from pathlib import Path
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import uvicorn
import re

# 添加项目根目录到路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

app = FastAPI(title="TLS握手前端API", version="3.0.0")

# 配置CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 存储握手会话数据
handshake_sessions = {}


class ResourceMonitor:
    """资源消耗监控器"""
    
    def __init__(self):
        self.monitoring = False
        self.cpu_samples = []
        self.memory_samples = []
        self.monitor_thread = None
        self.process = None
        
    def start(self, process=None):
        """开始监控资源消耗"""
        try:
            import psutil
            self.monitoring = True
            self.process = process or psutil.Process()
            self.cpu_samples = []
            self.memory_samples = []
            
            # 启动监控线程
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
        except ImportError:
            # psutil不可用，跳过监控
            pass
        except Exception as e:
            print(f"[资源监控] 启动失败: {e}")
    
    def _monitor_loop(self):
        """监控循环"""
        import psutil
        import time
        
        while self.monitoring:
            try:
                # 获取CPU使用率（百分比）
                cpu_percent = self.process.cpu_percent(interval=0.1)
                
                # 获取内存使用（MB）
                memory_info = self.process.memory_info()
                memory_mb = memory_info.rss / (1024 * 1024)  # RSS内存，单位MB
                
                self.cpu_samples.append({
                    'time': time.time(),
                    'cpu_percent': cpu_percent
                })
                
                self.memory_samples.append({
                    'time': time.time(),
                    'memory_mb': memory_mb
                })
                
                time.sleep(0.1)  # 每100ms采样一次
            except Exception as e:
                print(f"[资源监控] 采样错误: {e}")
                break
    
    def stop(self):
        """停止监控并返回统计信息"""
        self.monitoring = False
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
        
        try:
            import psutil
            
            if not self.cpu_samples and not self.memory_samples:
                # 如果没有采样数据，尝试获取当前进程的资源使用情况
                try:
                    if self.process:
                        cpu_percent = self.process.cpu_percent(interval=0.1)
                        memory_info = self.process.memory_info()
                        memory_mb = memory_info.rss / (1024 * 1024)
                        return {
                            'cpu': {
                                'avg_percent': round(cpu_percent, 2),
                                'max_percent': round(cpu_percent, 2),
                                'min_percent': round(cpu_percent, 2),
                                'samples': 1
                            },
                            'memory': {
                                'avg_mb': round(memory_mb, 2),
                                'max_mb': round(memory_mb, 2),
                                'min_mb': round(memory_mb, 2),
                                'peak_mb': round(memory_mb, 2),
                                'samples': 1
                            }
                        }
                except:
                    pass
                return None
            
            # 计算CPU统计
            cpu_values = [s['cpu_percent'] for s in self.cpu_samples if s['cpu_percent'] is not None]
            if not cpu_values:
                return None
            cpu_avg = sum(cpu_values) / len(cpu_values)
            cpu_max = max(cpu_values)
            cpu_min = min(cpu_values)
            
            # 计算内存统计
            memory_values = [s['memory_mb'] for s in self.memory_samples]
            if not memory_values:
                return None
            memory_avg = sum(memory_values) / len(memory_values)
            memory_max = max(memory_values)
            memory_min = min(memory_values)
            
            # 获取进程的峰值内存（如果可用）
            try:
                if self.process:
                    memory_info = self.process.memory_info()
                    peak_memory = memory_info.rss / (1024 * 1024)  # MB
                else:
                    peak_memory = memory_max
            except:
                peak_memory = memory_max
            
            return {
                'cpu': {
                    'avg_percent': round(cpu_avg, 2),
                    'max_percent': round(cpu_max, 2),
                    'min_percent': round(cpu_min, 2),
                    'samples': len(cpu_values)
                },
                'memory': {
                    'avg_mb': round(memory_avg, 2),
                    'max_mb': round(memory_max, 2),
                    'min_mb': round(memory_min, 2),
                    'peak_mb': round(peak_memory, 2),
                    'samples': len(memory_values)
                }
            }
        except ImportError:
            return None
        except Exception as e:
            print(f"[资源监控] 统计错误: {e}")
            import traceback
            traceback.print_exc()
            return None


# Pydantic模型用于请求体
class HandshakeRequest(BaseModel):
    mode: str
    cert_mode: str = "by_val"
    algorithm: Optional[str] = None
    kem: Optional[str] = None

# 全局变量：本地证书服务器进程
cert_server_process = None

# 全局变量：用于优雅退出
active_subprocesses = []  # 跟踪所有活动的子进程
temp_files = []  # 跟踪所有临时文件


def start_cert_server():
    """启动本地证书服务器（用于by_ref模式）"""
    global cert_server_process, active_subprocesses
    
    # 先快速检查服务器是否已经运行（避免不必要的启动）
    try:
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.settimeout(0.01)  # 非常短的超时
        result = test_socket.connect_ex(('127.0.0.1', 80))
        test_socket.close()
        if result == 0:
            # 服务器已经在运行，直接返回
            return
    except:
        pass
    
    if cert_server_process and cert_server_process.poll() is None:
        # 验证服务器是否真的在运行
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(0.01)  # 减少超时时间
            result = test_socket.connect_ex(('127.0.0.1', 80))
            test_socket.close()
            if result == 0:
                return  # 服务器正在运行
        except:
            pass
        # 如果进程存在但无法连接，清理并重启
        try:
            cert_server_process.terminate()
            cert_server_process.wait(timeout=2)
        except:
            pass
        cert_server_process = None
    
    # 启动证书服务器
    cert_server_script = project_root / "implementation" / "enhanced_v2" / "local_cert_server.py"
    
    # 检查脚本是否存在
    if not cert_server_script.exists():
        print(f"[API] ⚠️ 证书服务器脚本不存在: {cert_server_script}")
        return
    
    try:
        # 在Windows上，80端口可能需要管理员权限
        # 如果失败，尝试使用其他端口或给出提示
        cert_server_process = subprocess.Popen(
            [sys.executable, str(cert_server_script)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
        )
        # 注册到活动进程列表以便清理
        active_subprocesses.append(cert_server_process)
        
        # 等待服务器就绪（优化：减少等待时间）
        server_ready = False
        for i in range(10):  # 最多等待1秒（10次 * 0.1秒）
            time.sleep(0.1)
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.settimeout(0.05)  # 减少超时时间
                result = test_socket.connect_ex(('127.0.0.1', 80))
                test_socket.close()
                if result == 0:
                    print("[API] ✓ 本地证书服务器已启动（端口80）")
                    server_ready = True
                    break
            except Exception as e:
                pass
        
        if not server_ready:
            # 检查进程是否还在运行
            if cert_server_process.poll() is not None:
                # 进程已退出，读取错误信息
                try:
                    stdout, stderr = cert_server_process.communicate()
                    error_msg = stderr.decode('utf-8', errors='replace') if stderr else stdout.decode('utf-8', errors='replace')
                    print(f"[API] ⚠️ 证书服务器启动失败: {error_msg[:200]}")
                except:
                    print(f"[API] ⚠️ 证书服务器启动失败（无法读取错误信息）")
                print(f"[API] ⚠️ 提示: 在Windows上，80端口可能需要管理员权限")
                print(f"[API] ⚠️ 请手动启动证书服务器: python {cert_server_script}")
                cert_server_process = None
            else:
                print("[API] ⚠️ 本地证书服务器启动超时，但进程仍在运行")
                print("[API] ⚠️ 提示: 如果握手失败，请检查证书服务器是否在80端口运行")
    except Exception as e:
        print(f"[API] ⚠️ 启动证书服务器时出错: {e}")
        cert_server_process = None


def stop_cert_server():
    """停止本地证书服务器（仅停止由API服务器启动的进程）"""
    global cert_server_process
    if cert_server_process:
        try:
            cert_server_process.terminate()
            cert_server_process.wait(timeout=2)
        except:
            try:
                cert_server_process.kill()
            except:
                pass
        cert_server_process = None


@app.on_event("startup")
async def startup_event():
    """启动时初始化"""
    # 不再自动启动证书服务器，需要手动启动
    print("[API] 提示: by_ref模式需要手动启动证书服务器: python implementation/enhanced_v2/local_cert_server.py")


@app.on_event("shutdown")
async def shutdown_event():
    """关闭时清理"""
    # 只清理由API服务器启动的证书服务器进程
    stop_cert_server()


class RealHandshakeExecutor:
    """真实握手执行器 - 调用实际的客户端和服务器"""
    
    def __init__(self, mode: str, cert_mode: str = "by_val", algorithm: Optional[str] = None, kem: Optional[str] = None):
        self.mode = mode  # classic, pqc, hybrid
        self.cert_mode = cert_mode  # by_val, by_ref
        self.algorithm = algorithm or ("mldsa65" if mode != "classic" else "ecdsa_p256")
        self.kem = kem or ("p256_kyber768" if mode == "hybrid" else ("kyber768" if mode == "pqc" else "x25519"))
        self.messages = []
        self.start_time = None
        
    def execute(self) -> Dict[str, Any]:
        """执行真实握手"""
        self.start_time = time.time()
        
        # 根据cert_mode选择实现路径和执行方式
        if self.cert_mode == "by_ref":
            # by_ref模式：使用线程直接执行，避免子进程开销
            return self._execute_direct()
        else:
            # by_val模式：使用子进程执行
            return self._execute_subprocess()
    
    def _execute_direct(self) -> Dict[str, Any]:
        """直接执行握手（使用线程，避免子进程开销）"""
        # 导入时间追踪器
        from frontend.handshake_timing import HandshakeTimingTracker
        tracker = HandshakeTimingTracker()
        
        # 启动资源监控
        resource_monitor = ResourceMonitor()
        try:
            import psutil
            resource_monitor.start(psutil.Process())
        except:
            pass  # psutil不可用时跳过监控
        
        # 检查证书服务器是否运行（by_ref模式需要，但不自动启动）
        tracker.start_step("证书服务器检查")
        import time
        check_start = time.time()
        
        # 只检查服务器是否已经运行，不自动启动
        cert_server_ready = False
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(0.01)  # 非常短的超时
            result = test_socket.connect_ex(('127.0.0.1', 80))
            test_socket.close()
            if result == 0:
                cert_server_ready = True
        except:
            pass
        
        check_end = time.time()
        check_time = (check_end - check_start) * 1000
        tracker.finish_step({'ready': cert_server_ready, 'check_time_ms': check_time})
        
        if not cert_server_ready:
            return {
                'success': False,
                'error': '证书服务器未就绪（by_ref模式需要证书服务器运行在80端口）。请手动启动: python implementation/enhanced_v2/local_cert_server.py',
                'timing': tracker.get_summary()
            }
        
        # 根据cert_mode选择实现路径
        from implementation.enhanced_v2.config import ServerConfig, ClientConfig
        from implementation.enhanced_v2.enhanced_server import EnhancedTLSServer
        from implementation.enhanced_v2.enhanced_client import EnhancedTLSClient
        
        # 使用随机端口避免冲突
        import random
        server_port = random.randint(10000, 65535)
        
        # 使用线程直接执行，避免子进程开销
        server_error = [None]
        server_ready = threading.Event()
        server_timing = [None]  # 存储服务器端时间追踪
        
        def run_server():
            try:
                # 导入服务器端时间追踪器
                from frontend.handshake_timing import HandshakeTimingTracker
                server_tracker = HandshakeTimingTracker()
                
                # 先创建socket并监听，标记为就绪（减少等待时间）
                server_tracker.start_step("服务器Socket初始化")
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(('127.0.0.1', server_port))
                server_socket.listen(1)
                server_socket.settimeout(10)
                server_tracker.finish_step()
                
                server_ready.set()  # 服务器socket已就绪（在初始化TLS服务器之前）
                
                # 现在初始化TLS服务器（这可能需要一些时间加载证书）
                server_tracker.start_step("TLS服务器初始化")
                config = ServerConfig(
                    mode=self.mode,
                    host='127.0.0.1',
                    port=server_port,
                    algorithm=self.algorithm
                )
                server = EnhancedTLSServer(config)
                server_tracker.finish_step()
                
                # 接受客户端连接
                server_tracker.start_step("等待客户端连接")
                client_socket, addr = server_socket.accept()
                server_tracker.finish_step()
                
                try:
                    # 执行握手（这里会记录详细时间）
                    server_tracker.start_step("服务器握手处理")
                    server.handle_client(client_socket)
                    server_tracker.finish_step()
                except Exception as e:
                    server_error[0] = str(e)
                    import traceback
                    traceback.print_exc()
                finally:
                    try:
                        client_socket.close()
                    except:
                        pass
                    try:
                        server_socket.close()
                    except:
                        pass
                
                server_timing[0] = server_tracker.get_summary()
            except socket.timeout:
                server_error[0] = "服务器等待客户端连接超时"
            except Exception as e:
                server_error[0] = str(e)
                import traceback
                traceback.print_exc()
        
        # 启动服务器线程
        tracker.start_step("服务器线程启动")
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
        tracker.finish_step()
        
        # 等待服务器就绪（减少等待时间，通常很快）
        tracker.start_step("等待服务器就绪")
        if not server_ready.wait(timeout=0.2):
            tracker.finish_step()
            return {
                'success': False,
                'error': '服务器启动超时',
                'timing': tracker.get_summary()
            }
        tracker.finish_step()
        
        # 运行客户端（直接执行，不创建子进程）
        try:
            tracker.start_step("客户端初始化")
            client_config = ClientConfig(
                mode=self.mode,
                host='127.0.0.1',
                port=server_port,
                algorithm=self.algorithm
            )
            
            client = EnhancedTLSClient(client_config, tracker)  # 传入tracker以支持时间追踪
            tracker.finish_step()
            
            tracker.start_step("建立TCP连接")
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(10)
            client_socket.connect(('127.0.0.1', server_port))
            tracker.finish_step()
            
            # 只测量实际的握手时间（使用追踪器记录详细步骤）
            tracker.start_step("TLS握手执行")
            handshake_start = time.time()
            client.perform_enhanced_handshake(client_socket)
            handshake_end = time.time()
            handshake_time = (handshake_end - handshake_start) * 1000
            tracker.finish_step({'total_handshake_time_ms': handshake_time})
            
            tracker.start_step("清理连接")
            client_socket.close()
            tracker.finish_step()
            
            # 等待服务器线程完成（减少等待时间）
            tracker.start_step("等待服务器完成")
            server_thread.join(timeout=0.5)
            tracker.finish_step()
            
            if server_error[0]:
                return {
                    'success': False,
                    'error': f'服务器错误: {server_error[0]}',
                    'timing': tracker.get_summary(),
                    'server_timing': server_timing[0] if server_timing[0] else None
                }
            
            messages = self._generate_messages_from_output(handshake_time)
            
            # 获取时间追踪摘要
            timing_summary = tracker.get_summary()
            if server_timing[0]:
                timing_summary['server_timing'] = server_timing[0]
            
            # 停止资源监控并获取统计信息
            resource_stats = None
            try:
                resource_stats = resource_monitor.stop()
            except:
                pass
            
            result = {
                'success': True,
                'mode': self.mode,
                'cert_mode': self.cert_mode,
                'algorithm': self.algorithm,
                'kem': self.kem,
                'total_time': round(handshake_time, 2),
                'total_messages': len(messages),
                'client_to_server_size': sum(m['size'] for m in messages if m['direction'] == 'client_to_server'),
                'server_to_client_size': sum(m['size'] for m in messages if m['direction'] == 'server_to_client'),
                'total_size': sum(m['size'] for m in messages),
                'messages': messages,
                'timing': timing_summary
            }
            
            # 添加资源消耗数据
            if resource_stats:
                result['resources'] = resource_stats
            
            return result
            
        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            return {
                'success': False,
                'error': f'执行错误: {str(e)}',
            }
    
    def _execute_subprocess(self) -> Dict[str, Any]:
        """使用子进程执行握手（by_val模式）"""
        impl_path = "implementation.enhanced_v2_by_val"
        
        # 使用随机端口避免冲突
        import random
        server_port = random.randint(10000, 65535)
        
        # 创建临时测试脚本
        temp_dir = Path(tempfile.gettempdir())
        test_script = temp_dir / f"handshake_test_{int(time.time() * 1000)}.py"
        
        script_content = f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
import time
import socket
import threading
import json
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, r'{project_root}')

from {impl_path}.config import ServerConfig, ClientConfig
from {impl_path}.enhanced_server import EnhancedTLSServer
from {impl_path}.enhanced_client import EnhancedTLSClient
from frontend.handshake_timing import HandshakeTimingTracker

# 服务器错误标志和就绪事件
server_error = [None]
server_ready = threading.Event()
server_timing = [None]

def run_server():
    try:
        server_tracker = HandshakeTimingTracker()
        
        server_tracker.start_step("服务器Socket初始化")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('127.0.0.1', {server_port}))
        server_socket.listen(1)
        server_socket.settimeout(10)
        server_tracker.finish_step()
        
        server_ready.set()  # 服务器已就绪
        
        server_tracker.start_step("TLS服务器初始化")
        config = ServerConfig(
            mode='{self.mode}',
            host='127.0.0.1',
            port={server_port},
            algorithm='{self.algorithm}'
        )
        server = EnhancedTLSServer(config)
        server_tracker.finish_step()
        
        server_tracker.start_step("等待客户端连接")
        client_socket, addr = server_socket.accept()
        server_tracker.finish_step()
        
        try:
            server_tracker.start_step("服务器握手处理")
            server.handle_client(client_socket)
            server_tracker.finish_step()
        except Exception as e:
            server_error[0] = str(e)
            import traceback
            traceback.print_exc()
        finally:
            try:
                client_socket.close()
            except:
                pass
            try:
                server_socket.close()
            except:
                pass
        
        server_timing[0] = server_tracker.get_summary()
    except socket.timeout:
        server_error[0] = "服务器等待客户端连接超时"
    except Exception as e:
        server_error[0] = str(e)
        import traceback
        traceback.print_exc()

# 启动服务器线程
server_thread = threading.Thread(target=run_server, daemon=True)
server_thread.start()
# 等待服务器就绪（最多等待1秒）
if not server_ready.wait(timeout=1.0):
    raise Exception("服务器启动超时")

# 运行客户端
try:
    tracker = HandshakeTimingTracker()
    
    tracker.start_step("客户端初始化")
    client_config = ClientConfig(
        mode='{self.mode}',
        host='127.0.0.1',
        port={server_port},
        algorithm='{self.algorithm}'
    )
    
    client = EnhancedTLSClient(client_config, tracker)  # 传入tracker以支持时间追踪
    tracker.finish_step()
    
    tracker.start_step("建立TCP连接")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.settimeout(15)
    client_socket.connect(('127.0.0.1', {server_port}))
    tracker.finish_step()
    
    # 只测量实际的握手时间（客户端内部会记录详细步骤）
    tracker.start_step("TLS握手执行")
    handshake_start = time.time()
    client.perform_enhanced_handshake(client_socket)
    handshake_end = time.time()
    handshake_time = (handshake_end - handshake_start) * 1000
    tracker.finish_step({{'total_handshake_time_ms': handshake_time}})
    
    tracker.start_step("清理连接")
    client_socket.close()
    tracker.finish_step()
    
    # 等待服务器线程完成
    tracker.start_step("等待服务器完成")
    server_thread.join(timeout=2.0)
    tracker.finish_step()
    
    if server_error[0]:
        print(f"HANDSHAKE_ERROR|服务器错误: {{server_error[0]}}")
        timing_summary = tracker.get_summary()
        if server_timing[0]:
            timing_summary['server_timing'] = server_timing[0]
        print(f"TIMING_DATA|{{json.dumps(timing_summary)}}")
        sys.exit(1)
    
    timing_summary = tracker.get_summary()
    if server_timing[0]:
        timing_summary['server_timing'] = server_timing[0]
    
    print(f"HANDSHAKE_SUCCESS|{{handshake_time:.2f}}")
    print(f"TIMING_DATA|{{json.dumps(timing_summary)}}")
except Exception as e:
    import traceback
    error_msg = str(e)
    traceback.print_exc(file=sys.stderr)
    print(f"HANDSHAKE_ERROR|{{error_msg}}", file=sys.stderr)
    sys.exit(1)
'''
        
        try:
            # 写入临时脚本
            test_script.write_text(script_content, encoding='utf-8')
            temp_files.append(test_script)
            
            # 执行脚本
            proc = subprocess.Popen(
                [sys.executable, str(test_script)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace',
                cwd=str(project_root),
                env={**os.environ, 'PYTHONIOENCODING': 'utf-8'}
            )
            
            active_subprocesses.append(proc)
            
            # 启动资源监控（监控子进程）
            resource_monitor = ResourceMonitor()
            resource_stats = None
            try:
                import psutil
                resource_monitor.start(psutil.Process(proc.pid))
            except:
                pass  # psutil不可用时跳过监控
            
            # 等待进程完成（减少超时时间，因为实际握手应该很快）
            try:
                stdout, stderr = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
                raise subprocess.TimeoutExpired(proc.args, 10, stdout, stderr)
            finally:
                # 停止资源监控
                try:
                    resource_stats = resource_monitor.stop()
                except:
                    pass
                
                if proc in active_subprocesses:
                    active_subprocesses.remove(proc)
            
            # 解析输出
            if proc.returncode != 0:
                error_msg = stderr.strip() if stderr.strip() else stdout.strip()
                if not error_msg:
                    error_msg = f"进程返回非零退出码: {proc.returncode}"
                return {
                    'success': False,
                    'error': error_msg[:500],
                }
            elif "HANDSHAKE_SUCCESS" in stdout:
                match = re.search(r'HANDSHAKE_SUCCESS\|([\d.]+)', stdout)
                if match:
                    handshake_time = float(match.group(1))
                else:
                    # 如果无法解析，使用默认值（不应该发生）
                    handshake_time = 50.0  # 默认50ms
                
                # 解析时间数据
                timing_data = None
                timing_match = re.search(r'TIMING_DATA\|(.+)', stdout, re.DOTALL)
                if timing_match:
                    try:
                        timing_data = json.loads(timing_match.group(1))
                    except:
                        pass
                
                messages = self._generate_messages_from_output(handshake_time)
                
                result = {
                    'success': True,
                    'mode': self.mode,
                    'cert_mode': self.cert_mode,
                    'algorithm': self.algorithm,
                    'kem': self.kem,
                    'total_time': round(handshake_time, 2),
                    'total_messages': len(messages),
                    'client_to_server_size': sum(m['size'] for m in messages if m['direction'] == 'client_to_server'),
                    'server_to_client_size': sum(m['size'] for m in messages if m['direction'] == 'server_to_client'),
                    'total_size': sum(m['size'] for m in messages),
                    'messages': messages
                }
                
                if timing_data:
                    result['timing'] = timing_data
                
                # 添加资源消耗数据
                if resource_stats:
                    result['resources'] = resource_stats
                
                return result
            else:
                error_msg = stderr.strip() if stderr.strip() else stdout.strip()
                if "HANDSHAKE_ERROR" in error_msg:
                    match = re.search(r'HANDSHAKE_ERROR\|(.+)', error_msg, re.DOTALL)
                    if match:
                        error_msg = match.group(1).strip()
                
                return {
                    'success': False,
                    'error': error_msg[:500] if error_msg else '握手失败',
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': '握手超时（超过10秒）',
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'执行错误: {str(e)}',
            }
        finally:
            # 清理临时脚本
            if test_script.exists():
                try:
                    test_script.unlink()
                except:
                    pass
    
    def _get_certificate_chain_size(self) -> int:
        """获取证书链的实际大小"""
        try:
            if self.cert_mode == 'by_val':
                from implementation.enhanced_v2_by_val.config import get_cert_config
                config = get_cert_config(self.algorithm)
                paths = config.get_cert_paths()
                
                server_cert_size = os.path.getsize(paths['server_cert']) if os.path.exists(paths['server_cert']) else 0
                server_sig_size = os.path.getsize(paths['server_sig']) if os.path.exists(paths['server_sig']) else 0
                intermediate_cert_size = os.path.getsize(paths['intermediate_cert']) if os.path.exists(paths['intermediate_cert']) else 0
                intermediate_sig_size = os.path.getsize(paths['intermediate_sig']) if os.path.exists(paths['intermediate_sig']) else 0
                
                return server_cert_size + server_sig_size + intermediate_cert_size + intermediate_sig_size
            else:
                from implementation.enhanced_v2.config import get_cert_config
                config = get_cert_config(self.algorithm)
                paths = config.get_cert_paths()
                
                server_cert_size = os.path.getsize(paths['server_cert']) if os.path.exists(paths['server_cert']) else 0
                intermediate_cert_size = os.path.getsize(paths['intermediate_cert']) if os.path.exists(paths['intermediate_cert']) else 0
                
                return server_cert_size + intermediate_cert_size
        except Exception as e:
            print(f"[警告] 无法读取证书文件大小: {e}")
            return 12000 if self.cert_mode == 'by_val' else 4000
    
    def _get_signature_size(self) -> Optional[int]:
        """获取CertificateVerify签名的实际大小"""
        try:
            if self.cert_mode == 'by_val':
                from implementation.enhanced_v2_by_val.config import get_cert_config
                config = get_cert_config(self.algorithm)
                paths = config.get_cert_paths()
                if os.path.exists(paths['server_sig']):
                    return os.path.getsize(paths['server_sig'])
            else:
                from implementation.enhanced_v2.config import get_cert_config
                config = get_cert_config(self.algorithm)
                paths = config.get_cert_paths()
                if os.path.exists(paths['server_sig']):
                    return os.path.getsize(paths['server_sig'])
            return None
        except Exception as e:
            return None
    
    def _generate_messages_from_output(self, total_time: float) -> List[Dict]:
        """从输出生成消息列表"""
        messages = []
        base_time = 0
        
        cert_chain_size = self._get_certificate_chain_size()
        signature_size = self._get_signature_size() or 500
        
        # 注意：total_time已经是实际测量的握手时间
        # by_ref模式的HTTP请求时间已经包含在实际测量的握手时间内，不需要额外添加
        
        message_sequence = [
            ('client_to_server', 'ClientHello', 300),
            ('server_to_client', 'ServerHello', 250),
            ('server_to_client', 'Certificate', cert_chain_size),
            ('server_to_client', 'CertificateVerify', signature_size),
            ('server_to_client', 'Finished', 36),
            ('client_to_server', 'Finished', 36),
        ]
        
        time_per_message = total_time / len(message_sequence)
        
        for i, (direction, msg_type, base_size) in enumerate(message_sequence):
            messages.append({
                'index': i + 1,
                'direction': direction,
                'message_type': msg_type,
                'size': base_size,
                'timestamp': round(base_time + time_per_message * (i + 1), 2),
                'raw_hex': f'{"00" * min(50, base_size)}...',
                'decoded': {}
            })
        
        return messages


@app.get("/")
async def read_root():
    """主页面"""
    html_path = Path(__file__).parent / "index.html"
    return FileResponse(html_path, headers={"Cache-Control": "no-cache"})


@app.post("/api/handshake/execute")
async def execute_handshake(request: HandshakeRequest):
    """执行真实TLS握手"""
    mode = request.mode
    cert_mode = request.cert_mode
    algorithm = request.algorithm
    kem = request.kem
    
    if mode not in ['classic', 'pqc', 'hybrid']:
        raise HTTPException(status_code=400, detail=f"无效的模式: {mode}")
    if cert_mode not in ['by_val', 'by_ref']:
        raise HTTPException(status_code=400, detail=f"无效的证书模式: {cert_mode}")
    
    try:
        executor = RealHandshakeExecutor(mode, cert_mode, algorithm, kem)
        result = executor.execute()
        
        if not result.get('success'):
            raise HTTPException(status_code=500, detail=result.get('error', '未知错误'))
        
        # 注意：握手测试返回的是实际测量的握手时间（本地回环，无网络延迟）
        # by_ref模式的HTTP请求时间已经包含在实际测量中（因为是真实的HTTP请求）
        # 这与模式对比中的计算方式不同：
        # - 握手测试：实际测量时间（包含真实HTTP请求时间）
        # - 模式对比：基础握手时间 + 模拟的网络传输延迟 + 模拟的HTTP请求开销
        
        session_id = f"{mode}_{cert_mode}_{int(time.time())}"
        handshake_sessions[session_id] = result
        result['session_id'] = session_id
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"[API] 异常详情:\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"握手执行异常: {str(e)}")


@app.get("/api/benchmark/compare")
async def compare_benchmark():
    """获取基准测试对比数据"""
    # 加载by_val测试数据
    by_val_data_path = project_root / "benchmarks copy" / "results" / "batch_tests" / "comprehensive_20251019_212329" / "handshake_benchmark_20251019_212340.json"
    
    if not by_val_data_path.exists():
        raise HTTPException(status_code=404, detail="基准测试数据文件不存在")
    
    with open(by_val_data_path, 'r', encoding='utf-8') as f:
        by_val_data = json.load(f)
    
    # 转换时间单位：秒 -> 毫秒
    for item in by_val_data.get('handshake', []):
        if 'avg_time' in item:
            item['avg_time'] = item['avg_time'] * 1000
    
    # 生成by_ref数据
    by_ref_data = generate_byref_data(by_val_data)
    
    # 计算对比数据
    comparison = calculate_comparison(by_val_data, by_ref_data)
    
    return {
        'success': True,
        'by_val': by_val_data,
        'by_ref': by_ref_data,
        'comparison': comparison,
    }


def generate_byref_data(by_val_data: Dict) -> Dict:
    """基于by_val数据生成by_ref数据"""
    by_ref_handshake = []
    
    # 加载证书大小数据
    cert_sizes_file = project_root / "frontend" / "cert_sizes.json"
    cert_sizes = {}
    if cert_sizes_file.exists():
        with open(cert_sizes_file, 'r', encoding='utf-8') as f:
            cert_sizes_data = json.load(f)
            cert_sizes = cert_sizes_data.get('cert_sizes', {})
    
    for item in by_val_data.get('handshake', []):
        cert_size_by_val = item['sizes']['certificate']
        
        # 使用实际证书大小（默认使用mldsa65）
        algorithm = 'mldsa65'
        if cert_sizes.get(algorithm):
            by_ref_info = cert_sizes[algorithm].get('by_ref', {})
            cert_size_by_ref = by_ref_info.get('total_certificate_chain_size', int(cert_size_by_val * 0.08))
        else:
            cert_size_by_ref = int(cert_size_by_val * 0.08)
        
        total_size_by_val = item['sizes']['total']
        size_reduction = cert_size_by_val - cert_size_by_ref
        total_size_by_ref = total_size_by_val - size_reduction
        
        avg_time_by_val = item['avg_time']  # 已经是毫秒单位
        
        # 服务器端优化：证书传输时间减少
        server_side_saving = avg_time_by_val * 0.1
        
        # 客户端HTTP请求开销
        client_http_overhead = 2.5
        
        avg_time_by_ref = avg_time_by_val - server_side_saving + client_http_overhead
        
        throughput_by_ref = 1000.0 / avg_time_by_ref if avg_time_by_ref > 0 else 0
        operations_by_ref = int(throughput_by_ref * 10)
        
        by_ref_item = {
            'name': item['name'].replace('classic', 'classic-by_ref').replace('pqc', 'pqc-by_ref').replace('hybrid', 'hybrid-by_ref'),
            'avg_time': round(avg_time_by_ref, 2),
            'throughput': round(throughput_by_ref, 1),
            'operations_in_10s': operations_by_ref,
            'sizes': {
                'client_hello': item['sizes']['client_hello'],
                'server_hello': item['sizes']['server_hello'],
                'certificate': cert_size_by_ref,
                'total': total_size_by_ref,
                'cert_enabled': True,
                'http_requests': 2
            }
        }
        by_ref_handshake.append(by_ref_item)
    
    return {
        'timestamp': by_val_data.get('timestamp', ''),
        'test_type': 'handshake_only',
        'handshake': by_ref_handshake
    }


def calculate_comparison(by_val_data: Dict, by_ref_data: Dict) -> Dict:
    """计算by_val和by_ref的对比数据"""
    by_val_handshake = by_val_data.get('handshake', [])
    by_ref_handshake = by_ref_data.get('handshake', [])
    
    if by_val_handshake and by_ref_handshake:
        val_item = by_val_handshake[0]
        ref_item = by_ref_handshake[0]
        
        cert_size_by_val = val_item['sizes']['certificate']
        cert_size_by_ref = ref_item['sizes']['certificate']
        cert_size_reduction_bytes = cert_size_by_val - cert_size_by_ref
        cert_size_reduction_percent = ((cert_size_by_val - cert_size_by_ref) / cert_size_by_val) * 100
        
        time_changes = []
        size_reductions = []
        
        for val_item, ref_item in zip(by_val_handshake, by_ref_handshake):
            time_change = ((val_item['avg_time'] - ref_item['avg_time']) / val_item['avg_time']) * 100
            size_reduction = ((val_item['sizes']['total'] - ref_item['sizes']['total']) / val_item['sizes']['total']) * 100
            time_changes.append(time_change)
            size_reductions.append(size_reduction)
        
        avg_time_change = sum(time_changes) / len(time_changes) if time_changes else 0
        avg_size_reduction = sum(size_reductions) / len(size_reductions) if size_reductions else 0
        avg_handshake_time = sum(item['avg_time'] for item in by_val_handshake) / len(by_val_handshake) if by_val_handshake else 0
        transmission_time_saving = avg_handshake_time * 0.1
        
        return {
            'cert_mode_comparison': {
                'cert_size_reduction_bytes': cert_size_reduction_bytes,
                'cert_size_reduction_percent': round(cert_size_reduction_percent, 2),
                'avg_time_change_percent': round(avg_time_change, 2),
                'avg_size_reduction_percent': round(avg_size_reduction, 2),
                'server_side_benefit': {
                    'cert_size_reduction_bytes': cert_size_reduction_bytes,
                    'transmission_time_saving_ms': round(transmission_time_saving, 2)
                },
                'client_side_overhead': {
                    'http_requests': 2,
                    'estimated_latency_ms': 2.5
                }
            }
        }
    
    return {}


@app.post("/api/compare-modes")
async def compare_modes(
    request: Request
):
    """对比by_val和by_ref模式，使用真实的握手延迟"""
    try:
        body = await request.json()
        mode = body.get("mode", "hybrid")
        algorithm = body.get("algorithm", "mldsa65")
        runs = body.get("runs", 1)
        network_condition = body.get("network_condition", "loopback")
        network_bandwidth_mbps = body.get("network_bandwidth_mbps", 10.0)  # Mbps
        
        # 验证runs参数
        if runs < 1:
            runs = 1
        elif runs > 20:  # 限制最大运行次数，避免过度负载
            runs = 20

        print(f"[API] 开始模式对比测试 - 模式:{mode}, 算法:{algorithm}, 运行次数:{runs}, 网络条件:{network_condition}")

        # 加载证书大小数据
        cert_sizes_file = project_root / "frontend" / "cert_sizes.json"
        cert_sizes = {}
        if cert_sizes_file.exists():
            with open(cert_sizes_file, 'r', encoding='utf-8') as f:
                cert_sizes_data = json.load(f)
                cert_sizes = cert_sizes_data.get('cert_sizes', {}).get(algorithm, {})

        def calculate_average_result(results_list):
            """计算多次测试结果的平均值"""
            if not results_list:
                return None

            # 使用第一个结果作为模板
            avg_result = results_list[0].copy()

            # 计算数值字段的平均值
            numeric_fields = ['total_time', 'total_messages', 'client_to_server_size',
                            'server_to_client_size', 'total_size']

            for field in numeric_fields:
                if field in avg_result:
                    values = [r.get(field, 0) for r in results_list]
                    avg_result[field] = sum(values) / len(values)

            # 合并timing数据（取最后一次的，因为timing包含详细步骤）
            # 或者可以实现更复杂的timing平均计算
            avg_result['timing'] = results_list[-1].get('timing', {})
            
            # 合并资源消耗数据（计算平均值）
            resources_list = [r.get('resources') for r in results_list if r.get('resources')]
            if resources_list:
                avg_resources = {
                    'cpu': {
                        'avg_percent': sum(r['cpu']['avg_percent'] for r in resources_list) / len(resources_list),
                        'max_percent': max(r['cpu']['max_percent'] for r in resources_list),
                        'min_percent': min(r['cpu']['min_percent'] for r in resources_list),
                        'samples': sum(r['cpu'].get('samples', 0) for r in resources_list)
                    },
                    'memory': {
                        'avg_mb': sum(r['memory']['avg_mb'] for r in resources_list) / len(resources_list),
                        'max_mb': max(r['memory']['max_mb'] for r in resources_list),
                        'min_mb': min(r['memory']['min_mb'] for r in resources_list),
                        'peak_mb': max(r['memory'].get('peak_mb', r['memory']['max_mb']) for r in resources_list),
                        'samples': sum(r['memory'].get('samples', 0) for r in resources_list)
                    }
                }
                avg_result['resources'] = avg_resources
            elif results_list[-1].get('resources'):
                # 如果没有多个资源数据，使用最后一个
                avg_result['resources'] = results_list[-1].get('resources')

            # 添加测试次数信息
            avg_result['_run_count'] = len(results_list)
            avg_result['_total_runs'] = len(results_list)

            return avg_result

        # 执行多次测试并计算平均值
        def run_comparison_test():
            """执行单次对比测试"""
            try:
                # 执行by_val握手
                executor_byval = RealHandshakeExecutor(mode, "by_val", algorithm)
                result_byval = executor_byval.execute()

                if not result_byval.get('success'):
                    raise Exception(f"by_val握手失败: {result_byval.get('error')}")

                # 执行by_ref握手
                executor_byref = RealHandshakeExecutor(mode, "by_ref", algorithm)
                result_byref = executor_byref.execute()

                if not result_byref.get('success'):
                    raise Exception(f"by_ref握手失败: {result_byref.get('error')}")

                return result_byval, result_byref
            except Exception as e:
                print(f"[API] 单次测试失败: {e}")
                raise

        # 执行多次测试并计算平均值
        if runs == 1:
            print(f"[API] 执行单次对比测试...")
            result_byval, result_byref = run_comparison_test()
        else:
            print(f"[API] 执行{runs}次对比测试并计算平均值...")
            results_byval = []
            results_byref = []

            for i in range(runs):
                print(f"[API] 执行第{i+1}/{runs}次测试...")
                try:
                    result_byval, result_byref = run_comparison_test()
                    results_byval.append(result_byval)
                    results_byref.append(result_byref)
                    print(f"[API] 第{i+1}次测试成功完成")
                except Exception as e:
                    print(f"[API] 第{i+1}次测试失败，跳过: {e}")
                    continue

            if not results_byval or not results_byref:
                raise Exception("所有测试都失败了，无法计算平均值")

            # 计算平均值
            print(f"[API] 计算{runs}次测试的平均值...")
            result_byval = calculate_average_result(results_byval)
            result_byref = calculate_average_result(results_byref)
        
        # 获取证书大小
        byval_cert_size = cert_sizes.get('by_val', {}).get('total_certificate_chain_size', 0)
        byref_cert_size = cert_sizes.get('by_ref', {}).get('total_certificate_chain_size', 0)
        cert_size_reduction = byval_cert_size - byref_cert_size
        cert_size_reduction_percent = (cert_size_reduction / byval_cert_size * 100) if byval_cert_size > 0 else 0
        
        # 计算实际的TLS握手时间（从timing数据中提取）
        def extract_handshake_time(result):
            """从结果中提取实际的TLS握手时间"""
            timing = result.get('timing', {})
            if not timing:
                return result.get('total_time', 0)
            
            # 查找TLS握手执行步骤
            steps = timing.get('steps', [])
            excluded_steps = [
                '证书服务器检查', '服务器线程启动', '等待服务器就绪',
                '客户端初始化', '建立TCP连接', '清理连接', '等待服务器完成',
                '服务器Socket初始化', 'TLS服务器初始化', '等待客户端连接',
                'TLS握手执行'  # 排除总步骤，只显示详细步骤
            ]
            
            # 方法1：查找total_handshake_time_ms
            for step in steps:
                if step.get('step_name') == 'TLS握手执行':
                    details = step.get('details', {})
                    if 'total_handshake_time_ms' in details:
                        return details['total_handshake_time_ms']
            
            # 方法2：累加所有握手相关步骤的时间
            handshake_time = 0
            for step in steps:
                step_name = step.get('step_name', '')
                if step_name not in excluded_steps:
                    handshake_time += step.get('duration_ms', 0)
            
            return handshake_time if handshake_time > 0 else result.get('total_time', 0)
        
        byval_time = extract_handshake_time(result_byval)
        byref_time = extract_handshake_time(result_byref)
        
        # 注意：这里计算的time_change是基础握手时间的差异
        # 实际的网络传输时间会在后面添加
        time_change = byref_time - byval_time
        time_change_percent = (time_change / byval_time * 100) if byval_time > 0 else 0
        
        byval_total_size = result_byval.get('total_size', 0)
        byref_total_size = result_byref.get('total_size', 0)
        size_reduction = byval_total_size - byref_total_size
        size_reduction_percent = (size_reduction / byval_total_size * 100) if byval_total_size > 0 else 0
        
        # 统计握手消息大小（用于饼图展示）
        def get_message_sizes(result, cert_mode):
            """从结果中提取各消息的大小"""
            messages = result.get('messages', [])
            if messages and len(messages) > 0:
                # 从messages中提取
                message_sizes = {}
                for msg in messages:
                    msg_type = msg.get('message_type', '')
                    size = msg.get('size', 0)
                    if msg_type and size > 0:
                        message_sizes[msg_type] = size
                if len(message_sizes) > 0:
                    return message_sizes
            
            # 如果没有messages，根据cert_mode和证书大小估算
            if cert_mode == 'by_val':
                cert_chain_size = byval_cert_size
            else:
                cert_chain_size = byref_cert_size
            
            # 估算签名大小（根据算法）
            signature_size = 500  # 默认值
            if algorithm.startswith('mldsa'):
                signature_size = 2420 if '44' in algorithm else (2944 if '65' in algorithm else 4191)
            elif algorithm.startswith('falcon'):
                signature_size = 666 if '512' in algorithm else 1280
            
            return {
                'ClientHello': 300,
                'ServerHello': 250,
                'Certificate': cert_chain_size,
                'CertificateVerify': signature_size,
                'Finished': 36
            }
        
        byval_message_sizes = get_message_sizes(result_byval, 'by_val')
        byref_message_sizes = get_message_sizes(result_byref, 'by_ref')
        
        # 计算网络条件下的传输延迟
        network_latencies = {
            'loopback': 0.1,    # 本地回环，0.1ms
            'lan': 1.0,         # 局域网，1ms
            'wifi': 5.0,        # WiFi，5ms
            '4g': 50.0,         # 4G移动网络，50ms
            '3g': 100.0,        # 3G移动网络，100ms
            'slow': 200.0,      # 慢速网络，200ms
            'satellite': 500.0  # 卫星网络，500ms
        }

        base_latency = network_latencies.get(network_condition, 0.1)

        # 将带宽从Mbps转换为字节/毫秒
        # 1 Mbps = 1,000,000 bits/s = 125,000 bytes/s = 125 bytes/ms
        bandwidth_bytes_per_ms = (network_bandwidth_mbps * 1_000_000) / (8 * 1000)  # bytes/ms

        def calculate_transmission_time(size_bytes, network_condition, bandwidth_bytes_per_ms):
            """计算在指定网络条件下传输指定大小数据的时间"""
            base_delay = network_latencies.get(network_condition, 0.1)
            # 传输延迟 = 基础延迟（RTT/2，单向延迟） + 数据传输时间
            if bandwidth_bytes_per_ms > 0:
                transmission_delay = size_bytes / bandwidth_bytes_per_ms
            else:
                transmission_delay = 0
            return base_delay + transmission_delay

        # 计算by_val和by_ref的证书传输时间
        by_val_cert_time = calculate_transmission_time(byval_cert_size, network_condition, bandwidth_bytes_per_ms)
        by_ref_cert_time = calculate_transmission_time(byref_cert_size, network_condition, bandwidth_bytes_per_ms)
        
        # 计算总数据量的传输时间（包括所有握手消息）
        # by_val模式：证书链较大，传输时间更长
        by_val_total_transmission_time = calculate_transmission_time(byval_total_size, network_condition, bandwidth_bytes_per_ms)
        by_ref_total_transmission_time = calculate_transmission_time(byref_total_size, network_condition, bandwidth_bytes_per_ms)

        # by_ref模式需要额外的HTTP请求延迟（获取PQ组件）
        # HTTP请求包括：请求头 + 响应数据
        # 假设每次HTTP请求：请求头约500字节，响应数据约2000字节（公钥或签名）
        http_request_size = 500 + 2000  # 每次HTTP请求的总数据量（请求+响应）
        http_request_count = 2  # 2次HTTP请求（公钥和签名）
        # HTTP请求开销 = RTT延迟 + 数据传输时间
        # 每次请求：RTT = base_latency * 2（往返），数据传输时间 = http_request_size / bandwidth_bytes_per_ms
        single_http_overhead = (base_latency * 2) + (http_request_size / bandwidth_bytes_per_ms if bandwidth_bytes_per_ms > 0 else 0)
        http_request_overhead = single_http_overhead * http_request_count

        # 计算服务器端传输时间节省
        server_transmission_saving = by_val_cert_time - by_ref_cert_time
        server_transmission_saving_percent = (server_transmission_saving / by_val_cert_time * 100) if by_val_cert_time > 0 else 0
        
        # 将网络传输时间添加到实际的握手时间中
        # by_val: 基础握手时间 + 证书传输时间
        byval_time_with_network = byval_time + by_val_cert_time
        byref_time_with_network = byref_time + by_ref_cert_time + http_request_overhead
        
        # 计算时间变化
        time_change_with_network = byref_time_with_network - byval_time_with_network
        time_change_percent_with_network = (time_change_with_network / byval_time_with_network * 100) if byval_time_with_network > 0 else 0

        return {
            'success': True,
            'mode': mode,
            'algorithm': algorithm,
            'runs': runs,
            'network_condition': network_condition,
            'runs': runs,
            'by_val': {
                'handshake_time_ms': round(byval_time, 2),  # 基础握手时间（本地）
                'handshake_time_with_network_ms': round(byval_time_with_network, 2),  # 包含网络传输时间
                'certificate_size_bytes': byval_cert_size,
                'total_size_bytes': byval_total_size,
                'network_transmission_time_ms': round(by_val_cert_time, 3),
                'message_sizes': byval_message_sizes,  # 各消息的大小
                'timing': result_byval.get('timing'),  # 包含完整的时间追踪数据
                'resources': result_byval.get('resources')  # 资源消耗数据
            },
            'by_ref': {
                'handshake_time_ms': round(byref_time, 2),  # 基础握手时间（本地）
                'handshake_time_with_network_ms': round(byref_time_with_network, 2),  # 包含网络传输时间
                'certificate_size_bytes': byref_cert_size,
                'total_size_bytes': byref_total_size,
                'http_requests': 2,
                'estimated_http_latency_ms': round(http_request_overhead, 2),
                'network_transmission_time_ms': round(by_ref_cert_time, 3),
                'message_sizes': byref_message_sizes,  # 各消息的大小
                'timing': result_byref.get('timing'),  # 包含完整的时间追踪数据
                'resources': result_byref.get('resources')  # 资源消耗数据
            },
            'comparison': {
                'time_change_ms': round(time_change, 2),  # 基础握手时间差异
                'time_change_percent': round(time_change_percent, 2),
                'time_change_with_network_ms': round(time_change_with_network, 2),  # 包含网络传输的时间差异
                'time_change_with_network_percent': round(time_change_percent_with_network, 2),
                'cert_size_reduction_bytes': cert_size_reduction,
                'cert_size_reduction_percent': round(cert_size_reduction_percent, 2),
                'size_reduction_bytes': size_reduction,
                'size_reduction_percent': round(size_reduction_percent, 2),
                'server_side_benefit': {
                    'cert_size_reduction_bytes': cert_size_reduction,
                    'transmission_time_saving_ms': round(server_transmission_saving, 3),
                    'transmission_time_saving_percent': round(server_transmission_saving_percent, 2)
                },
                'client_side_overhead': {
                    'http_requests': 2,
                    'estimated_latency_ms': round(http_request_overhead, 2)
                },
                'network_simulation': {
                    'condition': network_condition,
                    'bandwidth_mbps': network_bandwidth_mbps,
                    'bandwidth_bytes_per_ms': round(bandwidth_bytes_per_ms, 2),
                    'base_latency_ms': base_latency,
                    'by_val_cert_transmission_ms': round(by_val_cert_time, 3),
                    'by_ref_cert_transmission_ms': round(by_ref_cert_time, 3),
                    'by_val_total_transmission_ms': round(by_val_total_transmission_time, 3),
                    'by_ref_total_transmission_ms': round(by_ref_total_transmission_time, 3),
                    'http_overhead_ms': round(http_request_overhead, 2),
                    'transmission_time_saving_ms': round(server_transmission_saving, 3)
                }
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"[API] 模式对比异常:\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"模式对比失败: {str(e)}")


@app.get("/api/cert-sizes")
async def get_cert_sizes_api():
    """获取证书大小数据"""
    cert_sizes_file = project_root / "frontend" / "cert_sizes.json"
    if cert_sizes_file.exists():
        with open(cert_sizes_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    else:
        raise HTTPException(status_code=404, detail="证书大小文件不存在，请先运行get_cert_sizes.py")


@app.post("/api/bandwidth-comparison")
async def bandwidth_comparison(request: Request):
    """生成不同带宽下的握手延迟对比数据"""
    try:
        body = await request.json()
        mode = body.get("mode", "hybrid")
        algorithm = body.get("algorithm", "mldsa65")
        network_latency = body.get("network_latency", "loopback")
        
        print(f"[API] 生成带宽对比数据 - 模式:{mode}, 算法:{algorithm}, 网络延迟:{network_latency}")
        
        # 定义测试的带宽范围（Mbps）
        bandwidths_mbps = [0.01, 0.056, 0.1, 1, 10, 100, 1000]
        
        # 网络延迟配置
        network_latencies = {
            'loopback': 0.1,
            'lan': 1.0,
            'wifi': 5.0,
            '4g': 50.0,
            '3g': 100.0,
            'slow': 200.0,
            'satellite': 500.0
        }
        base_latency = network_latencies.get(network_latency, 0.1)
        
        # 加载证书大小数据
        cert_sizes_file = project_root / "frontend" / "cert_sizes.json"
        cert_sizes = {}
        if cert_sizes_file.exists():
            with open(cert_sizes_file, 'r', encoding='utf-8') as f:
                cert_sizes_data = json.load(f)
                cert_sizes = cert_sizes_data.get('cert_sizes', {}).get(algorithm, {})
        
        byval_cert_size = cert_sizes.get('by_val', {}).get('total_certificate_chain_size', 12000)
        byref_cert_size = cert_sizes.get('by_ref', {}).get('total_certificate_chain_size', 1000)
        
        # 执行一次实际握手获取基础握手时间
        executor_byval = RealHandshakeExecutor(mode, "by_val", algorithm)
        result_byval = executor_byval.execute()
        
        executor_byref = RealHandshakeExecutor(mode, "by_ref", algorithm)
        result_byref = executor_byref.execute()
        
        if not result_byval.get('success') or not result_byref.get('success'):
            raise Exception("无法获取基础握手时间")
        
        # 提取基础握手时间
        def extract_handshake_time(result):
            timing = result.get('timing', {})
            if not timing:
                return result.get('total_time', 0)
            steps = timing.get('steps', [])
            for step in steps:
                if step.get('step_name') == 'TLS握手执行':
                    details = step.get('details', {})
                    if 'total_handshake_time_ms' in details:
                        return details['total_handshake_time_ms']
            return result.get('total_time', 0)
        
        byval_base_time = extract_handshake_time(result_byval)
        byref_base_time = extract_handshake_time(result_byref)
        
        # 计算不同带宽下的握手延迟
        byval_delays = []
        byref_delays = []
        
        for bandwidth_mbps in bandwidths_mbps:
            # 将带宽从Mbps转换为字节/毫秒
            bandwidth_bytes_per_ms = (bandwidth_mbps * 1_000_000) / (8 * 1000)
            
            # 计算证书传输时间
            def calculate_transmission_time(size_bytes, bandwidth_bytes_per_ms):
                if bandwidth_bytes_per_ms > 0:
                    transmission_delay = size_bytes / bandwidth_bytes_per_ms
                else:
                    transmission_delay = 0
                return base_latency + transmission_delay
            
            by_val_cert_time = calculate_transmission_time(byval_cert_size, bandwidth_bytes_per_ms)
            by_ref_cert_time = calculate_transmission_time(byref_cert_size, bandwidth_bytes_per_ms)
            
            # HTTP请求开销（by_ref模式）
            http_request_size = 500 + 2000  # 每次HTTP请求的总数据量
            http_request_count = 2
            single_http_overhead = (base_latency * 2) + (http_request_size / bandwidth_bytes_per_ms if bandwidth_bytes_per_ms > 0 else 0)
            http_request_overhead = single_http_overhead * http_request_count
            
            # 计算总握手延迟
            byval_delay = byval_base_time + by_val_cert_time
            byref_delay = byref_base_time + by_ref_cert_time + http_request_overhead
            
            byval_delays.append(round(byval_delay, 2))
            byref_delays.append(round(byref_delay, 2))
        
        # 准备数据来源说明
        data_source = {
            'test_config': f'TLS模式: {mode.upper()}, 签名算法: {algorithm.upper()}, 网络延迟: {network_latency} ({base_latency}ms)',
            'calculation_method': '握手延迟 = 基础握手时间（实际测量） + 证书传输时间（基于带宽计算） + HTTP请求开销（by_ref模式，基于带宽计算）',
            'network_latency': f'{network_latency} ({base_latency}ms)',
            'description': f'基础握手时间：by_val={byval_base_time:.2f}ms, by_ref={byref_base_time:.2f}ms（本地回环实际测量）。证书大小：by_val={byval_cert_size}字节, by_ref={byref_cert_size}字节。带宽范围：10 Kbps - 1 Gbps。'
        }
        
        return {
            'success': True,
            'mode': mode,
            'algorithm': algorithm,
            'network_latency': network_latency,
            'bandwidths': bandwidths_mbps,
            'by_val_delays': byval_delays,
            'by_ref_delays': byref_delays,
            'data_source': data_source
        }
        
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"[API] 带宽对比异常:\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"带宽对比失败: {str(e)}")


@app.post("/api/algorithm-comparison")
async def algorithm_comparison(request: Request):
    """对比经典TLS、纯PQC-TLS和混合TLS三种模式"""
    try:
        body = await request.json()
        cert_mode = body.get("cert_mode", "by_val")
        runs = body.get("runs", 3)
        
        # 获取各模式的KEM和签名算法配置（支持旧版本API）
        classic_config = body.get("classic", {})
        pqc_config = body.get("pqc", {})
        hybrid_config = body.get("hybrid", {})
        
        # 兼容旧版本API（如果没有提供各模式配置，使用全局algorithm参数）
        if not classic_config and not pqc_config and not hybrid_config:
            algorithm = body.get("algorithm", "mldsa65")
            classic_config = {"kem": "x25519", "signature": "ecdsa_p256"}
            pqc_config = {"kem": "kyber768", "signature": algorithm}
            hybrid_config = {"kem": "p256_kyber768", "signature": algorithm}
        
        classic_kem = classic_config.get("kem", "x25519")
        classic_sig = classic_config.get("signature", "ecdsa_p256")
        pqc_kem = pqc_config.get("kem", "kyber768")
        pqc_sig = pqc_config.get("signature", "mldsa65")
        hybrid_kem = hybrid_config.get("kem", "p256_kyber768")
        hybrid_sig = hybrid_config.get("signature", "mldsa65")
        
        # 验证runs参数
        if runs < 1:
            runs = 1
        elif runs > 20:
            runs = 20
        
        print(f"[API] 开始算法对比测试 - 证书模式:{cert_mode}, 运行次数:{runs}")
        print(f"[API] 经典TLS: KEM={classic_kem}, 签名={classic_sig}")
        print(f"[API] 纯PQC-TLS: KEM={pqc_kem}, 签名={pqc_sig}")
        print(f"[API] 混合TLS: KEM={hybrid_kem}, 签名={hybrid_sig}")
        
        def calculate_average_result(results_list):
            """计算多次测试结果的平均值"""
            if not results_list:
                return None
            
            avg_result = results_list[0].copy()
            numeric_fields = ['total_time', 'total_messages', 'client_to_server_size',
                            'server_to_client_size', 'total_size']
            
            for field in numeric_fields:
                if field in avg_result:
                    values = [r.get(field, 0) for r in results_list]
                    avg_result[field] = sum(values) / len(values)
            
            avg_result['timing'] = results_list[-1].get('timing', {})
            avg_result['resources'] = results_list[-1].get('resources')
            avg_result['_run_count'] = len(results_list)
            
            return avg_result
        
        def run_mode_test(mode, kem, signature):
            """执行指定模式的测试"""
            results = []
            for i in range(runs):
                try:
                    executor = RealHandshakeExecutor(mode, cert_mode, signature, kem)
                    result = executor.execute()
                    if result.get('success'):
                        results.append(result)
                except Exception as e:
                    print(f"[API] {mode}模式第{i+1}次测试失败: {e}")
                    continue
            
            if not results:
                return None
            
            if runs == 1:
                return results[0]
            else:
                return calculate_average_result(results)
        
        # 执行三种模式的测试，使用各自的KEM和签名算法
        classic_result = run_mode_test('classic', classic_kem, classic_sig)
        pqc_result = run_mode_test('pqc', pqc_kem, pqc_sig)
        hybrid_result = run_mode_test('hybrid', hybrid_kem, hybrid_sig)
        
        if not classic_result or not pqc_result or not hybrid_result:
            raise Exception("部分模式测试失败，无法完成对比")
        
        # 提取握手时间
        def extract_handshake_time(result):
            timing = result.get('timing', {})
            if timing and timing.get('steps'):
                steps = timing['steps']
                excluded_steps = [
                    '证书服务器检查', '服务器线程启动', '等待服务器就绪',
                    '客户端初始化', '建立TCP连接', '清理连接', '等待服务器完成',
                    '服务器Socket初始化', 'TLS服务器初始化', '等待客户端连接',
                    'TLS握手执行'
                ]
                for step in steps:
                    if step.get('step_name') == 'TLS握手执行':
                        details = step.get('details', {})
                        if 'total_handshake_time_ms' in details:
                            return details['total_handshake_time_ms']
                handshake_time = 0
                for step in steps:
                    step_name = step.get('step_name', '')
                    if step_name not in excluded_steps:
                        handshake_time += step.get('duration_ms', 0)
                return handshake_time if handshake_time > 0 else result.get('total_time', 0)
            return result.get('total_time', 0)
        
        # 获取证书大小（使用各自的签名算法）
        cert_sizes_file = project_root / "frontend" / "cert_sizes.json"
        cert_sizes_data = {}
        if cert_sizes_file.exists():
            try:
                with open(cert_sizes_file, 'r', encoding='utf-8') as f:
                    cert_sizes_data = json.load(f)
            except Exception as e:
                print(f"[API] 读取证书大小文件失败: {e}")
                cert_sizes_data = {}
        
        def get_cert_size(signature_alg):
            """获取指定签名算法的证书大小"""
            if cert_sizes_data and cert_sizes_data.get('cert_sizes'):
                sig_cert_sizes = cert_sizes_data.get('cert_sizes', {}).get(signature_alg, {})
                return sig_cert_sizes.get('by_val' if cert_mode == 'by_val' else 'by_ref', {}).get('total_certificate_chain_size', 0)
            return 0
        
        classic_cert_size = get_cert_size(classic_sig)
        pqc_cert_size = get_cert_size(pqc_sig)
        hybrid_cert_size = get_cert_size(hybrid_sig)
        
        # 如果没有证书大小数据，使用估算值
        if classic_cert_size == 0:
            classic_cert_size = 2000  # 经典TLS证书较小
        if pqc_cert_size == 0:
            pqc_cert_size = 30000  # 纯PQC证书较大
        if hybrid_cert_size == 0:
            hybrid_cert_size = 28000  # 混合TLS证书中等
        
        # 格式化KEM名称
        def format_kem_name(kem_str):
            """格式化KEM名称以便显示"""
            if not kem_str:
                return '-'
            kem_map = {
                'x25519': 'X25519',
                'secp256r1': 'secp256r1',
                'kyber512': 'Kyber-512',
                'kyber768': 'Kyber-768',
                'kyber1024': 'Kyber-1024',
                'ML_KEM_512': 'ML-KEM-512',
                'ML_KEM_768': 'ML-KEM-768',
                'ML_KEM_1024': 'ML-KEM-1024',
                'p256_kyber512': 'P256 + Kyber-512',
                'p256_kyber768': 'P256 + Kyber-768',
                'p384_kyber768': 'P384 + Kyber-768',
                'p521_kyber1024': 'P521 + Kyber-1024'
            }
            return kem_map.get(kem_str, kem_str)
        
        # 格式化签名算法名称
        def format_signature_name(sig_str):
            """格式化签名算法名称以便显示"""
            if not sig_str:
                return '-'
            sig_map = {
                'ecdsa_p256': 'ECDSA-P256',
                'rsa_pss_sha256': 'RSA-PSS-SHA256',
                'mldsa44': 'ML-DSA-44',
                'mldsa65': 'ML-DSA-65',
                'mldsa87': 'ML-DSA-87',
                'falcon512': 'Falcon-512',
                'falcon1024': 'Falcon-1024'
            }
            return sig_map.get(sig_str, sig_str)
        
        return {
            'success': True,
            'cert_mode': cert_mode,
            'runs': runs,
            'comparison': {
                'classic': {
                    'handshake_time_ms': round(extract_handshake_time(classic_result), 2),
                    'certificate_size_bytes': classic_cert_size,
                    'total_size_bytes': round(classic_result.get('total_size', 0), 0),
                    'total_messages': classic_result.get('total_messages', 0),
                    'kem': format_kem_name(classic_result.get('kem', classic_kem)),
                    'signature': format_signature_name(classic_result.get('algorithm', classic_sig))
                },
                'pqc': {
                    'handshake_time_ms': round(extract_handshake_time(pqc_result), 2),
                    'certificate_size_bytes': pqc_cert_size,
                    'total_size_bytes': round(pqc_result.get('total_size', 0), 0),
                    'total_messages': pqc_result.get('total_messages', 0),
                    'kem': format_kem_name(pqc_result.get('kem', pqc_kem)),
                    'signature': format_signature_name(pqc_result.get('algorithm', pqc_sig))
                },
                'hybrid': {
                    'handshake_time_ms': round(extract_handshake_time(hybrid_result), 2),
                    'certificate_size_bytes': hybrid_cert_size,
                    'total_size_bytes': round(hybrid_result.get('total_size', 0), 0),
                    'total_messages': hybrid_result.get('total_messages', 0),
                    'kem': format_kem_name(hybrid_result.get('kem', hybrid_kem)),
                    'signature': format_signature_name(hybrid_result.get('algorithm', hybrid_sig))
                }
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"[API] 算法对比异常:\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"算法对比异常: {str(e)}")


@app.get("/api/images/list")
async def list_images():
    """列出static/plots目录中的PNG图片，排除bandwidth comparison相关文件"""
    # 尝试多个可能的路径
    possible_paths = [
        project_root / "frontend" / "static" / "plots",
        project_root / "frontend" / "static",
        Path(__file__).parent / "static" / "plots",
        Path(__file__).parent.parent / "frontend" / "static" / "plots"
    ]
    
    plots_dir = None
    for path in possible_paths:
        if path.exists():
            plots_dir = path
            break
    
    if not plots_dir:
        return {'success': False, 'images': [], 'message': '未找到plots目录'}
    
    images = []
    # 只支持PNG文件
    for img_file in plots_dir.glob("*.png"):
        # 排除bandwidth comparison相关的文件
        filename_lower = img_file.name.lower()
        if 'bandwidth' in filename_lower and 'comparison' in filename_lower:
            continue
        
        # 排除Handshake Comparison 01相关的文件
        if 'handshake comparison 01' in filename_lower or 'handshake_comparison_01' in filename_lower:
            continue
        
        # 计算相对路径
        try:
            rel_path = img_file.relative_to(Path(__file__).parent)
            if rel_path.parent.name == 'static':
                path_str = f"/static/{rel_path.name}"
            else:
                path_str = f"/static/{rel_path.parent.name}/{rel_path.name}"
        except:
            # 如果无法计算相对路径，使用默认路径
            path_str = f"/static/plots/{img_file.name}"
        
        images.append({
            'filename': img_file.name,
            'path': path_str,
            'size': img_file.stat().st_size,
            'title': img_file.stem.replace('_', ' ').replace('-', ' ').title()
        })
    
    images.sort(key=lambda x: x['filename'])
    
    return {
        'success': True,
        'count': len(images),
        'images': images
    }


# 挂载静态文件
frontend_dir = Path(__file__).parent

# 挂载static目录（包含plots子目录）
if (frontend_dir / "static").exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir / "static")), name="static")

# 提供静态文件服务（CSS、JS等）
# 使用精确路径匹配，避免与API路由冲突
@app.get("/style.css")
async def serve_css():
    """提供CSS文件"""
    css_path = frontend_dir / "style.css"
    if css_path.exists():
        return FileResponse(css_path, media_type="text/css", headers={"Cache-Control": "no-cache"})
    raise HTTPException(status_code=404, detail="CSS file not found")

@app.get("/script.js")
async def serve_js():
    """提供JavaScript文件"""
    js_path = frontend_dir / "script.js"
    if js_path.exists():
        return FileResponse(js_path, media_type="application/javascript", headers={"Cache-Control": "no-cache"})
    raise HTTPException(status_code=404, detail="JS file not found")


@app.post("/api/cert-server/stop")
async def stop_cert_server_api():
    """停止证书服务器（停止80端口上的证书服务器）"""
    try:
        # 停止由API服务器启动的进程
        stop_cert_server()
        
        # 尝试停止80端口上的证书服务器进程
        stopped = False
        try:
            import psutil
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr.port == 80 and conn.status == psutil.CONN_LISTEN:
                    try:
                        process = psutil.Process(conn.pid)
                        cmdline = ' '.join(process.cmdline())
                        if 'local_cert_server' in cmdline or 'cert_server' in cmdline.lower():
                            process.terminate()
                            try:
                                process.wait(timeout=3)
                            except psutil.TimeoutExpired:
                                process.kill()
                            stopped = True
                            break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        except ImportError:
            # psutil不可用，使用Windows的taskkill
            if sys.platform == 'win32':
                try:
                    result = subprocess.run(
                        ['netstat', '-ano'], 
                        capture_output=True, 
                        text=True, 
                        timeout=2
                    )
                    for line in result.stdout.split('\n'):
                        if ':80' in line and 'LISTENING' in line:
                            parts = line.split()
                            if len(parts) >= 5:
                                pid = parts[-1]
                                # 检查进程命令行
                                try:
                                    proc_info = subprocess.run(
                                        ['wmic', 'process', 'where', f'ProcessId={pid}', 'get', 'CommandLine'],
                                        capture_output=True,
                                        text=True,
                                        timeout=2
                                    )
                                    if 'local_cert_server' in proc_info.stdout or 'cert_server' in proc_info.stdout.lower():
                                        subprocess.run(['taskkill', '/F', '/PID', pid], 
                                                     capture_output=True, timeout=2)
                                        stopped = True
                                except:
                                    pass
                except:
                    pass
        
        return {
            'success': True,
            'stopped': stopped,
            'message': '证书服务器已停止' if stopped else '未找到证书服务器进程或已停止'
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }


def cleanup_resources():
    """清理所有资源"""
    print("\n[清理] 开始清理资源...")
    
    global cert_server_process
    if cert_server_process:
        try:
            if cert_server_process.poll() is None:
                cert_server_process.terminate()
                try:
                    cert_server_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    cert_server_process.kill()
                    cert_server_process.wait()
        except Exception as e:
            print(f"[清理] 停止证书服务器失败: {e}")
        cert_server_process = None
    
    global active_subprocesses
    for proc in active_subprocesses[:]:
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        except Exception as e:
            print(f"[清理] 终止子进程失败: {e}")
    active_subprocesses.clear()
    
    global temp_files
    for temp_file in temp_files[:]:
        try:
            if temp_file.exists():
                temp_file.unlink()
        except Exception as e:
            print(f"[清理] 删除临时文件失败: {e}")
    temp_files.clear()
    
    temp_dir = Path(tempfile.gettempdir())
    for temp_file in temp_dir.glob("handshake_test_*.py"):
        try:
            if temp_file.exists():
                temp_file.unlink()
        except:
            pass
    
    print("[清理] 资源清理完成")


def signal_handler(signum, frame):
    """信号处理器"""
    signal_name = signal.Signals(signum).name
    print(f"\n[信号] 收到 {signal_name} 信号，开始优雅退出...")
    cleanup_resources()
    print("[退出] 服务器已关闭")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)
if hasattr(signal, 'SIGTERM'):
    signal.signal(signal.SIGTERM, signal_handler)

atexit.register(cleanup_resources)


if __name__ == "__main__":
    print("\n" + "="*70)
    print("  TLS握手前端API服务器 v3.0")
    print("  支持by_ref和by_val模式对比")
    print("  按 Ctrl+C 优雅退出")
    print("="*70 + "\n")
    
    try:
        uvicorn.run(
            "api_server:app",
            host="127.0.0.1",
            port=8000,
            reload=True,
            log_level="info"
        )
    except KeyboardInterrupt:
        print("\n[退出] 收到键盘中断信号")
        cleanup_resources()
        print("[退出] 服务器已关闭")
    except Exception as e:
        print(f"\n[错误] 服务器异常退出: {e}")
        cleanup_resources()
        raise
