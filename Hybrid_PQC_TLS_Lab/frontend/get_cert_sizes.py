#!/usr/bin/env python3
"""
读取证书大小信息
从enhanced_certificates（by_val）和pq_certificates（by_ref）读取实际证书文件大小
"""

import os
import sys
from pathlib import Path
import json

# 添加项目根目录到路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


def get_file_size(file_path: Path) -> int:
    """获取文件大小（字节）"""
    if file_path.exists():
        return file_path.stat().st_size
    return 0


def read_cert_sizes_by_val(algorithm: str) -> dict:
    """读取by_val模式的证书大小（从enhanced_certificates）"""
    base_dir = project_root / "enhanced_certificates" / algorithm
    
    server_cert = base_dir / "server" / "server.crt"
    server_sig = base_dir / "server" / "server_pq.sig"
    intermediate_cert = base_dir / "intermediate" / "intermediate_ca.crt"
    intermediate_sig = base_dir / "intermediate" / "intermediate_ca_pq.sig"
    
    server_cert_size = get_file_size(server_cert)
    server_sig_size = get_file_size(server_sig)
    intermediate_cert_size = get_file_size(intermediate_cert)
    intermediate_sig_size = get_file_size(intermediate_sig)
    
    total = server_cert_size + server_sig_size + intermediate_cert_size + intermediate_sig_size
    
    return {
        "server_cert_size": server_cert_size,
        "server_sig_size": server_sig_size,
        "intermediate_cert_size": intermediate_cert_size,
        "intermediate_sig_size": intermediate_sig_size,
        "total_certificate_chain_size": total
    }


def read_cert_sizes_by_ref(algorithm: str) -> dict:
    """读取by_ref模式的证书大小（从pq_certificates）"""
    base_dir = project_root / "implementation" / "enhanced_v2" / "pq_certificates" / algorithm
    
    server_cert = base_dir / "server" / "server.crt"
    intermediate_cert = base_dir / "intermediate" / "intermediate_ca.crt"
    
    server_cert_size = get_file_size(server_cert)
    intermediate_cert_size = get_file_size(intermediate_cert)
    
    # by_ref模式下，签名通过HTTP URI获取，不包含在Certificate消息中
    total = server_cert_size + intermediate_cert_size
    
    return {
        "server_cert_size": server_cert_size,
        "intermediate_cert_size": intermediate_cert_size,
        "total_certificate_chain_size": total,
        "note": "签名通过HTTP URI获取，不包含在Certificate消息中"
    }


def get_all_cert_sizes() -> dict:
    """获取所有算法的证书大小"""
    algorithms = ["mldsa44", "mldsa65", "mldsa87", "falcon512", "falcon1024", "ecdsa_p256"]
    
    result = {
        "timestamp": "",
        "cert_sizes": {}
    }
    
    for algo in algorithms:
        try:
            by_val = read_cert_sizes_by_val(algo)
            by_ref = read_cert_sizes_by_ref(algo)
            
            # 计算减少量
            size_reduction = by_val["total_certificate_chain_size"] - by_ref["total_certificate_chain_size"]
            percent_reduction = (size_reduction / by_val["total_certificate_chain_size"] * 100) if by_val["total_certificate_chain_size"] > 0 else 0
            
            result["cert_sizes"][algo] = {
                "algorithm": algo,
                "by_val": by_val,
                "by_ref": by_ref,
                "size_reduction": {
                    "bytes": size_reduction,
                    "percent": round(percent_reduction, 2)
                }
            }
        except Exception as e:
            print(f"警告: 无法读取算法 {algo} 的证书大小: {e}")
            continue
    
    from datetime import datetime
    result["timestamp"] = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    return result


if __name__ == "__main__":
    sizes = get_all_cert_sizes()
    print(json.dumps(sizes, indent=2, ensure_ascii=False))
    
    # 保存到文件
    output_file = project_root / "frontend" / "cert_sizes.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(sizes, f, indent=2, ensure_ascii=False)
    print(f"\n证书大小信息已保存到: {output_file}")

