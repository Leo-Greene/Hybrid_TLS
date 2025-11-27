#!/usr/bin/env python3
"""
多算法证书生成工具
支持生成不同签名算法的完整证书链
"""

import os
import sys
import json
from pathlib import Path

# 添加项目路径
project_root = Path(__file__).parent.parent.parent.parent
print(f"project_root: {project_root}")
sys.path.insert(0, str(project_root))

from implementation.enhanced_v2.pq_certificates.x509_wrapper import X509PQWrapper, PQWrappedCertificate


# 定义支持的算法配置
ALGORITHM_CONFIGS = {
    "mldsa44": {
        "name": "ML-DSA-44",
        "root_algo": "ML-DSA-87",
        "intermediate_algo": "ML-DSA-65", 
        "server_algo": "ML-DSA-44",
        "description": "ML-DSA (Dilithium) - NIST Level 2/3/5"
    },
    "mldsa65": {
        "name": "ML-DSA-65",
        "root_algo": "ML-DSA-87",
        "intermediate_algo": "ML-DSA-65",
        "server_algo": "ML-DSA-65",
        "description": "ML-DSA (Dilithium) - 推荐配置"
    },
    "mldsa87": {
        "name": "ML-DSA-87",
        "root_algo": "ML-DSA-87",
        "intermediate_algo": "ML-DSA-87",
        "server_algo": "ML-DSA-87",
        "description": "ML-DSA (Dilithium) - 最高安全级别"
    },
    "falcon512": {
        "name": "Falcon-512",
        "root_algo": "Falcon-1024",
        "intermediate_algo": "Falcon-512",
        "server_algo": "Falcon-512",
        "description": "Falcon - 紧凑签名"
    },
    "falcon1024": {
        "name": "Falcon-1024",
        "root_algo": "Falcon-1024",
        "intermediate_algo": "Falcon-1024",
        "server_algo": "Falcon-1024",
        "description": "Falcon - 高安全级别"
    },
    "dilithium2": {
        "name": "Dilithium2",
        "root_algo": "ML-DSA-87",
        "intermediate_algo": "ML-DSA-65", 
        "server_algo": "ML-DSA-44",
        "description": "Dilithium (实验版本)"
    },
    "dilithium3": {
        "name": "Dilithium3",
        "root_algo": "ML-DSA-87",
        "intermediate_algo": "ML-DSA-65",
        "server_algo": "ML-DSA-65",
        "description": "Dilithium (实验版本)"
    },
}


def generate_certificate_chain(algo_key: str, base_dir: str = "implementation/enhanced_v2/pq_certificates"):
    """
    生成指定算法的完整证书链
    
    Args:
        algo_key: 算法配置键 (如 "mldsa65", "falcon512")
        base_dir: 基础目录
    """
    if algo_key not in ALGORITHM_CONFIGS:
        raise ValueError(f"不支持的算法: {algo_key}。支持的算法: {list(ALGORITHM_CONFIGS.keys())}")
    
    config = ALGORITHM_CONFIGS[algo_key]
    
    print("=" * 80)
    print(f"生成证书链: {config['name']}")
    print(f"描述: {config['description']}")
    print("=" * 80)
    
    # 创建算法专用目录
    algo_base = f"{algo_key}"
    dirs = [
        f"{algo_base}/root",
        f"{algo_base}/intermediate",
        f"{algo_base}/server",
        f"{algo_base}/client/trust_store",
    ]
    
    for dir_path in dirs:
        os.makedirs(dir_path, exist_ok=True)
    
    print(f"✓ 目录结构已创建: {algo_base}/")
    
    # ==================== 1. 生成根 CA ====================
    print(f"\n[1/3] 生成根 CA ({config['root_algo']})")
    
    root_wrapper = X509PQWrapper(config['root_algo'])
    root_wrapper.generate_keypair()
    
    root_cert = root_wrapper.create_certificate(
        subject_name=f"PQ Root CA ({config['name']})",
        issuer_name=f"PQ Root CA ({config['name']})",
        issuer_wrapper=None,
        is_ca=True,
        path_length=2,
        validity_days=3650,
        base_algorithm=config['name']  # 使用基础算法名称（如 "ML-DSA-65"）构建URI
    )
    
    # 保存根证书
    root_cert.save_pem(
        f"{algo_base}/root/root_ca.crt",
        f"{algo_base}/root/root_ca_pq.sig",
        f"{algo_base}/root/root_pq_pubkey.pub"
    )
    with open(f"{algo_base}/root/root_ca.key", 'wb') as f:
        f.write(root_wrapper.pq_private_key)
    
    # 复制到信任存储
    root_cert.save_pem(
        f"{algo_base}/client/trust_store/root_ca.crt",
        f"{algo_base}/client/trust_store/root_ca_pq.sig",
        f"{algo_base}/client/trust_store/root_pq_pubkey.pub"
    )
    
    print(f"  ✓ 根证书: {algo_base}/root/root_ca.crt")
    print(f"  ✓ 根私钥: {algo_base}/root/root_ca.key")
    print(f"  ✓ 公钥大小: {len(root_cert.get_pq_public_key())} 字节")
    
    # ==================== 2. 生成中间 CA ====================
    print(f"\n[2/3] 生成中间 CA ({config['intermediate_algo']})")
    
    intermediate_wrapper = X509PQWrapper(config['intermediate_algo'])
    intermediate_wrapper.generate_keypair()
    
    intermediate_cert = intermediate_wrapper.create_certificate(
        subject_name=f"PQ Intermediate CA ({config['name']})",
        issuer_name=f"PQ Root CA ({config['name']})",
        issuer_wrapper=root_wrapper,
        is_ca=True,
        path_length=1,
        validity_days=1825,
        base_algorithm=config['name']  # 使用基础算法名称（如 "ML-DSA-65"）构建URI
    )
    
    # 保存中间证书
    intermediate_cert.save_pem(
        f"{algo_base}/intermediate/intermediate_ca.crt",
        f"{algo_base}/intermediate/intermediate_ca_pq.sig",
        f"{algo_base}/intermediate/intermediate_pq_pubkey.pub"
    )
    with open(f"{algo_base}/intermediate/intermediate_ca.key", 'wb') as f:
        f.write(intermediate_wrapper.pq_private_key)
    
    print(f"  ✓ 中间证书: {algo_base}/intermediate/intermediate_ca.crt")
    print(f"  ✓ 中间私钥: {algo_base}/intermediate/intermediate_ca.key")
    print(f"  ✓ 公钥大小: {len(intermediate_cert.get_pq_public_key())} 字节")
    
    # ==================== 3. 生成服务器证书 ====================
    print(f"\n[3/3] 生成服务器证书 ({config['server_algo']})")
    
    server_wrapper = X509PQWrapper(config['server_algo'])
    server_wrapper.generate_keypair()
    
    server_cert = server_wrapper.create_certificate(
        subject_name="server.example.com",
        issuer_name=f"PQ Intermediate CA ({config['name']})",
        issuer_wrapper=intermediate_wrapper,
        is_ca=False,
        validity_days=365,
        base_algorithm=config['name']  # 使用基础算法名称（如 "ML-DSA-65"）构建URI
    )
    
    # 保存服务器证书
    server_cert.save_pem(
        f"{algo_base}/server/server.crt",
        f"{algo_base}/server/server_pq.sig",
        f"{algo_base}/server/server_pq_pubkey.pub"
    )
    with open(f"{algo_base}/server/server.key", 'wb') as f:
        f.write(server_wrapper.pq_private_key)
    
    print(f"  ✓ 服务器证书: {algo_base}/server/server.crt")
    print(f"  ✓ 服务器私钥: {algo_base}/server/server.key")
    print(f"  ✓ 公钥大小: {len(server_cert.get_pq_public_key())} 字节")
    
    # ==================== 4. 生成配置信息 ====================
    cert_info = {
        "algorithm": config['name'],
        "description": config['description'],
        "root_algorithm": config['root_algo'],
        "intermediate_algorithm": config['intermediate_algo'],
        "server_algorithm": config['server_algo'],
        "files": {
            "root_cert": f"{algo_base}/root/root_ca.crt",
            "root_key": f"{algo_base}/root/root_ca.key",
            "root_sig": f"{algo_base}/root/root_ca_pq.sig",
            "intermediate_cert": f"{algo_base}/intermediate/intermediate_ca.crt",
            "intermediate_key": f"{algo_base}/intermediate/intermediate_ca.key",
            "intermediate_sig": f"{algo_base}/intermediate/intermediate_ca_pq.sig",
            "server_cert": f"{algo_base}/server/server.crt",
            "server_key": f"{algo_base}/server/server.key",
            "server_sig": f"{algo_base}/server/server_pq.sig",
        }
    }
    
    with open(f"{algo_base}/cert_info.json", 'w') as f:
        json.dump(cert_info, f, indent=2)
    
    print(f"\n✓ 配置信息: {algo_base}/cert_info.json")
    
    print("\n" + "=" * 80)
    print(f"[OK] 证书链生成完成: {config['name']}")
    print("=" * 80)
    
    return cert_info


def generate_all_algorithms():
    """生成所有支持的算法的证书链"""
    print("\n" + "=" * 80)
    print("生成所有算法的证书链")
    print("=" * 80 + "\n")
    
    results = {}
    for algo_key in ALGORITHM_CONFIGS.keys():
        try:
            print(f"\n正在生成 {algo_key}...")
            cert_info = generate_certificate_chain(algo_key)
            results[algo_key] = {"status": "success", "info": cert_info}
        except Exception as e:
            print(f"❌ 生成 {algo_key} 失败: {e}")
            results[algo_key] = {"status": "failed", "error": str(e)}
    
    # 生成总索引
    with open("all_certs_index.json", 'w') as f:
        json.dump(results, f, indent=2)
    
    print("\n" + "=" * 80)
    print("[OK] 所有证书链生成完成")
    print("=" * 80)
    
    # 显示摘要
    print("\n生成摘要:")
    for algo_key, result in results.items():
        status = "✓" if result["status"] == "success" else "✗"
        print(f"  {status} {algo_key}: {result['status']}")
    
    print(f"\n索引文件: all_certs_index.json")


def list_available_algorithms():
    """列出所有可用的算法"""
    print("\n可用的签名算法:")
    print("=" * 80)
    for key, config in ALGORITHM_CONFIGS.items():
        print(f"\n{key}:")
        print(f"  名称: {config['name']}")
        print(f"  描述: {config['description']}")
        print(f"  根CA: {config['root_algo']}")
        print(f"  中间CA: {config['intermediate_algo']}")
        print(f"  服务器: {config['server_algo']}")
    print("=" * 80)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="多算法证书生成工具")
    parser.add_argument(
        "--algorithm", "-a",
        type=str,
        help=f"指定算法生成证书链。支持: {', '.join(ALGORITHM_CONFIGS.keys())}"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="生成所有算法的证书链"
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="列出所有可用的算法"
    )
    
    args = parser.parse_args()
    
    if args.list:
        list_available_algorithms()
    elif args.all:
        generate_all_algorithms()
    elif args.algorithm:
        generate_certificate_chain(args.algorithm)
    else:
        print("用法示例:")
        print("  生成单个算法: python generate_multi_algorithm_certs.py -a mldsa65")
        print("  生成所有算法: python generate_multi_algorithm_certs.py --all")
        print("  列出可用算法: python generate_multi_algorithm_certs.py --list")
        parser.print_help()

