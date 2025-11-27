#!/usr/bin/env python3
"""
完整证书生成脚本
生成根CA、中间CA、服务器证书及所有相关文件
"""

import os
import sys
import json
from pathlib import Path

# 添加项目路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# 导入x509_wrapper
from enhanced_certificates.x509_wrapper import X509PQWrapper, PQWrappedCertificate


def generate_all_certificates():
    """生成完整的证书层次结构"""
    print("=" * 80)
    print("开始生成完整的后量子证书层次结构")
    print("=" * 80)
    
    # 创建所有需要的目录
    dirs = [
        "enhanced_certificates/root",
        "enhanced_certificates/intermediate",
        "enhanced_certificates/server",
        "enhanced_certificates/client/trust_store",
    ]
    
    for dir_path in dirs:
        os.makedirs(dir_path, exist_ok=True)
        print(f"[OK] 目录已创建/确认: {dir_path}")
    
    print("\n" + "=" * 80)
    
    # ==================== 1. 生成根 CA ====================
    print("\n[步骤 1/5] 生成根 CA (Root CA)")
    print("-" * 80)
    
    root_wrapper = X509PQWrapper("ML-DSA-87")
    root_wrapper.generate_keypair()
    
    root_cert = root_wrapper.create_certificate(
        subject_name="Post-Quantum Root CA",
        issuer_name="Post-Quantum Root CA",  # 自签名
        issuer_wrapper=None,
        is_ca=True,
        path_length=2,
        validity_days=3650  # 10年
    )
    
    print(f"[成功] 根 CA 创建成功")
    print(f"   主题名称: {root_cert.x509_cert.subject}")
    print(f"   后量子算法: {root_cert.pq_algorithm}")
    print(f"   公钥大小: {len(root_cert.get_pq_public_key())} 字节")
    print(f"   有效期: 3650 天 (10年)")
    
    # 保存根证书和私钥
    root_cert_path = "enhanced_certificates/root/root_ca.crt"
    root_key_path = "enhanced_certificates/root/root_ca.key"
    root_sig_path = "enhanced_certificates/root/root_ca_pq.sig"
    
    # 保存证书（PEM格式）和签名
    root_cert.save_pem(root_cert_path, root_sig_path)
    
    # 保存私钥
    with open(root_key_path, 'wb') as f:
        f.write(root_wrapper.pq_private_key)
    
    print(f"   已保存证书: {root_cert_path}")
    print(f"   已保存私钥: {root_key_path}")
    print(f"   已保存签名: {root_sig_path}")
    
    # 复制根证书到客户端信任存储
    trust_store_path = "enhanced_certificates/client/trust_store/root_ca.crt"
    root_cert.save_pem(trust_store_path, "enhanced_certificates/client/trust_store/root_ca_pq.sig")
    print(f"   已复制到信任存储: {trust_store_path}")
    
    # ==================== 2. 生成中间 CA ====================
    print("\n[步骤 2/5] 生成中间 CA (Intermediate CA)")
    print("-" * 80)
    
    intermediate_wrapper = X509PQWrapper("ML-DSA-65")
    intermediate_wrapper.generate_keypair()
    
    intermediate_cert = intermediate_wrapper.create_certificate(
        subject_name="PQ Intermediate CA",
        issuer_name="Post-Quantum Root CA",
        issuer_wrapper=root_wrapper,
        is_ca=True,
        path_length=1,
        validity_days=1825  # 5年
    )
    
    print(f"[成功] 中间 CA 创建成功")
    print(f"   主题名称: {intermediate_cert.x509_cert.subject}")
    print(f"   颁发者: {intermediate_cert.x509_cert.issuer}")
    print(f"   后量子算法: {intermediate_cert.pq_algorithm}")
    print(f"   公钥大小: {len(intermediate_cert.get_pq_public_key())} 字节")
    print(f"   有效期: 1825 天 (5年)")
    
    # 保存中间证书和私钥
    intermediate_cert_path = "enhanced_certificates/intermediate/intermediate_ca.crt"
    intermediate_key_path = "enhanced_certificates/intermediate/intermediate_ca.key"
    intermediate_sig_path = "enhanced_certificates/intermediate/intermediate_ca_pq.sig"
    
    intermediate_cert.save_pem(intermediate_cert_path, intermediate_sig_path)
    
    with open(intermediate_key_path, 'wb') as f:
        f.write(intermediate_wrapper.pq_private_key)
    
    print(f"   已保存证书: {intermediate_cert_path}")
    print(f"   已保存私钥: {intermediate_key_path}")
    print(f"   已保存签名: {intermediate_sig_path}")
    
    # ==================== 3. 生成服务器证书 ====================
    print("\n[步骤 3/5] 生成服务器证书 (Server Certificate)")
    print("-" * 80)
    
    server_wrapper = X509PQWrapper("ML-DSA-44")
    server_wrapper.generate_keypair()
    
    server_cert = server_wrapper.create_certificate(
        subject_name="server.example.com",
        issuer_name="PQ Intermediate CA",
        issuer_wrapper=intermediate_wrapper,
        is_ca=False,
        validity_days=365  # 1年
    )
    
    print(f"[成功] 服务器证书创建成功")
    print(f"   主题名称: {server_cert.x509_cert.subject}")
    print(f"   颁发者: {server_cert.x509_cert.issuer}")
    print(f"   后量子算法: {server_cert.pq_algorithm}")
    print(f"   公钥大小: {len(server_cert.get_pq_public_key())} 字节")
    print(f"   有效期: 365 天 (1年)")
    
    # 保存服务器证书和私钥
    server_cert_path = "enhanced_certificates/server/server.crt"
    server_key_path = "enhanced_certificates/server/server.key"
    server_sig_path = "enhanced_certificates/server/server_pq.sig"
    
    server_cert.save_pem(server_cert_path, server_sig_path)
    
    with open(server_key_path, 'wb') as f:
        f.write(server_wrapper.pq_private_key)
    
    print(f"   已保存证书: {server_cert_path}")
    print(f"   已保存私钥: {server_key_path}")
    print(f"   已保存签名: {server_sig_path}")
    
    # ==================== 4. 生成证书链 ====================
    print("\n[步骤 4/5] 生成证书链文件 (Certificate Chain)")
    print("-" * 80)
    
    cert_chain_path = "enhanced_certificates/server/cert_chain.pem"
    
    # 证书链 = 服务器证书 + 中间CA证书
    from cryptography.hazmat.primitives import serialization
    
    with open(cert_chain_path, 'wb') as f:
        # 服务器证书
        f.write(server_cert.x509_cert.public_bytes(serialization.Encoding.PEM))
        f.write(b"\n")
        # 中间CA证书
        f.write(intermediate_cert.x509_cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"[成功] 证书链创建成功")
    print(f"   已保存: {cert_chain_path}")
    print(f"   包含: 服务器证书 + 中间CA证书")
    
    # ==================== 5. 验证证书链 ====================
    print("\n[步骤 5/5] 验证证书链")
    print("-" * 80)
    
    # 验证中间证书（由根 CA 签名）
    print("正在验证中间CA证书...")
    intermediate_valid = intermediate_cert.verify(
        root_wrapper.pq_public_key,
        root_wrapper.pq_algorithm
    )
    
    if intermediate_valid:
        print(f"   [通过] 中间CA证书验证通过")
        print(f"      颁发者: {intermediate_cert.x509_cert.issuer}")
        print(f"      签名算法: {root_wrapper.pq_algorithm}")
    else:
        print(f"   [失败] 中间CA证书验证失败")
    
    # 验证服务器证书（由中间 CA 签名）
    print("\n正在验证服务器证书...")
    server_valid = server_cert.verify(
        intermediate_wrapper.pq_public_key,
        intermediate_wrapper.pq_algorithm
    )
    
    if server_valid:
        print(f"   [通过] 服务器证书验证通过")
        print(f"      颁发者: {server_cert.x509_cert.issuer}")
        print(f"      签名算法: {intermediate_wrapper.pq_algorithm}")
    else:
        print(f"   [失败] 服务器证书验证失败")
    
    # ==================== 总结 ====================
    print("\n" + "=" * 80)
    print("证书生成完成！")
    print("=" * 80)
    
    print("\n[文件结构] 生成的文件结构:")
    print("""
enhanced_certificates/
├── root/
│   ├── root_ca.crt              # 根CA证书
│   ├── root_ca.key              # 根CA私钥
│   └── root_ca_pq.sig           # 根CA的后量子签名
├── intermediate/
│   ├── intermediate_ca.crt      # 中间CA证书
│   ├── intermediate_ca.key      # 中间CA私钥
│   └── intermediate_ca_pq.sig   # 中间CA的后量子签名
├── server/
│   ├── server.crt               # 服务器证书
│   ├── server.key               # 服务器私钥
│   ├── server_pq.sig            # 服务器的后量子签名
│   └── cert_chain.pem           # 证书链（服务器+中间CA）
└── client/
    └── trust_store/
        ├── root_ca.crt          # 根CA证书（用于验证）
        └── root_ca_pq.sig       # 根CA的后量子签名
    """)
    
    print("\n[证书链] 证书层次结构:")
    print(f"""
    Root CA (ML-DSA-87)
    └── {root_cert.x509_cert.subject.rfc4514_string()}
        │
        └── Intermediate CA (ML-DSA-65)
            └── {intermediate_cert.x509_cert.subject.rfc4514_string()}
                │
                └── Server Certificate (ML-DSA-44)
                    └── {server_cert.x509_cert.subject.rfc4514_string()}
    """)
    
    print("\n[验证] 验证状态:")
    print(f"   中间CA证书: {'有效' if intermediate_valid else '无效'}")
    print(f"   服务器证书: {'有效' if server_valid else '无效'}")
    
    print("\n[说明] 使用说明:")
    print("   1. 服务器使用: server.crt + server.key + cert_chain.pem")
    print("   2. 客户端使用: client/trust_store/root_ca.crt 作为信任锚点")
    print("   3. 查看证书: openssl x509 -in <cert_file> -text -noout")
    
    print("\n" + "=" * 80)
    
    return {
        "root": {
            "wrapper": root_wrapper,
            "cert": root_cert,
            "cert_path": root_cert_path,
            "key_path": root_key_path
        },
        "intermediate": {
            "wrapper": intermediate_wrapper,
            "cert": intermediate_cert,
            "cert_path": intermediate_cert_path,
            "key_path": intermediate_key_path
        },
        "server": {
            "wrapper": server_wrapper,
            "cert": server_cert,
            "cert_path": server_cert_path,
            "key_path": server_key_path,
            "chain_path": cert_chain_path
        },
        "validation": {
            "intermediate_valid": intermediate_valid,
            "server_valid": server_valid
        }
    }


if __name__ == "__main__":
    try:
        result = generate_all_certificates()
        print("\n[完成] 所有证书生成成功！")
        sys.exit(0)
    except Exception as e:
        print(f"\n[错误] 证书生成失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

