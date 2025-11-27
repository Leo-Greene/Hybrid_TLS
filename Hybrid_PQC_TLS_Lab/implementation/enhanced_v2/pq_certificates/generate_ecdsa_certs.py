#!/usr/bin/env python3
"""
生成ECDSA-P256经典证书链
用于基准测试中的经典TLS模式
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

def generate_ecdsa_certificate_chain(base_dir: str = "ecdsa_p256"):
    """
    生成ECDSA-P256完整证书链
    
    证书链结构:
    - 根CA: ECDSA-P384 (更高安全级别)
    - 中间CA: ECDSA-P256
    - 服务器证书: ECDSA-P256
    """
    print("=" * 80)
    print("生成ECDSA-P256证书链")
    print("=" * 80)
    
    # 创建目录结构
    dirs = [
        f"{base_dir}/root",
        f"{base_dir}/intermediate",
        f"{base_dir}/server",
        f"{base_dir}/client/trust_store",
    ]
    
    for dir_path in dirs:
        os.makedirs(dir_path, exist_ok=True)
    
    # 1. 生成根CA证书（使用P-384以获得更高安全性）
    print("\n[1/3] 生成根CA证书 (ECDSA-P384)...")
    
    # 生成根CA私钥
    root_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    
    # 根CA证书信息
    root_subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Beijing"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PQC-TLS Research Lab"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "ECDSA Root CA"),
    ])
    
    # 生成根CA证书
    root_cert = x509.CertificateBuilder().subject_name(
        root_subject
    ).issuer_name(
        issuer
    ).public_key(
        root_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=3650)  # 10年有效期
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=1),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(root_private_key.public_key()),
        critical=False,
    ).sign(root_private_key, hashes.SHA384(), default_backend())
    
    # 保存根CA证书和私钥
    with open(f"{base_dir}/root/root_ca.crt", "wb") as f:
        f.write(root_cert.public_bytes(serialization.Encoding.PEM))
    
    with open(f"{base_dir}/root/root_ca.key", "wb") as f:
        f.write(root_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    print(f"  ✓ 根CA证书已生成: {base_dir}/root/root_ca.crt")
    
    # 2. 生成中间CA证书（使用P-256）
    print("\n[2/3] 生成中间CA证书 (ECDSA-P256)...")
    
    # 生成中间CA私钥
    intermediate_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    
    # 中间CA证书信息
    intermediate_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Beijing"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PQC-TLS Research Lab"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Intermediate CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "ECDSA Intermediate CA"),
    ])
    
    # 生成中间CA证书（由根CA签名）
    intermediate_cert = x509.CertificateBuilder().subject_name(
        intermediate_subject
    ).issuer_name(
        root_subject
    ).public_key(
        intermediate_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=1825)  # 5年有效期
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(intermediate_private_key.public_key()),
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(root_private_key.public_key()),
        critical=False,
    ).sign(root_private_key, hashes.SHA384(), default_backend())  # 根CA用P-384签名
    
    # 保存中间CA证书和私钥
    with open(f"{base_dir}/intermediate/intermediate_ca.crt", "wb") as f:
        f.write(intermediate_cert.public_bytes(serialization.Encoding.PEM))
    
    with open(f"{base_dir}/intermediate/intermediate_ca.key", "wb") as f:
        f.write(intermediate_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    print(f"  ✓ 中间CA证书已生成: {base_dir}/intermediate/intermediate_ca.crt")
    
    # 3. 生成服务器证书（使用P-256）
    print("\n[3/3] 生成服务器证书 (ECDSA-P256)...")
    
    # 生成服务器私钥
    server_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    
    # 服务器证书信息
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Beijing"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PQC-TLS Research Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, "server.example.com"),
    ])
    
    # 生成服务器证书（由中间CA签名）
    server_cert = x509.CertificateBuilder().subject_name(
        server_subject
    ).issuer_name(
        intermediate_subject
    ).public_key(
        server_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)  # 1年有效期
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("server.example.com"),
            x509.DNSName("localhost"),
            x509.DNSName("*.example.com"),
        ]),
        critical=False,
    ).add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
        ]),
        critical=False,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(server_private_key.public_key()),
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate_private_key.public_key()),
        critical=False,
    ).sign(intermediate_private_key, hashes.SHA256(), default_backend())  # 中间CA用P-256签名
    
    # 保存服务器证书和私钥
    with open(f"{base_dir}/server/server.crt", "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))
    
    with open(f"{base_dir}/server/server.key", "wb") as f:
        f.write(server_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    print(f"  ✓ 服务器证书已生成: {base_dir}/server/server.crt")
    
    # 4. 复制根CA到客户端信任存储
    print("\n[4/4] 配置客户端信任存储...")
    
    with open(f"{base_dir}/client/trust_store/root_ca.crt", "wb") as f:
        f.write(root_cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"  ✓ 根CA证书已复制到: {base_dir}/client/trust_store/root_ca.crt")
    
    # 5. 生成证书信息文件
    cert_info = {
        "algorithm": "ECDSA-P256",
        "description": "经典ECDSA证书链 (P-384根CA + P-256中间CA + P-256服务器)",
        "root_algorithm": "ECDSA-P384",
        "intermediate_algorithm": "ECDSA-P256",
        "server_algorithm": "ECDSA-P256",
        "files": {
            "root_cert": f"{base_dir}/root/root_ca.crt",
            "root_key": f"{base_dir}/root/root_ca.key",
            "intermediate_cert": f"{base_dir}/intermediate/intermediate_ca.crt",
            "intermediate_key": f"{base_dir}/intermediate/intermediate_ca.key",
            "server_cert": f"{base_dir}/server/server.crt",
            "server_key": f"{base_dir}/server/server.key"
        },
        "note": "经典证书不需要.sig文件，签名已包含在X.509证书中"
    }
    
    with open(f"{base_dir}/cert_info.json", "w") as f:
        json.dump(cert_info, f, indent=2)
    
    print(f"\n[OK] ECDSA-P256证书链生成完成！")
    print(f"   证书目录: {base_dir}/")
    print(f"   - 根CA (P-384): {base_dir}/root/root_ca.crt")
    print(f"   - 中间CA (P-256): {base_dir}/intermediate/intermediate_ca.crt")
    print(f"   - 服务器 (P-256): {base_dir}/server/server.crt")
    
    return cert_info


def main():
    """主函数"""
    # 切换到脚本所在目录
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    
    print("\n🔐 ECDSA证书链生成工具")
    print("=" * 80)
    
    try:
        cert_info = generate_ecdsa_certificate_chain()
        
        # 更新全局证书索引
        index_file = "all_certs_index.json"
        try:
            with open(index_file, 'r') as f:
                all_certs = json.load(f)
        except FileNotFoundError:
            all_certs = {}
        
        all_certs['ecdsa_p256'] = {
            "status": "success",
            "info": cert_info
        }
        
        with open(index_file, 'w') as f:
            json.dump(all_certs, f, indent=2)
        
        print(f"\n[OK] 证书索引已更新: {index_file}")
        
    except Exception as e:
        print(f"\n❌ 生成失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

