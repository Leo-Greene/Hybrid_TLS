# Hybrid PQC-TLS Lab

<div align="center">

**一个用于研究和评估混合后量子密码学TLS 1.3协议的完整实验平台**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![TLS](https://img.shields.io/badge/TLS-1.3-green.svg)](https://datatracker.ietf.org/doc/html/rfc8446)
[![PQC](https://img.shields.io/badge/PQC-NIST%20Standardized-orange.svg)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[功能特性](#-功能特性) • [快速开始](#-快速开始) • [项目架构](#-项目架构) • [使用指南](#-使用指南) • [性能评估](#-性能评估)

</div>

---

## 📖 项目概述

### 项目背景

随着量子计算技术的快速发展，传统的公钥密码学（如RSA、ECDSA、ECDH）面临着被量子计算机破解的威胁。为应对这一挑战，美国国家标准与技术研究院（NIST）启动了后量子密码学（Post-Quantum Cryptography, PQC）标准化进程，并于2022-2024年陆续公布了首批标准化算法，包括ML-KEM（Kyber）、ML-DSA（Dilithium）和Falcon等。

### 项目目的

本项目旨在：
1. **实现混合PQC-TLS协议**：在TLS 1.3框架下实现经典、纯后量子和混合三种安全模式
2. **评估性能开销**：全面评估后量子密码学算法在TLS握手中的性能表现
3. **验证证书链**：实现完整的X.509证书链验证，支持经典和后量子签名
4. **网络影响分析**：模拟真实网络环境，评估网络延迟对握手性能的影响
5. **可视化展示**：提供直观的Web界面，实时展示握手流程和性能数据

### 核心特性

- ✅ **完整的TLS 1.3实现**：支持ClientHello、ServerHello、证书交换、握手完成等完整流程
- ✅ **三种安全模式**：经典模式、纯PQC模式、混合模式
- ✅ **多算法支持**：12种KEM算法、6种签名算法、多种组合方案
- ✅ **真实证书验证**：三级证书链（服务器→中间CA→根CA）完整验证
- ✅ **性能基准测试**：密钥交换、签名、握手、网络感知等多维度测试
- ✅ **Web可视化界面**：实时展示握手流程、消息解码、性能分析

---

## 🎯 功能特性

### 1. 核心密码学实现

#### 密钥交换算法（KEM）
| 类别 | 算法 | 安全级别 | 公钥大小 | 密文大小 |
|------|------|---------|---------|---------|
| **经典** | X25519 | ~128位 | 32B | 32B |
| **经典** | P-256/384/521 | ~128-256位 | 65-133B | 65-133B |
| **PQC** | Kyber512/768/1024 | NIST L1/3/5 | 800-1568B | 768-1568B |
| **PQC** | ML-KEM-512/768/1024 | NIST L1/3/5 | 800-1568B | 768-1568B |
| **PQC** | NTRU-HPS | NIST L1/3 | 699-930B | 699-930B |
| **混合** | P-256+Kyber768 | L3混合 | 1249B | 1153B |
| **混合** | P-384+Kyber768 | L3混合 | 1281B | 1185B |

#### 签名算法
| 类别 | 算法 | 安全级别 | 公钥大小 | 签名大小 |
|------|------|---------|---------|---------|
| **经典** | ECDSA-P256 | ~128位 | 64B | 72B |
| **PQC** | ML-DSA-44/65/87 | NIST L2/3/5 | 1312-2592B | 2420-4627B |
| **PQC** | Falcon-512/1024 | NIST L1/5 | 897-1793B | 666-1280B |
| **混合** | P256+Dilithium3 | L3混合 | 2016B | 3385B |

### 2. TLS 1.3协议实现

#### 三种运行模式
```
┌─────────────┬─────────────────────┬──────────────────────┬──────────────┐
│   模式      │  密钥交换           │  签名算法            │  安全特性     │
├─────────────┼─────────────────────┼──────────────────────┼──────────────┤
│ Classic     │ X25519              │ ECDSA-P256           │ 传统安全     │
│ PQC         │ Kyber768            │ Dilithium3 (ML-DSA-65)│ 抗量子攻击   │
│ Hybrid      │ P-256+Kyber768      │ Dilithium3           │ 双重保护     │
└─────────────┴─────────────────────┴──────────────────────┴──────────────┘
```

#### 握手流程
```
客户端                                                    服务器
  |                                                         |
  |  -------- ClientHello (Key Share) -------->           |
  |                                                         |
  |  <------- ServerHello (Key Share) ---------           |
  |  <------- EncryptedExtensions --------------           |
  |  <------- Certificate ----------------------           |
  |  <------- CertificateVerify ----------------           |
  |  <------- Finished -------------------------           |
  |                                                         |
  |  -------- Certificate ---------------------->          |
  |  -------- CertificateVerify ---------------->          |
  |  -------- Finished ------------------------->          |
  |                                                         |
  |  <======== Application Data ===============>          |
```

### 3. 证书管理系统

#### X.509证书链结构
```
Root CA (根证书颁发机构)
    └─ Intermediate CA (中间证书颁发机构)
           └─ Server Certificate (服务器证书)
```

#### 支持的证书类型
- **经典证书**：ECDSA签名（P-256），签名包含在X.509结构内
- **PQC证书**：ML-DSA/Falcon签名，签名单独存储为.sig文件
- **证书文件结构**：
  - `.crt`：标准X.509证书（DER/PEM格式）
  - `.sig`：后量子签名文件（二进制格式）
  - `.key`：私钥文件（用于签名生成）

#### 增强证书验证模块
- ✅ 完整的证书链构建
- ✅ 安全策略验证（STRICT_PQ、HYBRID_TRANSITION、CLASSIC_FALLBACK）
- ✅ 签名验证（经典和PQC）
- ✅ 证书有效期检查
- ✅ 信任锚管理

### 4. 性能基准测试

#### 测试维度
1. **密钥交换性能**：KeyGen、Encaps、Decaps操作
2. **签名性能**：签名生成、验证操作
3. **TLS握手性能**：完整握手流程
4. **网络感知测试**：真实网络环境模拟

#### 网络延迟模拟
- **传输时延**：基于数据大小和传输速率（1Gbps - 100Kbps）
- **传播时延**：基于物理距离（0.1km - 10000km）
- **5种网络环境**：localhost、LAN、WAN（快/慢）、Mobile

#### 输出格式
- JSON格式：详细数据，便于程序处理
- 文本格式：人类可读的表格和图表
- PDF图表：高质量论文级可视化

### 5. Web可视化系统

#### 六大功能页面
1. **概览页面**：握手状态、关键指标、时间线快览
2. **流程可视化**：动画展示消息流动
3. **消息详情**：完整解码、十六进制数据
4. **数据分析**：大小、时间、流量、模式对比
5. **性能图表**：基准测试结果展示
6. **设置页面**：系统配置和关于信息

#### 技术栈
- **后端**：FastAPI (Python)
- **前端**：HTML5 + CSS3 + JavaScript
- **图表**：Chart.js + Plotly
- **样式**：现代化卡片设计，响应式布局

---

## 🚀 快速开始

### 环境要求

- **操作系统**：Windows 10/11、Linux、macOS
- **Python版本**：Python 3.8 或更高
- **依赖库**：见 `requirements.txt`

### 安装步骤

#### 1. 克隆项目
```bash
git clone https://github.com/yourusername/Hybrid_PQC_TLS_Lab.git
cd Hybrid_PQC_TLS_Lab
```

#### 2. 创建虚拟环境
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

#### 3. 安装依赖
```bash
pip install -r requirements.txt
```

**注意**：如遇到NumPy版本冲突，请执行：
```bash
pip install "numpy<2.0.0"
```

#### 4. 生成证书（首次使用）
```bash
cd enhanced_certificates

# 生成经典证书（ECDSA）
python generate_ecdsa_certs.py

# 生成PQC证书（ML-DSA、Falcon等）
python generate_multi_algorithm_certs.py

cd ..
```

### 快速测试

#### 运行性能基准测试
```bash
cd benchmarks

# 快速测试（5次迭代，约3分钟）
python run_benchmarks.py --iterations 5

# 查看结果
python visualize_results.py

# 生成论文级图表
python paper_visualization.py
```

#### 启动Web可视化界面
```bash
cd frontend

# 启动API服务器
python enhanced_api_server.py

# 在浏览器中打开
# http://127.0.0.1:8000/enhanced_index.html
```

---

## 📂 项目架构

### 目录结构

```
Hybrid_PQC_TLS_Lab/
├── core/                              # 核心密码学和协议实现
│   ├── types.py                       # TLS类型定义
│   ├── crypto/                        # 密码学算法
│   │   ├── key_exchange.py            # KEM算法实现
│   │   ├── signature.py               # 签名算法实现
│   │   ├── record_encryption.py       # 记录层加密
│   │   └── enhanced_certificate/      # 增强证书验证模块
│   │       ├── core/                  # 核心验证逻辑
│   │       ├── models/                # 证书数据模型
│   │       └── crypto/                # 加密算法实现
│   └── protocol/                      # TLS协议实现
│       ├── messages.py                # 消息编解码
│       └── handshake.py               # 握手逻辑
│
├── implementation/                     # 客户端/服务器实现
│   └── enhanced_v2/                   # 增强版本
│       ├── config.py                  # 配置管理
│       ├── enhanced_client.py         # 客户端实现
│       ├── enhanced_server.py         # 服务器实现
│       ├── cert_loader.py             # 证书加载器
│       ├── multi_cert_manager.py      # 多证书管理
│       └── trust_store_manager.py     # 信任存储管理
│
├── enhanced_certificates/              # 证书存储
│   ├── ecdsa_p256/                    # ECDSA证书
│   ├── mldsa44/                       # ML-DSA-44证书
│   ├── mldsa65/                       # ML-DSA-65证书（推荐）
│   ├── mldsa87/                       # ML-DSA-87证书
│   ├── falcon512/                     # Falcon-512证书
│   ├── falcon1024/                    # Falcon-1024证书
│   ├── generate_ecdsa_certs.py        # ECDSA证书生成
│   ├── generate_multi_algorithm_certs.py  # PQC证书生成
│   └── x509_wrapper.py                # X.509包装工具
│
├── benchmarks/                         # 性能基准测试
│   ├── run_benchmarks.py              # 主测试脚本
│   ├── batch_benchmark_and_visualize.py  # 批量测试工具
│   ├── paper_visualization.py         # 论文级可视化
│   ├── README.md                      # 详细测试文档
│   ├── 完整实现文档.md                 # 实现文档
│   └── results/                       # 测试结果
│       ├── benchmarks/                # 单次测试结果
│       └── batch_tests/               # 批量测试结果
│
├── frontend/                           # Web可视化界面
│   ├── enhanced_api_server.py         # FastAPI服务器
│   ├── enhanced_index.html            # 前端HTML
│   ├── enhanced_style.css             # 样式表
│   ├── enhanced_script.js             # JavaScript逻辑
│   ├── ENHANCED_README.md             # 前端文档
│   ├── QUICKSTART.md                  # 快速启动指南
│   └── static/plots/                  # 性能图表
│
├── requirements.txt                    # Python依赖
├── README.md                          # 本文件
└── venv/                              # 虚拟环境（自动生成）
```

### 核心模块说明

#### 1. `core/` - 核心实现
- **types.py**：定义TLS 1.3的所有类型（TLSMode、NamedGroup、SignatureScheme等）
- **crypto/**：
  - `key_exchange.py`：实现所有KEM算法（经典、PQC、混合）
  - `signature.py`：实现所有签名算法
  - `record_encryption.py`：TLS记录层加密（AES-GCM、ChaCha20-Poly1305）
  - `enhanced_certificate/`：完整的证书验证系统
- **protocol/**：
  - `messages.py`：TLS消息的序列化和反序列化
  - `handshake.py`：握手流程控制

#### 2. `implementation/enhanced_v2/` - 增强实现
- **enhanced_client.py**：TLS客户端，支持三种模式
- **enhanced_server.py**：TLS服务器，支持多证书配置
- **cert_loader.py**：自动加载X.509和PQC证书
- **config.py**：统一的配置管理（证书路径、算法选择等）
- **multi_cert_manager.py**：根据算法自动选择证书
- **trust_store_manager.py**：管理信任锚和证书链

#### 3. `benchmarks/` - 性能测试
- **run_benchmarks.py**：主测试脚本，支持多种测试模式
- **batch_benchmark_and_visualize.py**：批量测试，支持6种预定义场景
- **paper_visualization.py**：生成高质量PDF图表
- **network_config.py**：网络延迟模拟配置

#### 4. `frontend/` - Web界面
- **enhanced_api_server.py**：基于FastAPI的REST API服务器
- **enhanced_index.html**：单页应用前端
- **enhanced_script.js**：处理握手执行、数据可视化、页面交互
- **enhanced_style.css**：现代化UI设计

---

## 📚 使用指南

### 基础使用

#### 1. 运行单次握手测试
```python
from core.types import TLSMode
from implementation.enhanced_v2.enhanced_client import EnhancedTLSClient
from implementation.enhanced_v2.enhanced_server import EnhancedTLSServer

# 创建服务器（混合模式，ML-DSA-65签名）
server = EnhancedTLSServer(
    mode=TLSMode.HYBRID,
    algorithm="mldsa65"
)

# 创建客户端
client = EnhancedTLSClient(
    mode=TLSMode.HYBRID,
    algorithm="mldsa65"
)

# 执行握手
server.start()
client.connect("localhost", 8443)
```

#### 2. 性能基准测试
```bash
cd benchmarks

# 测试所有算法（默认10次迭代）
python run_benchmarks.py

# 只测试密钥交换算法
python run_benchmarks.py --test kex

# 只测试签名算法
python run_benchmarks.py --test sig

# 只测试TLS握手
python run_benchmarks.py --test handshake

# 网络感知测试
python run_benchmarks.py --test network
```

#### 3. 批量测试
```bash
# 快速验证（1次迭代，~2分钟）
python batch_benchmark_and_visualize.py --scenarios quick

# 标准测试（10次迭代，~5分钟）
python batch_benchmark_and_visualize.py --scenarios standard

# 全面测试（50次迭代+多网络，~30分钟）
python batch_benchmark_and_visualize.py --scenarios comprehensive

# 列出所有可用场景
python batch_benchmark_and_visualize.py --list

# 运行所有场景
python batch_benchmark_and_visualize.py --all
```

### 高级使用

#### 1. 自定义算法组合
```python
from core.types import TLSMode, NamedGroup, SignatureScheme

# 自定义配置
config = {
    "mode": TLSMode.HYBRID,
    "kem": NamedGroup.p384_kyber768,  # 使用P-384+Kyber768
    "signature": SignatureScheme.falcon1024,  # 使用Falcon-1024
}

# 创建客户端
client = EnhancedTLSClient(**config)
```

#### 2. 生成自定义证书
```bash
cd enhanced_certificates

# 编辑generate_multi_algorithm_certs.py
# 修改算法参数，例如：
# ALGORITHM = "falcon512"  # 改为您需要的算法

python generate_multi_algorithm_certs.py
```

#### 3. 网络环境模拟
```python
from benchmarks.run_benchmarks import NetworkConfig

# 模拟慢速WAN + 跨国距离
network_config = NetworkConfig(
    rate_profile='slow_wan',      # 1 Mbps
    distance_profile='international'  # 10000 km
)

# 运行测试
result = benchmark_complete_handshake_with_network(
    TLSMode.HYBRID,
    network_config
)

print(f"总时间: {result['total_time']:.2f} ms")
print(f"网络延迟占比: {result['network_delay_ratio']:.1f}%")
```

#### 4. Web界面高级配置
```python
# 编辑 frontend/enhanced_api_server.py

# 修改端口
uvicorn.run(
    "enhanced_api_server:app",
    host="0.0.0.0",  # 允许外部访问
    port=9000,       # 自定义端口
    reload=True
)

# 添加CORS支持（跨域）
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
)
```

---

## 📊 性能评估

### 典型测试结果

#### 握手性能对比（NIST Level 3）
| 模式 | 握手时间 | 吞吐量 | ClientHello大小 | 证书链大小 |
|------|---------|--------|----------------|-----------|
| Classic | 2.77 ms | 360.6 ops/s | 301 B | ~2 KB |
| PQC | 2.57 ms | 389.3 ops/s | 2630 B | ~8 KB |
| Hybrid | 2.48 ms | 402.5 ops/s | 3040 B | ~9 KB |

**关键发现**：
- ✅ PQC模式比Classic快 **7%**（得益于Kyber的高性能）
- ✅ Hybrid模式最快（经过ClientHello优化）
- ⚠️ 消息大小增加 **8-10倍**

#### 密钥交换性能（Level 3）
| 算法 | 平均时间 | 吞吐量 | 公钥大小 |
|------|---------|--------|---------|
| X25519 | 17.88 μs | 55,925 ops/s | 32 B |
| Kyber768 | 0.48 μs | 2,070,822 ops/s | 1184 B |
| P-256+Kyber768 | 0.88 μs | 1,141,422 ops/s | 1251 B |

**关键发现**：
- ✅ Kyber768速度是X25519的 **37倍**！
- ⚠️ 公钥大小增加 **37-39倍**

#### 签名性能（Level 3）
| 算法 | 签名时间 | 验证时间 | 签名大小 |
|------|---------|---------|---------|
| ECDSA-P256 | 0.51 ms | 0.12 ms | 72 B |
| Dilithium3 | 1.21 ms | 0.17 ms | 3309 B |
| P-256+Dilithium3 | 0.89 ms | 0.29 ms | 3385 B |

**关键发现**：
- ⚠️ Dilithium3签名慢 **2.4倍**
- ⚠️ 签名大小增加 **46倍**
- ✅ 混合模式验证更快（可并行验证）

#### 网络感知测试（localhost + local）
| 模式 | 计算时间 | 网络延迟 | 总时间 | 延迟占比 |
|------|---------|---------|--------|---------|
| Classic | 6.06 ms | 0.02 ms | 6.09 ms | 0.3% |
| PQC | 7.34 ms | 0.26 ms | 7.59 ms | 3.4% |
| Hybrid | 9.40 ms | 0.26 ms | 9.66 ms | 2.7% |

**关键发现**：
- ⚠️ PQC消息大小增加 **8.3倍**（4974B vs 532B）
- ✅ 本地环境下网络延迟影响小（<5%）
- ⚠️ 广域网环境下影响会显著增加

### 安全级别映射

| NIST等级 | 经典算法 | 纯PQC算法 | 混合算法 | 安全强度 |
|----------|---------|----------|---------|---------|
| **Level 1** | - | Kyber512 + Falcon512 | P-256+Kyber512 | ~128位 |
| **Level 3** | X25519 + ECDSA-P256 | Kyber768 + Dilithium3 | P-256+Kyber768 + Dilithium3 | ~192位 |
| **Level 5** | - | Kyber1024 + Dilithium5 | P-521+Kyber1024 + Falcon1024 | ~256位 |

**推荐配置**：Level 3混合模式（平衡安全性和性能）

---

## 🔬 技术细节

### 混合密钥交换

混合KEM采用"组合器"设计，确保只要一个算法安全，整体就安全：

```
共享密钥 = KDF(经典共享密钥 ∥ PQC共享密钥 ∥ 上下文)
```

**实现**：
```python
# 经典ECDH
classical_shared = ecdh_exchange(classical_private, classical_public)

# PQC KEM
pqc_shared = kyber_decapsulate(pqc_private, pqc_ciphertext)

# 组合
combined_shared = HKDF(
    classical_shared + pqc_shared + context,
    algorithm=hashes.SHA256()
)
```

### 混合签名

混合签名同时使用两种算法，验证时必须两者都通过：

```python
def hybrid_sign(message, classical_key, pqc_key):
    sig1 = ecdsa_sign(message, classical_key)
    sig2 = dilithium_sign(message, pqc_key)
    return sig1 + sig2

def hybrid_verify(message, signature, classical_pubkey, pqc_pubkey):
    sig1, sig2 = split_signature(signature)
    return (
        ecdsa_verify(message, sig1, classical_pubkey) and
        dilithium_verify(message, sig2, pqc_pubkey)
    )
```

### 证书链验证

#### 经典证书验证（ECDSA）
```python
# 签名包含在X.509证书内
intermediate_cert.public_key().verify(
    server_cert.signature,
    server_cert.tbs_certificate_bytes,
    ec.ECDSA(hashes.SHA256())
)
```

#### PQC证书验证（ML-DSA/Falcon）
```python
# 签名单独存储在.sig文件
verifier = HybridCertificateVerifier(trust_anchors, policy)
result = verifier.verify_certificate_chain(
    leaf_cert=server_cert_info,
    intermediate_certs=[intermediate_cert_info]
)
```

**关键区别**：
- 经典证书签名在X.509内部，验证用cryptography库
- PQC证书签名单独存储，验证用liboqs库
- PQC签名太大（~3KB），无法放入标准X.509扩展

### 网络延迟模拟

```python
# 传输时延 = 数据大小 / 传输速率
transmission_delay = message_size_bits / transmission_rate_bps

# 传播时延 = 距离 / 光速
propagation_delay = distance_km / speed_of_light_km_per_s

# 总网络延迟
network_delay = transmission_delay + propagation_delay

# 模拟（使用sleep）
time.sleep(network_delay)
```

---

## 🛠️ 故障排除

### 常见问题

#### 1. NumPy版本冲突
```
错误：A module that was compiled using NumPy 1.x cannot be run in NumPy 2.1.3
解决：pip install "numpy<2.0.0"
```

#### 2. liboqs安装失败
```bash
# Windows
pip install --upgrade liboqs-python

# Linux (需要先安装liboqs C库)
sudo apt-get install liboqs-dev
pip install liboqs-python

# macOS
brew install liboqs
pip install liboqs-python
```

#### 3. 证书验证失败
```bash
# 检查证书文件是否存在
ls enhanced_certificates/mldsa65/

# 重新生成证书
cd enhanced_certificates
python generate_multi_algorithm_certs.py
```

#### 4. 端口被占用
```bash
# Windows
netstat -ano | findstr :8000
taskkill /PID <进程ID> /F

# Linux/macOS
lsof -ti:8000 | xargs kill -9
```

#### 5. 测试执行时间异常短
```bash
# 检查是否使用了正确的虚拟环境
which python  # Linux/macOS
where python  # Windows

# 确认依赖已安装
pip list | grep -E "liboqs|cryptography|numpy"
```

### 性能优化建议

1. **ClientHello优化**：只为选定的KEM生成密钥对，减少消息大小70%
2. **证书缓存**：复用已加载的证书，避免重复解析
3. **并行验证**：混合签名可并行验证两个算法
4. **网络配置**：本地测试使用localhost配置，减少延迟
5. **迭代次数**：快速测试用5次，论文数据用50-100次

---

## 📖 相关文档

- **核心实现**：
  - [核心类型定义](core/types.py)
  - [密钥交换实现](core/crypto/key_exchange.py)
  - [签名算法实现](core/crypto/signature.py)

- **证书管理**：
  - [增强证书验证](core/crypto/enhanced_certificate/README.md)
  - [证书生成指南](enhanced_certificates/)

- **性能测试**：
  - [基准测试指南](benchmarks/README.md)
  - [完整实现文档](benchmarks/完整实现文档.md)
  - [安全等级说明](benchmarks/security_level.md)

- **Web界面**：
  - [前端使用指南](frontend/ENHANCED_README.md)
  - [快速启动](frontend/QUICKSTART.md)
  - [算法配置](frontend/ALGORITHM_CONFIG.md)

---

## 🤝 贡献指南

欢迎贡献代码、报告问题和提出建议！

### 如何贡献
1. Fork本项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开Pull Request

### 代码规范
- 遵循PEP 8 Python代码风格
- 添加必要的注释和文档字符串
- 编写单元测试
- 更新相关文档

---

## 🙏 致谢

本项目使用了以下开源项目：

- [liboqs](https://github.com/open-quantum-safe/liboqs) - Open Quantum Safe项目
- [cryptography](https://github.com/pyca/cryptography) - Python密码学库
- [FastAPI](https://github.com/tiangolo/fastapi) - 现代Web框架
- [matplotlib](https://matplotlib.org/) - 数据可视化
- [NumPy](https://numpy.org/) - 数值计算

感谢NIST后量子密码学标准化项目为密码学社区做出的贡献。

---

## 📚 参考资料

### 标准文档
- [RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [NIST PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203 - ML-KEM (Kyber)](https://csrc.nist.gov/publications/detail/fips/203/final)
- [FIPS 204 - ML-DSA (Dilithium)](https://csrc.nist.gov/publications/detail/fips/204/final)

### 研究论文
- Stebila, D., & Mosca, M. (2016). Post-quantum key exchange for the internet and the open quantum safe project.
- Schwabe, P., et al. (2019). CRYSTALS-KYBER. NIST PQC Round 2 submission.
- Ducas, L., et al. (2018). CRYSTALS-Dilithium. NIST PQC Round 2 submission.

### 相关项目
- [Open Quantum Safe](https://openquantumsafe.org/)
- [PQC-TLS](https://github.com/open-quantum-safe/oqs-demos)
- [Cloudflare CIRCL](https://github.com/cloudflare/circl)

---

<div align="center">

**⭐ 如果这个项目对您有帮助，请给我们一个Star！⭐**

Made with ❤️ by TLS Hybrid Security Team

[⬆ 回到顶部](#hybrid-pqc-tls-lab)

</div>


