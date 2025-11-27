# TLS性能基准测试套件

本目录包含TLS协议性能基准测试工具，用于评估传统、后量子密码(PQC)和混合TLS模式的性能差异。

## 📁 目录结构

```
benchmarks/
├── run_benchmarks.py          # 主基准测试脚本
├── visualize_results.py       # 文本格式结果可视化
├── paper_visualization.py     # 论文格式可视化（依赖pandas）
├── paper_visualization_simple.py # 简化版论文可视化
├── __init__.py
├── results/                   # 测试结果目录
│   ├── benchmarks/            # 原始测试结果
│   │   ├── benchmark_*.json  # JSON格式结果
│   │   ├── benchmark_*.txt   # 文本格式结果
│   │   └── 时间戳目录/        # 详细测试数据
│   └── paper_plots/          # 论文用图表
│       ├── kem_comparison.pdf
│       ├── signature_comparison.pdf
│       ├── handshake_comparison.pdf
│       ├── comprehensive_comparison.pdf
│       └── boxplot_comparison.pdf
└── README.md                 # 本文件
```

## 🚀 快速开始

### 1. 运行基准测试

```bash
# 进入benchmarks目录
cd benchmarks

# 使用虚拟环境运行基准测试
venv\Scripts\python run_benchmarks.py
```

基准测试将自动执行以下测试（按NIST安全等级组织，精简版）：
- **密钥交换算法**：
  - Level 3：X25519（经典）、Kyber768（纯PQC）、P256+Kyber768（混合）
- **签名算法**：
  - Level 3：ECDSA-P256（经典）、Dilithium3（纯PQC）、P256+Dilithium3（混合）
- **TLS握手**：Level 3安全等级下经典/混合/纯PQC模式对比
- **网络感知握手**：本地和局域网环境下评估网络时延影响
- **10秒性能测试**：经典和纯PQC模式快速性能评估

### 2. 查看文本格式结果

```bash
# 生成文本格式的可视化结果
venv\Scripts\python visualize_results.py
```

输出包括：
- 密钥交换算法性能表格
- 签名算法性能表格
- TLS握手柱状图比较
- 安全等级性能分析
- **网络感知握手性能分析**：新增的网络延迟影响分析

### 3. 生成论文用图表

```bash
# 生成PDF格式的论文图表
venv\Scripts\python paper_visualization_simple.py
```

生成的PDF图表保存在 `results/paper_plots/` 目录。

## 🌐 网络感知性能评估方案

### 核心创新：网络时延模拟系统

本方案设计了创新的网络时延模拟系统，解决了传统TLS性能测试中忽略传输时延的问题：

#### 传输时延模拟 (Transmission Delay)
- **计算公式**：`传输时间 = 数据大小(bits) / 传输速率(bps)`
- **实现方式**：使用`sleep()`函数精确模拟实际传输时间
- **可配置参数**：
  - 传输速率：`localhost` (1Gbps)、`lan` (100Mbps)、`fast_wan` (10Mbps)、`slow_wan` (1Mbps)、`mobile` (100Kbps)

#### 传播时延模拟 (Propagation Delay)
- **计算公式**：`传播时间 = 物理距离(km) / 光速(200,000 km/s)`
- **实现方式**：基于地理距离模拟光信号传播时间
- **可配置参数**：
  - 距离配置：`local` (0.1km)、`city` (10km)、`province` (500km)、`country` (2000km)、`international` (10000km)

#### 完整握手流程测量
- **范围**：从ClientHello到CertificateVerify的完整过程
- **包含内容**：
  - 自动证书路径管理（根据算法类型选择证书）
  - 证书加载、签名、发送和验证的完整流程
  - 证书链构建（服务器证书.crt + 中间CA证书）
  - PQ签名生成和验证（.sig文件）
  - 握手哈希计算、网络传输模拟
  - 信任存储管理器初始化（多算法支持）
- **证书支持**：完整的X.509包装后量子证书验证，支持证书链验证和多算法信任锚

### 网络配置参数系统

```python
@dataclass
class NetworkConfig:
    # 预定义传输速率配置
    transmission_rates = {
        'localhost': 1_000_000_000,      # 1 Gbps - 本地测试
        'lan': 100_000_000,             # 100 Mbps - 局域网
        'fast_wan': 10_000_000,         # 10 Mbps - 高速广域网
        'slow_wan': 1_000_000,          # 1 Mbps - 低速广域网
        'mobile': 100_000,              # 100 Kbps - 移动网络
    }

    # 预定义距离配置
    distances = {
        'local': 0.1,                   # 本地（同机房）
        'city': 10,                     # 城域（同城）
        'province': 500,               # 省域（同省）
        'country': 2000,               # 全国
        'international': 10000,        # 国际
    }
```

## 📊 测试内容详解

### 传统性能测试

#### 密钥交换算法测试（按NIST安全等级）

| 安全等级 | 经典算法 | 纯PQC算法 | 混合算法 | 特点 |
|----------|----------|-----------|----------|------|
| Level 3 (~192-bit) | X25519 | Kyber768 | P-256+Kyber768 | 核心测试，平衡性能和安全性 |

**测试指标**：
- 平均执行时间（毫秒）
- 吞吐量（操作数/秒）
- 10秒内操作次数
- 公钥大小（字节）

#### 签名算法测试（按NIST安全等级）

| 安全等级 | 经典算法 | 纯PQC算法 | 混合算法 | 特点 |
|----------|----------|-----------|----------|------|
| Level 3 (~192-bit) | ECDSA-P256 | Dilithium3 | P-256+Dilithium3 | 核心测试，平衡性能和安全性 |

**测试指标**：
- 平均签名时间（毫秒）
- 验证吞吐量（操作数/秒）
- 10秒内签名次数
- 公钥和签名大小（字节）

#### TLS握手测试（按NIST安全等级）

| 安全等级 | 经典模式 | 纯PQC模式 | 混合模式 | 特点 |
|----------|----------|-----------|----------|------|
| Level 3 (~192-bit) | X25519 + ECDSA-P256 | Kyber768 + Dilithium3 | P-256+Kyber768 + Dilithium3 | 核心测试，混合模式使用纯PQC签名 |

**测试指标**：
- 10秒内握手次数
- 握手吞吐量（握手数/秒）
- 握手消息总大小（KB）
- 平均握手时间（毫秒）

#### 网络感知握手测试（按网络环境）

| 网络环境 | 距离 | 传输速率 | 典型场景 |
|----------|------|----------|----------|
| localhost | 0.1km | 1Gbps | 本地开发测试（最快） |
| lan | 10km | 100Mbps | 企业局域网（快速） |

**网络感知测试指标**：
- **计算时间**：纯密码学计算耗时（不含网络时延）
- **网络时延**：传输时延 + 传播时延的总和
- **总时间**：计算时间 + 网络时延
- **网络延迟占比**：网络时延占总时间的百分比
- **跨环境性能下降**：不同网络环境下性能衰减幅度

### 签名算法测试

| 算法 | 安全等级 | 特点 |
|------|----------|------|
| ECDSA-P256 | L1 (传统) | 椭圆曲线数字签名 |
| Dilithium3 | L3 (PQC) | 后量子数字签名 |
| P256+Dilithium3 | L5 (混合) | 传统+PQC双重签名 |

**测试指标**：
- 平均签名时间（毫秒）
- 验证吞吐量（操作数/秒）
- 10秒内签名次数
- 公钥和签名大小（字节）

### TLS握手测试

| 模式 | 安全等级 | 算法组合 |
|------|----------|----------|
| 传统模式 | L1 | X25519 + ECDSA-P256 |
| PQC模式 | L3 | Kyber768 + Dilithium3 |
| 混合模式 | L5 | P-256+Kyber768 + P256+Dilithium3 |

**测试指标**：
- 10秒内握手次数
- 握手吞吐量（握手数/秒）
- 握手消息总大小（KB）
- 平均握手时间（毫秒）

## 📈 结果可视化

### 文本可视化 (`visualize_results.py`)

生成控制台友好的文本格式结果：

```
====================================================
            密钥交换算法性能比较
====================================================
算法           | 平均时间   | 吞吐量    | 10秒操作数
---------------|-----------|-----------|-----------
X25519        | 0.123 ms  | 8126.5 ops/s | 81,265
Kyber768      | 0.246 ms  | 4065.0 ops/s | 40,650
P-256+Kyber768| 0.369 ms  | 2708.3 ops/s | 27,083
```

### 论文可视化 (`paper_visualization_simple.py`)

生成适合学术论文的PDF图表：

1. **KEM算法比较图** (`kem_comparison.pdf`)
   - 吞吐量、操作次数、平均时间、密钥大小四维度比较
   - 传统/PQC/混合算法颜色编码

2. **签名算法比较图** (`signature_comparison.pdf`)  
   - 签名性能多维度可视化
   - 包含签名大小和验证时间

3. **TLS握手比较图** (`handshake_comparison.pdf`)
   - 三种模式性能对比
   - 握手次数和消息大小分析

4. **综合性能比较图** (`comprehensive_comparison.pdf`)
   - 所有算法的综合性能视图
   - 安全等级与性能关系

5. **箱线图风格比较** (`boxplot_comparison.pdf`)
   - 统计分布可视化
   - 异常值检测

## 🔧 高级用法

### 网络感知性能测试

```bash
# 只运行网络感知握手测试
venv\Scripts\python run_benchmarks.py --test network

# 指定网络环境进行测试
venv\Scripts\python run_benchmarks.py --test network --network-profiles lan fast_wan --distance-profiles local city

# 证书验证已自动化，无需手动指定路径
```

### 自定义网络配置

```python
# 在run_benchmarks.py中自定义网络配置

# 添加新的传输速率配置
NetworkConfig.transmission_rates['custom_fast'] = 50_000_000  # 50 Mbps

# 添加新的距离配置
NetworkConfig.distances['custom_distance'] = 100  # 100km

# 使用自定义配置运行测试
network_config = NetworkConfig(rate_profile='custom_fast', distance_profile='custom_distance')
result = benchmark_complete_handshake_with_network(TLSMode.HYBRID, network_config)
```

### 自定义测试参数

```python
# 在run_benchmarks.py中修改测试参数

# 修改迭代次数（默认100次）
iterations = 500

# 修改测试的算法组合
test_groups = [
    NamedGroup.X25519,
    NamedGroup.KYBER768,
    NamedGroup.P256_KYBER768
]

# 修改签名算法
signature_schemes = [
    SignatureScheme.ECDSA_P256,
    SignatureScheme.DILITHIUM3,
    SignatureScheme.P256_DILITHIUM3
]
```

### 批量测试

```bash
# 运行多次测试并比较结果
for i in {1..5}; do
    venv\Scripts\python run_benchmarks.py
    sleep 10
done
```

### 结果分析脚本

```python
# 自定义分析脚本示例
import json
from pathlib import Path

# 加载最新结果
results_dir = Path('results/benchmarks')
latest_json = max(results_dir.glob('benchmark_*.json'))

with open(latest_json, 'r') as f:
    data = json.load(f)

# 自定义分析逻辑
for kem in data['key_exchange']:
    print(f"{kem['name']}: {kem['throughput']:.1f} ops/s")
```

## 📋 性能指标说明

### 关键性能指标

1. **吞吐量 (Throughput)**
   - 单位：操作数/秒 (ops/s)
   - 意义：系统处理能力的重要指标

2. **10秒操作数**
   - 单位：次数
   - 意义：实际应用场景下的性能表现

3. **平均时间**
   - 单位：毫秒 (ms)
   - 意义：单次操作的时间成本

4. **消息大小**
   - 单位：字节/千字节
   - 意义：通信开销和带宽需求

### 网络感知性能指标（新增）

5. **计算时间 (Compute Time)**
   - 单位：毫秒 (ms)
   - 意义：纯密码学运算耗时，不包含网络传输时延

6. **网络时延 (Network Delay)**
   - 单位：毫秒 (ms)
   - 意义：传输时延 + 传播时延的总和

7. **总时间 (Total Time)**
   - 单位：毫秒 (ms)
   - 意义：握手完成所需的完整时间

8. **网络延迟占比 (Network Delay Ratio)**
   - 单位：百分比 (%)
   - 意义：网络时延占总握手时间的比例

9. **跨环境性能下降 (Cross-Environment Performance Drop)**
   - 单位：百分比 (%)
   - 意义：不同网络环境下性能衰减的幅度

### 安全等级对应

| 安全等级 | 描述 | 适用场景 |
|----------|------|----------|
| L1 | 传统密码学 | 当前标准应用 |
| L3 | 后量子密码学 | 长期安全需求 |
| L5 | 混合模式 | 最高安全级别 |

## 🐛 故障排除

### 常见问题

1. **NumPy版本冲突**
   ```bash
   # 使用项目虚拟环境
   venv\Scripts\python --version
   venv\Scripts\pip list | grep numpy
   ```

2. **文件路径错误**
   ```bash
   # 确保在正确目录运行
   pwd  # 应该显示 .../Hybrid_PQC_TLS_Lab/benchmarks
   ```

3. **依赖包缺失**
   ```bash
   # 安装依赖
   venv\Scripts\pip install -r ../requirements.txt
   ```

### 日志文件

测试结果保存在：
- `results/benchmarks/benchmark_YYYYMMDD_HHMMSS.json` - JSON格式
- `results/benchmarks/benchmark_YYYYMMDD_HHMMSS.txt` - 文本格式
- `results/benchmarks/YYYYMMDD_HHMMSS/` - 详细测试数据

## 📚 相关文档

- [项目主README](../README.md) - 项目整体介绍
- [实验指南](../EXPERIMENT_GUIDE.md) - 详细实验步骤
- [实验结果](../EXPERIMENT_RESULTS.md) - 实验结果分析

## 🔧 核心改进：消息大小优化与可视化修复

### ✅ 消息大小优化

**问题**: 客户端在生成ClientHello时会为每一种supported group都生成对应公钥，导致消息过大。

**解决方案**:
- **选定KEM策略**: 客户端选择特定的KEM启动，只保留该KEM作为主要支持组
- **智能回退**: 为混合模式保留经典算法回退选项，为纯PQC模式不保留回退
- **消息压缩**: 大幅减少ClientHello消息大小，提高握手效率

**具体改进**:
```python
# 修改前：为所有supported_groups生成密钥对
for group in self.config['supported_groups']:
    kex = create_key_exchange(group, is_server=False)
    kex.generate_keypair()

# 修改后：只为选定的主要KEM生成密钥对
selected_kem = NamedGroup.p256_kyber768  # 例如混合模式
client = ClientHandshake(mode=mode, selected_kem=selected_kem)
```

### ✅ 可视化修复

**问题**: handshake comparison图表中缺少混合模式的数据。

**解决方案**:
- 恢复10秒握手测试中的混合模式
- 确保所有TLS模式都有完整的性能数据用于可视化比较
- 提供经典/PQC/混合模式的三维对比

### 实际支持的算法组合

根据核心实现中的`types.py`文件，本测试套件实际支持以下算法组合：

#### 密钥交换算法 (Key Exchange)
- **经典算法**: `x25519`, `secp256r1`, `secp384r1`, `secp521r1`
- **纯PQC算法**: `kyber512`, `kyber768`, `kyber1024`, `ML_KEM_512`, `ML_KEM_768`, `ML_KEM_1024`
- **混合算法**: `p256_kyber512`, `p256_kyber768`, `p384_kyber768`, `p521_kyber1024`

#### 签名算法 (Signature)
- **经典算法**: `ecdsa_secp256r1_sha256`, `ecdsa_secp384r1_sha384`, `ecdsa_secp521r1_sha512`
- **纯PQC算法**: `dilithium2`, `dilithium3`, `dilithium5`, `falcon512`, `falcon1024`
- **混合算法**: `p256_dilithium2`, `p256_dilithium3`, `p384_dilithium5`, `p256_falcon512`, `p521_falcon1024`

### 安全等级映射

| NIST等级 | 经典算法 | 混合算法 | 纯PQC算法 | 安全强度 |
|----------|----------|----------|-----------|----------|
| Level 3 | X25519 + ECDSA-P256 | P-256+Kyber768 + Dilithium3 | Kyber768 + Dilithium3 | ~192-bit |
| Level 4 | - | P-384+Kyber768 + P-384+Dilithium5 | - | ~192-bit (增强) |
| Level 5 | - | P-521+Kyber1024 + P-521+Falcon1024 | Kyber1024 + Dilithium5 | ~256-bit |

**重要修正说明**:
- **Level 4**: 由于没有直接对应的经典算法，使用P-384混合算法提供增强的安全性
- **Level 5混合签名**: 使用`p521_falcon1024`而不是不存在的`p521_dilithium5`
- **测试覆盖**: 涵盖了所有实际支持的算法组合，确保测试的实用性

### 快速测试建议

```bash
# 极快速全测试（默认10次迭代，最快结果）
python run_benchmarks.py

# 超快速测试（5次迭代）
python run_benchmarks.py --iterations 5

# 只测试密钥交换算法
python run_benchmarks.py --test kex

# 只测试签名算法
python run_benchmarks.py --test sig

# 只测试握手（现在包含混合模式）
python run_benchmarks.py --test handshake

# 只测试网络感知握手（推荐最快，消息更小）
python run_benchmarks.py --test network
```

### 消息大小对比

**改进效果**:
- **修改前**: 客户端为所有supported groups生成密钥对，消息很大
- **修改后**: 客户端只为选定的KEM生成密钥对，消息大幅减小

**典型对比**:
```
Level 3混合模式消息大小对比:
- 修改前: ~5,000+ 字节（为多个KEM生成密钥对）
- 修改后: ~1,500 字节（只为选定的KEM生成密钥对）
- 减少幅度: ~70%

证书验证耗时（使用PQWrappedCertificate）:
- 证书加载: ~2ms（从.crt和.sig文件加载）
- 证书解析: ~5ms（DER格式证书解析）
- PQ信息提取: ~3ms（公钥、算法、签名提取）
- 证书验证: ~5ms（基本证书信息验证）
- 总验证时间: ~15ms

证书验证流程:
```
[证书验证] 使用EnhancedTLSClient验证证书链...
[证书验证] 开始验证服务器证书链...
[步骤1] ✓ 服务器证书解析成功
[步骤2] 提取后量子信息...
      ✓ 服务器证书PQ算法: ML-DSA-65
      ✓ 服务器证书PQ公钥: 2,592 字节
✅ 证书验证成功: ML-DSA-65
      公钥大小: 2592 字节
```

## 🎯 使用建议

1. **快速体验**：运行默认测试 `python run_benchmarks.py`（只需几分钟，包含完整证书验证）
2. **极速测试**：`python run_benchmarks.py --test network`（最快结果，消息更小）
3. **证书验证测试**：自动证书验证，无需手动指定路径（根据算法类型自动选择）
4. **初次使用**：先运行 `visualize_results.py` 查看文本结果
5. **论文写作**：使用 `paper_visualization_simple.py` 生成图表
6. **深度分析**：直接分析JSON格式的原始数据

### 证书验证自动化

**自动证书路径管理**:
- **经典模式**：自动选择 `mldsa44` 证书（ECDSA签名）
- **纯PQC模式**：自动选择 `mldsa65` 证书（Dilithium3签名）
- **混合模式**：自动选择 `mldsa65` 证书（Dilithium3签名）

**无需手动指定路径**:
```bash
# 所有测试都自动包含证书验证
python run_benchmarks.py --iterations 5
python run_benchmarks.py --test handshake
python run_benchmarks.py --test network
```

### 证书验证测试说明

完整的证书验证测试包含：
- **自动证书路径管理**：根据算法类型自动选择证书（.crt文件）和PQ签名（.sig文件）
- **证书链构建**：服务器证书 + 中间CA证书（DER格式）
- **PQ签名处理**：生成和验证后量子签名
- **证书验证**：在所有握手测试中都包含证书验证
- **信任存储**：初始化多算法信任锚（首次运行需额外50ms）
- **性能测量**：包含完整证书验证耗时（~15ms）

**证书路径自动映射**:
- **经典模式**：`ecdsa_secp256r1_sha256` → `mldsa44`证书
- **纯PQC模式**：`dilithium3` → `mldsa65`证书
- **混合模式**：`p256_dilithium3` → `mldsa65`证书

**文件类型说明**:
- `.crt` 文件：X.509证书文件（标准证书格式）
- `.sig` 文件：后量子签名文件（PQ算法签名，符合X.509标准要求）
- `.key` 文件：私钥文件（用于签名生成，不在验证时使用）

---

**最后更新**：2025年1月14日  
**维护者**：TLS性能测试团队