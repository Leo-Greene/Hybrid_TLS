# 混合PQC-TLS HTTPS服务器使用指南

本指南介绍如何使用自定义混合TLS协议实现HTTPS网站，支持浏览器访问和抓包分析。

## 架构说明

### 方案1: 直接HTTPS服务器（需要自定义客户端）

```
浏览器/客户端 -> 自定义TLS -> HTTPS服务器
```

**特点**：
- 直接使用自定义TLS协议
- 需要支持自定义TLS的客户端
- 可以使用Wireshark抓包查看加密数据

### 方案2: HTTPS代理服务器（推荐）

```
浏览器 -> 标准HTTPS -> 代理服务器 -> 自定义TLS -> 后端服务器
```

**特点**：
- 浏览器使用标准HTTPS协议
- 代理服务器将标准HTTPS转换为自定义TLS
- 后端服务器使用自定义TLS协议
- 可以使用Wireshark抓包查看两端的数据包

## 快速开始

### 1. 启动HTTPS服务器（使用自定义TLS）

```bash
# 启动后端HTTPS服务器（使用自定义TLS）
python implementation/enhanced_v2/https_server.py --port 8443 --mode hybrid
```

### 2. 启动HTTPS代理服务器（可选）

```bash
# 启动代理服务器（将标准HTTPS转换为自定义TLS）
python implementation/enhanced_v2/https_proxy.py \
    --proxy-port 8080 \
    --backend-host 127.0.0.1 \
    --backend-port 8443 \
    --mode hybrid
```

### 3. 配置浏览器

#### 方式1: 使用代理（推荐）

1. 打开浏览器设置
2. 配置HTTP代理：
   - 代理服务器: `127.0.0.1`
   - 端口: `8080`
3. 访问: `https://127.0.0.1:8443`

#### 方式2: 使用自定义客户端

使用提供的TLS客户端直接连接：

```bash
python implementation/enhanced_v2/enhanced_client.py \
    --host 127.0.0.1 \
    --port 8443 \
    --mode hybrid
```

## 抓包分析

### 使用Wireshark抓包

1. **启动Wireshark**
2. **选择网络接口**（如：Loopback）
3. **设置过滤规则**：
   ```
   tcp.port == 8443 or tcp.port == 8080
   ```
4. **开始抓包**
5. **访问网站**，观察加密的数据包

### 抓包要点

- **握手阶段**：可以看到TLS握手消息（ClientHello, ServerHello等）
- **应用数据**：可以看到加密的HTTP请求和响应
- **数据包大小**：后量子算法的签名和密钥较大，数据包会相应增大

## 命令行参数

### https_server.py

```bash
python https_server.py [选项]

选项:
  --host HOST         绑定主机 (默认: 0.0.0.0)
  --port PORT         绑定端口 (默认: 8443)
  --mode MODE         TLS模式: classic/pqc/hybrid (默认: hybrid)
  --algorithm ALGO    签名算法: mldsa65/falcon512等 (可选)
```

### https_proxy.py

```bash
python https_proxy.py [选项]

选项:
  --proxy-host HOST   代理服务器主机 (默认: 0.0.0.0)
  --proxy-port PORT   代理服务器端口 (默认: 8080)
  --backend-host HOST 后端服务器主机 (默认: 127.0.0.1)
  --backend-port PORT 后端服务器端口 (默认: 8443)
  --mode MODE         TLS模式: classic/pqc/hybrid (默认: hybrid)
  --algorithm ALGO    签名算法: mldsa65/falcon512等 (可选)
```

## 示例场景

### 场景1: 本地测试

```bash
# 终端1: 启动HTTPS服务器
python implementation/enhanced_v2/https_server.py --port 8443

# 终端2: 启动代理服务器
python implementation/enhanced_v2/https_proxy.py --proxy-port 8080

# 浏览器: 设置代理 127.0.0.1:8080，访问 https://127.0.0.1:8443
```

### 场景2: 抓包分析

```bash
# 启动服务器
python implementation/enhanced_v2/https_server.py --port 8443 --mode hybrid --algorithm mldsa65

# 启动Wireshark，过滤 tcp.port == 8443

# 使用客户端连接
python implementation/enhanced_v2/enhanced_client.py --host 127.0.0.1 --port 8443

# 观察Wireshark中的加密数据包
```

## 安全特性

- ✅ **后量子密码学**: 使用ML-DSA、Falcon等后量子签名算法
- ✅ **混合密钥交换**: P-256 + Kyber768等混合方案
- ✅ **端到端加密**: AES-128-GCM加密
- ✅ **抗降级攻击**: TLS 1.3标准保护
- ✅ **证书验证**: 完整的证书链验证

## 注意事项

1. **浏览器兼容性**: 标准浏览器不支持自定义TLS协议，需要使用代理或自定义客户端
2. **证书信任**: 浏览器会显示证书警告，这是正常的（使用自定义证书）
3. **性能**: 后量子算法的签名和密钥较大，会增加数据包大小
4. **抓包**: 使用Wireshark可以看到加密的数据包，但无法解密（除非有密钥）

## 故障排除

### 问题1: 浏览器无法连接

**解决方案**:
- 确保使用代理服务器
- 检查代理配置是否正确
- 尝试使用自定义客户端直接连接

### 问题2: 抓包看不到数据

**解决方案**:
- 确保选择正确的网络接口
- 检查过滤规则是否正确
- 确认服务器正在运行

### 问题3: TLS握手失败

**解决方案**:
- 检查证书文件是否存在
- 确认端口未被占用
- 查看服务器日志了解详细错误

## 相关文件

- `https_server.py`: HTTPS服务器（使用自定义TLS）
- `https_proxy.py`: HTTPS代理服务器
- `enhanced_server.py`: TLS服务器实现
- `enhanced_client.py`: TLS客户端实现

