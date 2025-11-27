# TLS混合握手前端演示

## 功能概述

本前端界面用于演示TLS混合握手，支持以下功能：

1. **完整的客户端-服务器通信演示**
   - 客户端成功协商混合握手
   - 服务器提供由PQC签名的证书
   - 客户端对证书进行验证

2. **基准测试比较**
   - 经典TLS
   - 纯PQC-TLS
   - 混合TLS

3. **by_val vs by_ref模式对比**
   - 重点体现by_ref模式服务器端的优化效果
   - 展示证书大小减少带来的性能提升
   - 考虑HTTP请求带来的客户端开销

4. **模式切换**
   - 支持by_val和by_ref模式切换
   - 一键对比功能

## 快速开始

### 1. 安装依赖

```bash
pip install fastapi uvicorn
```

### 2. 生成证书大小数据

```bash
python frontend/get_cert_sizes.py
```

### 3. 生成by_ref测试数据（可选）

```bash
python frontend/generate_byref_data.py
```

### 4. 启动API服务器

```bash
cd frontend
python api_server.py
```

### 5. 访问前端界面

打开浏览器访问：`http://localhost:8000`

## 使用说明

### 执行握手

1. 选择TLS模式（经典/纯PQC/混合）
2. 选择证书模式（by_val/by_ref）
3. 选择签名算法
4. 点击"执行握手"按钮

### 一键对比

点击"一键对比"按钮，系统会自动：
1. 执行by_val模式的握手
2. 执行by_ref模式的握手
3. 显示对比结果和服务器端优化效果

### 查看基准测试

1. 点击"一键对比"加载基准测试数据
2. 使用标签页切换不同模式（经典/纯PQC/混合）
3. 查看by_val和by_ref模式的对比数据

## 实现说明

### 真实实现

- **握手执行**: 使用真实的客户端-服务器实现（`enhanced_v2`和`enhanced_v2_by_val`）
- **证书大小**: 从实际证书文件读取
- **握手延迟**: 真实测量的延迟（10-60ms）

### 估算部分

部分数据使用估算值，详见 `IMPLEMENTATION_NOTES.md`：
- ClientHello/ServerHello消息大小（估算）
- HTTP请求延迟（本地回环，估算）
- 传输时间节省（基于网络条件估算）

## 文件结构

```
frontend/
├── api_server.py              # API服务器（FastAPI）
├── index.html                 # 前端HTML界面
├── style.css                  # 样式文件
├── script.js                  # 前端JavaScript逻辑
├── get_cert_sizes.py          # 证书大小读取脚本
├── generate_byref_data.py     # by_ref数据生成脚本
├── cert_sizes.json            # 证书大小数据（自动生成）
├── IMPLEMENTATION_NOTES.md    # 实现说明文档
└── README.md                  # 本文档
```

## API接口

### POST /api/handshake/execute

执行真实TLS握手

**参数**:
- `mode`: TLS模式 (classic/pqc/hybrid)
- `cert_mode`: 证书模式 (by_val/by_ref)
- `algorithm`: 签名算法 (mldsa44/mldsa65/mldsa87/falcon512/falcon1024)

**返回**: 握手结果数据

### GET /api/compare-modes

对比by_val和by_ref模式

**参数**:
- `mode`: TLS模式
- `algorithm`: 签名算法

**返回**: 对比数据

### GET /api/benchmark/compare

获取基准测试对比数据

**返回**: by_val和by_ref的基准测试数据

### GET /api/cert-sizes

获取证书大小数据

**返回**: 所有算法的证书大小信息

## 注意事项

1. **本地证书服务器**: by_ref模式需要本地证书服务器运行在80端口。API服务器会自动启动该服务。

2. **端口冲突**: 如果80端口被占用，需要手动启动证书服务器：
   ```bash
   python implementation/enhanced_v2/local_cert_server.py
   ```

3. **证书文件**: 确保证书文件已生成：
   - by_val模式: `enhanced_certificates/` 目录
   - by_ref模式: `implementation/enhanced_v2/pq_certificates/` 目录

4. **性能**: 真实握手执行可能需要几秒到几十秒，请耐心等待。

## 技术栈

- **后端**: FastAPI + Python
- **前端**: 原生HTML/CSS/JavaScript
- **TLS实现**: enhanced_v2 / enhanced_v2_by_val

## 许可证

本项目遵循项目主许可证。

