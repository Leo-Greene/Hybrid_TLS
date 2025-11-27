import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import json
import os
from matplotlib.ticker import FuncFormatter

# 设置中文字体支持
plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False

# 安全等级映射
SECURITY_LEVELS = {
    # KEM算法
    'Kyber512': 'Level 1',
    'Kyber768': 'Level 3',
    'Kyber1024': 'Level 5',
    'P-256+Kyber512': 'Level 1',
    'P-256+Kyber768': 'Level 3',
    'P-384+Kyber768': 'Level 4',
    'P-521+Kyber1024': 'Level 5',
    'X25519': 'Level 2',
    'P-256': 'Level 2',
    
    # 签名算法
    'ML-DSA-44': 'Level 2',
    'ML-DSA-65': 'Level 3',
    'ML-DSA-87': 'Level 5',
    'Dilithium2': 'Level 2',
    'Dilithium3': 'Level 3',
    'Dilithium5': 'Level 5',
    'Falcon512': 'Level 1',
    'Falcon-512': 'Level 1',
    'Falcon1024': 'Level 5',
    'Falcon-1024': 'Level 5',
    'ECDSA-P256': 'Level 2',
    'P256+Dilithium3': 'Level 3',
}

def get_security_level(name):
    """获取算法的安全等级"""
    for key, level in SECURITY_LEVELS.items():
        if key in name:
            return level
    return 'Unknown'

def load_benchmark_data(json_file):
    """加载基准测试JSON数据"""
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data

def create_kem_comparison_plot(data, output_dir):
    """创建KEM算法性能比较图"""
    kem_data = data['key_exchange']
    
    # 准备数据
    names = [item['name'].replace('KEX-', '') for item in kem_data]
    throughputs = [item['throughput'] for item in kem_data]
    operations = [item['operations_in_10s'] for item in kem_data]
    avg_times = [item['avg_time'] * 1000 for item in kem_data]  # 转换为毫秒
    
    # 获取安全等级
    security_levels = [get_security_level(name) for name in names]
    
    # 为x轴标签添加安全等级信息（使用更紧凑的格式，避免重叠）
    labels_with_level = [f"{name}\n[{level.replace('Level ', 'L')}]" for name, level in zip(names, security_levels)]
    
    # 创建子图 - 增加宽度以避免标签重叠
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(22, 12))
    
    # 根据安全等级设置颜色
    level_colors = {
        'Level 1': '#90EE90',  # 浅绿
        'Level 2': '#87CEEB',  # 天蓝
        'Level 3': '#FFD700',  # 金色
        'Level 4': '#FFA500',  # 橙色
        'Level 5': '#FF6347',  # 番茄红
    }
    colors = [level_colors.get(level, '#808080') for level in security_levels]
    
    # 1. 吞吐量比较
    bars1 = ax1.bar(range(len(names)), throughputs, color=colors, alpha=0.8)
    ax1.set_title('KEM算法吞吐量比较（按安全等级）', fontsize=16, fontweight='bold', pad=20)
    ax1.set_ylabel('吞吐量 (ops/s)', fontsize=14)
    ax1.set_xticks(range(len(names)))
    ax1.set_xticklabels(labels_with_level, rotation=0, fontsize=9, ha='center')
    ax1.grid(True, axis='y', linestyle='--', alpha=0.7)
    ax1.margins(x=0.05)  # 增加左右边距，避免标签被裁剪
    
    # 在柱状图上添加数值标签
    for bar in bars1:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height + 100,
                f'{height:.0f}', ha='center', va='bottom', fontsize=10)
    
    # 2. 10秒操作次数比较
    bars2 = ax2.bar(range(len(names)), operations, color=colors, alpha=0.8)
    ax2.set_title('KEM算法10秒操作次数（按安全等级）', fontsize=16, fontweight='bold', pad=20)
    ax2.set_ylabel('操作次数', fontsize=14)
    ax2.set_xticks(range(len(names)))
    ax2.set_xticklabels(labels_with_level, rotation=0, fontsize=9, ha='center')
    ax2.grid(True, axis='y', linestyle='--', alpha=0.7)
    ax2.margins(x=0.05)
    
    # 格式化y轴为千分位
    ax2.yaxis.set_major_formatter(FuncFormatter(lambda x, p: f'{x/1000:.0f}K'))
    
    for bar in bars2:
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height + 1000,
                f'{height/1000:.0f}K', ha='center', va='bottom', fontsize=10)
    
    # 3. 平均时间比较
    bars3 = ax3.bar(range(len(names)), avg_times, color=colors, alpha=0.8)
    ax3.set_title('KEM算法平均时间（按安全等级）', fontsize=16, fontweight='bold', pad=20)
    ax3.set_ylabel('平均时间 (ms)', fontsize=14)
    ax3.set_xticks(range(len(names)))
    ax3.set_xticklabels(labels_with_level, rotation=0, fontsize=9, ha='center')
    ax3.grid(True, axis='y', linestyle='--', alpha=0.7)
    ax3.margins(x=0.05)
    
    for bar in bars3:
        height = bar.get_height()
        ax3.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                f'{height:.2f}ms', ha='center', va='bottom', fontsize=10)
    
    # 4. 密钥大小比较
    client_sizes = [item['sizes']['client_public'] for item in kem_data]
    server_sizes = [item['sizes']['server_public'] for item in kem_data]
    
    x = np.arange(len(names))
    width = 0.35
    
    bars4a = ax4.bar(x - width/2, client_sizes, width, label='客户端公钥', color='#1f77b4', alpha=0.8)
    bars4b = ax4.bar(x + width/2, server_sizes, width, label='服务器公钥', color='#ff7f0e', alpha=0.8)
    
    ax4.set_title('KEM算法密钥大小比较（按安全等级）', fontsize=16, fontweight='bold', pad=20)
    ax4.set_ylabel('大小 (字节)', fontsize=14)
    ax4.set_xticks(x)
    ax4.set_xticklabels(labels_with_level, rotation=0, fontsize=9, ha='center')
    ax4.legend()
    ax4.grid(True, axis='y', linestyle='--', alpha=0.7)
    ax4.margins(x=0.05)
    
    # 添加数值标签
    for bar in bars4a:
        height = bar.get_height()
        ax4.text(bar.get_x() + bar.get_width()/2., height + 50,
                f'{height}', ha='center', va='bottom', fontsize=9)
    
    for bar in bars4b:
        height = bar.get_height()
        ax4.text(bar.get_x() + bar.get_width()/2., height + 50,
                f'{height}', ha='center', va='bottom', fontsize=9)
    
    # 调整子图间距，避免标签重叠
    plt.tight_layout(pad=2.0, h_pad=3.0, w_pad=2.0)
    plt.savefig(os.path.join(output_dir, 'kem_comparison.pdf'), dpi=300, bbox_inches='tight', pad_inches=0.3)
    plt.close()
    
    print("KEM算法比较图已保存为: kem_comparison.pdf")

def create_signature_comparison_plot(data, output_dir):
    """创建签名算法性能比较图"""
    sig_data = data['signature']
    
    # 准备数据
    names = [item['name'].replace('SIG-', '') for item in sig_data]
    throughputs = [item['throughput'] for item in sig_data]
    operations = [item['operations_in_10s'] for item in sig_data]
    avg_times = [item['avg_time'] * 1000 for item in sig_data]  # 转换为毫秒
    
    # 获取安全等级
    security_levels = [get_security_level(name) for name in names]
    
    # 为x轴标签添加安全等级信息（使用更紧凑的格式，避免重叠）
    labels_with_level = [f"{name}\n[{level.replace('Level ', 'L')}]" for name, level in zip(names, security_levels)]
    
    # 创建子图 - 增加宽度以避免标签重叠
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(22, 12))
    
    # 根据安全等级设置颜色
    level_colors = {
        'Level 1': '#90EE90',  # 浅绿
        'Level 2': '#87CEEB',  # 天蓝
        'Level 3': '#FFD700',  # 金色
        'Level 4': '#FFA500',  # 橙色
        'Level 5': '#FF6347',  # 番茄红
    }
    colors = [level_colors.get(level, '#808080') for level in security_levels]
    
    # 1. 吞吐量比较
    bars1 = ax1.bar(range(len(names)), throughputs, color=colors, alpha=0.8)
    ax1.set_title('签名算法吞吐量比较（按安全等级）', fontsize=16, fontweight='bold', pad=20)
    ax1.set_ylabel('吞吐量 (ops/s)', fontsize=14)
    ax1.set_xticks(range(len(names)))
    ax1.set_xticklabels(labels_with_level, rotation=0, fontsize=9, ha='center')
    ax1.grid(True, axis='y', linestyle='--', alpha=0.7)
    ax1.margins(x=0.05)
    
    for bar in bars1:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height + 50,
                f'{height:.0f}', ha='center', va='bottom', fontsize=10)
    
    # 2. 10秒操作次数比较
    bars2 = ax2.bar(range(len(names)), operations, color=colors, alpha=0.8)
    ax2.set_title('签名算法10秒操作次数（按安全等级）', fontsize=16, fontweight='bold', pad=20)
    ax2.set_ylabel('操作次数', fontsize=14)
    ax2.set_xticks(range(len(names)))
    ax2.set_xticklabels(labels_with_level, rotation=0, fontsize=9, ha='center')
    ax2.grid(True, axis='y', linestyle='--', alpha=0.7)
    ax2.margins(x=0.05)
    
    ax2.yaxis.set_major_formatter(FuncFormatter(lambda x, p: f'{x/1000:.0f}K'))
    
    for bar in bars2:
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height + 500,
                f'{height/1000:.0f}K', ha='center', va='bottom', fontsize=10)
    
    # 3. 平均时间比较
    bars3 = ax3.bar(range(len(names)), avg_times, color=colors, alpha=0.8)
    ax3.set_title('签名算法平均时间（按安全等级）', fontsize=16, fontweight='bold', pad=20)
    ax3.set_ylabel('平均时间 (ms)', fontsize=14)
    ax3.set_xticks(range(len(names)))
    ax3.set_xticklabels(labels_with_level, rotation=0, fontsize=9, ha='center')
    ax3.grid(True, axis='y', linestyle='--', alpha=0.7)
    ax3.margins(x=0.05)
    
    for bar in bars3:
        height = bar.get_height()
        ax3.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                f'{height:.2f}ms', ha='center', va='bottom', fontsize=10)
    
    # 4. 密钥和签名大小比较
    pubkey_sizes = [item['sizes']['public_key'] for item in sig_data]
    sig_sizes = [item['sizes']['signature'] for item in sig_data]
    
    x = np.arange(len(names))
    width = 0.35
    
    bars4a = ax4.bar(x - width/2, pubkey_sizes, width, label='公钥大小', color='#1f77b4', alpha=0.8)
    bars4b = ax4.bar(x + width/2, sig_sizes, width, label='签名大小', color='#ff7f0e', alpha=0.8)
    
    ax4.set_title('签名算法大小比较（按安全等级）', fontsize=16, fontweight='bold', pad=20)
    ax4.set_ylabel('大小 (字节)', fontsize=14)
    ax4.set_xticks(x)
    ax4.set_xticklabels(labels_with_level, rotation=0, fontsize=9, ha='center')
    ax4.legend()
    ax4.grid(True, axis='y', linestyle='--', alpha=0.7)
    ax4.margins(x=0.05)
    
    for bar in bars4a:
        height = bar.get_height()
        ax4.text(bar.get_x() + bar.get_width()/2., height + 100,
                f'{height}', ha='center', va='bottom', fontsize=9)
    
    for bar in bars4b:
        height = bar.get_height()
        ax4.text(bar.get_x() + bar.get_width()/2., height + 100,
                f'{height}', ha='center', va='bottom', fontsize=9)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'signature_comparison.pdf'), dpi=300, bbox_inches='tight')
    plt.close()
    
    print("签名算法比较图已保存为: signature_comparison.pdf")

def create_handshake_comparison_plot(data, output_dir):
    """创建TLS握手性能比较图"""
    handshake_data = data['handshake_10s']
    
    # 准备数据
    names = [item['name'].replace('Handshake-10s-', '') for item in handshake_data]
    throughputs = [item['throughput'] for item in handshake_data]
    operations = [item['operations_in_10s'] for item in handshake_data]
    avg_times = [item['avg_time'] * 1000 for item in handshake_data]  # 转换为毫秒
    
    # 创建子图
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
    
    # 设置颜色
    colors = ['#1f77b4', '#ff7f0e', '#2ca02c']
    
    # 1. 吞吐量比较
    bars1 = ax1.bar(names, throughputs, color=colors, alpha=0.8)
    ax1.set_title('TLS握手吞吐量比较', fontsize=16, fontweight='bold', pad=20)
    ax1.set_ylabel('吞吐量 (ops/s)', fontsize=14)
    ax1.tick_params(axis='x', rotation=45)
    ax1.grid(True, axis='y', linestyle='--', alpha=0.7)
    
    for bar in bars1:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height + 50,
                f'{height:.1f}', ha='center', va='bottom', fontsize=10)
    
    # 2. 10秒握手次数比较
    bars2 = ax2.bar(names, operations, color=colors, alpha=0.8)
    ax2.set_title('TLS握手10秒操作次数', fontsize=16, fontweight='bold', pad=20)
    ax2.set_ylabel('握手次数', fontsize=14)
    ax2.tick_params(axis='x', rotation=45)
    ax2.grid(True, axis='y', linestyle='--', alpha=0.7)
    
    ax2.yaxis.set_major_formatter(FuncFormatter(lambda x, p: f'{x/1000:.0f}K'))
    
    for bar in bars2:
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height + 500,
                f'{height/1000:.0f}K', ha='center', va='bottom', fontsize=10)
    
    # 3. 平均时间比较
    bars3 = ax3.bar(names, avg_times, color=colors, alpha=0.8)
    ax3.set_title('TLS握手平均时间', fontsize=16, fontweight='bold', pad=20)
    ax3.set_ylabel('平均时间 (ms)', fontsize=14)
    ax3.tick_params(axis='x', rotation=45)
    ax3.grid(True, axis='y', linestyle='--', alpha=0.7)
    
    for bar in bars3:
        height = bar.get_height()
        ax3.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                f'{height:.2f}ms', ha='center', va='bottom', fontsize=10)
    
    # 4. 消息大小比较
    client_hello_sizes = [item['sizes']['client_hello'] for item in handshake_data]
    server_hello_sizes = [item['sizes']['server_hello'] for item in handshake_data]
    total_sizes = [item['sizes']['total'] for item in handshake_data]
    
    x = np.arange(len(names))
    width = 0.25
    
    bars4a = ax4.bar(x - width, client_hello_sizes, width, label='Client Hello', color='#1f77b4', alpha=0.8)
    bars4b = ax4.bar(x, server_hello_sizes, width, label='Server Hello', color='#ff7f0e', alpha=0.8)
    bars4c = ax4.bar(x + width, total_sizes, width, label='总大小', color='#2ca02c', alpha=0.8)
    
    ax4.set_title('TLS握手消息大小比较', fontsize=16, fontweight='bold', pad=20)
    ax4.set_ylabel('大小 (字节)', fontsize=14)
    ax4.set_xticks(x)
    ax4.set_xticklabels(names, rotation=45)
    ax4.legend()
    ax4.grid(True, axis='y', linestyle='--', alpha=0.7)
    
    # 添加数值标签
    for bar in bars4a:
        height = bar.get_height()
        ax4.text(bar.get_x() + bar.get_width()/2., height + 200,
                f'{height}', ha='center', va='bottom', fontsize=8)
    
    for bar in bars4b:
        height = bar.get_height()
        ax4.text(bar.get_x() + bar.get_width()/2., height + 200,
                f'{height}', ha='center', va='bottom', fontsize=8)
    
    for bar in bars4c:
        height = bar.get_height()
        ax4.text(bar.get_x() + bar.get_width()/2., height + 200,
                f'{height}', ha='center', va='bottom', fontsize=8)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'handshake_comparison.pdf'), dpi=300, bbox_inches='tight')
    plt.close()
    
    print("TLS握手比较图已保存为: handshake_comparison.pdf")

def create_comprehensive_comparison(data, output_dir):
    """创建综合性能比较图（类似plotBox.py的风格）"""
    
    # 提取所有算法的吞吐量数据
    all_throughputs = []
    all_names = []
    
    # KEM算法
    for item in data['key_exchange']:
        all_throughputs.append(item['throughput'])
        all_names.append(item['name'].replace('KEX-', ''))
    
    # 签名算法
    for item in data['signature']:
        all_throughputs.append(item['throughput'])
        all_names.append(item['name'].replace('SIG-', ''))
    
    # TLS握手
    for item in data['handshake_10s']:
        all_throughputs.append(item['throughput'])
        all_names.append(item['name'].replace('Handshake-10s-', ''))
    
    # 创建图表
    fig, ax = plt.subplots(figsize=(14, 8))
    
    # 设置颜色（根据算法类型）
    colors = []
    for name in all_names:
        # 先判断是否是混合算法（包含'+'符号）
        if '+' in name or 'hybrid' in name:
            colors.append('#2ca02c')  # 混合算法 - 绿色
        # 再判断是否是传统算法
        elif 'X25519' in name or ('P-256' in name and '+' not in name) or 'ECDSA' in name or 'classic' in name:
            colors.append('#1f77b4')  # 传统算法 - 蓝色
        # 其余都是PQC算法（包括 Kyber, NTRU, Dilithium, ML-DSA, Falcon）
        else:
            colors.append('#ff7f0e')  # PQC算法 - 橙色
    
    # 创建柱状图
    bars = ax.bar(range(len(all_names)), all_throughputs, color=colors, alpha=0.8, width=0.6)
    
    # 设置图表属性
    ax.set_title('TLS算法性能综合比较', fontsize=20, fontweight='bold', pad=20)
    ax.set_ylabel('吞吐量 (ops/s)', fontsize=16, fontweight='bold')
    ax.set_xlabel('算法类型', fontsize=16, fontweight='bold')
    
    # 设置x轴标签
    ax.set_xticks(range(len(all_names)))
    ax.set_xticklabels(all_names, rotation=45, ha='right', fontsize=12)
    
    # 添加网格
    ax.grid(True, axis='y', linestyle='--', alpha=0.7)
    
    # 在柱状图上添加数值标签
    for i, bar in enumerate(bars):
        height = bar.get_height()
        if height > 1000:
            label = f'{height/1000:.1f}K'
        else:
            label = f'{height:.0f}'
        # 使用动态偏移量，根据最大值的1%来设置距离
        offset = max(all_throughputs) * 0.01
        ax.text(bar.get_x() + bar.get_width()/2., height + offset,
                label, ha='center', va='bottom', fontsize=10)
    
    # 添加图例
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='#1f77b4', alpha=0.8, label='传统算法'),
        Patch(facecolor='#ff7f0e', alpha=0.8, label='PQC算法'),
        Patch(facecolor='#2ca02c', alpha=0.8, label='混合算法')
    ]
    ax.legend(handles=legend_elements, loc='upper right')
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'comprehensive_comparison.pdf'), dpi=300, bbox_inches='tight')
    plt.close()
    
    print("综合性能比较图已保存为: comprehensive_comparison.pdf")

def main():
    # 设置输出目录
    output_dir = os.path.join(os.path.dirname(__file__), 'results', 'paper_plots')
    os.makedirs(output_dir, exist_ok=True)
    
    # 查找最新的JSON结果文件
    results_dir = os.path.join(os.path.dirname(__file__), 'results', 'benchmarks')
    json_files = [f for f in os.listdir(results_dir) if f.endswith('.json')]
    
    if not json_files:
        print("未找到JSON结果文件")
        return
    
    # 使用最新的JSON文件
    latest_json = max(json_files, key=lambda x: os.path.getmtime(os.path.join(results_dir, x)))
    json_file_path = os.path.join(results_dir, latest_json)
    
    print(f"使用结果文件: {latest_json}")
    
    # 加载数据
    data = load_benchmark_data(json_file_path)
    
    # 创建各种比较图
    create_kem_comparison_plot(data, output_dir)
    create_signature_comparison_plot(data, output_dir)
    create_handshake_comparison_plot(data, output_dir)
    create_comprehensive_comparison(data, output_dir)
    
    print(f"所有图表已保存到: {output_dir}")
    print("图表格式适合论文使用，包含：")
    print("- KEM算法性能比较")
    print("- 签名算法性能比较") 
    print("- TLS握手性能比较")
    print("- 综合性能比较")

if __name__ == "__main__":
    main()