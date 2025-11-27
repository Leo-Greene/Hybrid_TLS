#!/usr/bin/env python3
"""
批量基准测试和可视化脚本
支持运行多组测试条件并自动生成图表
"""

import os
import sys
import json
import subprocess
import time
import threading
from pathlib import Path
from datetime import datetime
import argparse

# 测试配置方案
TEST_SCENARIOS = {
    "quick": {
        "description": "快速测试（1次迭代，功能验证）",
        "iterations": 1,
        "network_profiles": ["localhost"],
        "distance_profiles": ["local"],
        "tests": ["all"],
        "estimated_time": "~5秒（超级并行）⚡"
    },
    "standard": {
        "description": "标准测试（10次迭代，日常评估）",
        "iterations": 10,
        "network_profiles": ["localhost", "lan"],
        "distance_profiles": ["local"],
        "tests": ["all"],
        "estimated_time": "~15秒（超级并行）⚡"
    },
    "moderate": {
        "description": "中等测试（20次迭代，论文初稿）",
        "iterations": 20,
        "network_profiles": ["localhost", "lan"],
        "distance_profiles": ["local", "city"],
        "tests": ["all"],
        "estimated_time": "~30秒（超级并行）⚡"
    },
    "comprehensive": {
        "description": "全面测试（100次迭代，多网络，论文终稿）",
        "iterations": 100,
        "network_profiles": ["localhost", "lan", "fast_wan"],
        "distance_profiles": ["local", "city", "country"],
        "tests": ["all"],
        "estimated_time": "~140秒（超级并行）⚡"
    },
    "network_only": {
        "description": "仅网络感知测试",
        "iterations": 100,
        "network_profiles": ["localhost", "lan", "fast_wan", "slow_wan"],
        "distance_profiles": ["local", "city", "province", "country"],
        "tests": ["network"],
        "estimated_time": "5-10分钟（网络延迟模拟）"
    },
    "kex_only": {
        "description": "仅密钥交换测试（6算法×100次）",
        "iterations": 100,
        "network_profiles": [],
        "distance_profiles": [],
        "tests": ["kex"],
        "estimated_time": "~3秒（超级并行）⚡"
    },
    "sig_only": {
        "description": "仅签名测试（5算法×100次）",
        "iterations": 100,
        "network_profiles": [],
        "distance_profiles": [],
        "tests": ["sig"],
        "estimated_time": "~27秒（超级并行，含Falcon）⚡"
    }
}


def run_benchmark(scenario_name: str, scenario_config: dict, output_base_dir: Path, benchmarks_dir: Path) -> dict:
    """
    运行单个测试场景
    
    Args:
        scenario_name: 场景名称
        scenario_config: 场景配置
        output_base_dir: 输出基础目录
        benchmarks_dir: benchmarks脚本所在目录
        
    Returns:
        测试结果信息字典
    """
    print("\n" + "=" * 80)
    print(f"🚀 开始测试场景: {scenario_name}")
    print(f"   描述: {scenario_config['description']}")
    print(f"   迭代次数: {scenario_config['iterations']}")
    print(f"   ⏱️  预计时间: {scenario_config.get('estimated_time', '未知')}")
    print("=" * 80)
    
    # 创建场景专用目录
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scenario_dir = output_base_dir / f"{scenario_name}_{timestamp}"
    scenario_dir.mkdir(parents=True, exist_ok=True)
    
    # 构建命令参数 - 使用超级并行版本极致加速
    run_benchmarks_script = benchmarks_dir / "run_benchmarks_ultra_parallel.py"
    cmd = [
        sys.executable,
        str(run_benchmarks_script),
        "--iterations", str(scenario_config['iterations'])
    ]
    
    print(f"⚡ 使用超级并行脚本加速（预计提速 30-600倍）")
    
    # 添加测试类型
    if scenario_config['tests']:
        cmd.extend(["--test", scenario_config['tests'][0]])
    
    # 添加网络配置（如果适用）
    if scenario_config['network_profiles']:
        cmd.append("--network-profiles")
        cmd.extend(scenario_config['network_profiles'])
    
    if scenario_config['distance_profiles']:
        cmd.append("--distance-profiles")
        cmd.extend(scenario_config['distance_profiles'])
    
    # 运行测试（带任务进度提示）
    print(f"\n执行命令: {' '.join(cmd)}")
    print(f"输出目录: {scenario_dir}")
    print(f"\n⏳ 测试正在运行，请稍候...")
    print(f"   (将每20秒显示任务进度)\n")
    
    start_time = time.time()
    
    # 使用Popen以便可以监控进度和捕获输出
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding='utf-8',
        errors='replace',
        bufsize=1,  # 行缓冲
        universal_newlines=True
    )
    
    # 定期检查进程状态并分析进度
    reminder_interval = 20  # 每20秒提醒一次
    last_reminder = time.time()
    
    # 估算总任务数（根据测试类型）
    total_tasks = 0
    if scenario_config['tests'][0] == 'all':
        total_tasks = 18  # 10 KEM (5 Kyber+NTRU + 5 混合) + 5 签名 + 3 握手
    elif scenario_config['tests'][0] == 'kex':
        total_tasks = 10  # 5 纯PQC + 5 混合
    elif scenario_config['tests'][0] == 'sig':
        total_tasks = 5
    elif scenario_config['tests'][0] == 'handshake':
        total_tasks = 3
    elif scenario_config['tests'][0] == 'network':
        # 网络测试: 3个模式 × 网络配置数 × 距离配置数
        total_tasks = 3 * len(scenario_config.get('network_profiles', [1])) * len(scenario_config.get('distance_profiles', [1]))
    
    # 用于累积输出并统计进度
    accumulated_output = ""
    
    # 使用非阻塞方式读取输出
    import threading
    output_lines = []
    
    def read_output(pipe, output_list):
        """后台线程读取输出"""
        try:
            for line in iter(pipe.readline, ''):
                if line:
                    output_list.append(line)
        except:
            pass
    
    # 启动输出读取线程
    stdout_thread = threading.Thread(target=read_output, args=(process.stdout, output_lines), daemon=True)
    stdout_thread.start()
    
    while process.poll() is None:
        time.sleep(1)  # 每秒检查一次
        current_time = time.time()
        if current_time - last_reminder >= reminder_interval:
            elapsed = int(current_time - start_time)
            
            # 统计当前累积的输出中完成的任务数
            accumulated_output = ''.join(output_lines)
            completed_count = accumulated_output.count('[OK]')
            
            if total_tasks > 0:
                progress_pct = min(100, int(completed_count / total_tasks * 100))
                remaining_tasks = max(0, total_tasks - completed_count)
                print(f"   📊 进度: {completed_count}/{total_tasks} 任务完成 ({progress_pct}%) | 剩余 {remaining_tasks} 个 | {elapsed}秒")
            else:
                print(f"   ⏱️  测试运行中... | 已运行 {elapsed}秒")
            
            last_reminder = current_time
    
    # 等待输出读取完成
    stdout_thread.join(timeout=5)
    
    # 获取累积的输出
    stdout = ''.join(output_lines)
    
    # 获取stderr
    stderr_data, _ = process.communicate()
    elapsed_time = time.time() - start_time
    
    # 创建一个类似subprocess.run返回的对象
    class Result:
        def __init__(self, returncode, stdout, stderr):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr
    
    result = Result(process.returncode, stdout, stderr_data if stderr_data else '')
    
    # 保存控制台输出
    output_file = scenario_dir / "console_output.txt"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"测试场景: {scenario_name}\n")
        f.write(f"描述: {scenario_config['description']}\n")
        f.write(f"开始时间: {timestamp}\n")
        f.write(f"执行时间: {elapsed_time:.2f} 秒\n")
        f.write("=" * 80 + "\n\n")
        f.write("标准输出:\n")
        f.write(result.stdout if result.stdout else "（无输出）")
        if result.stderr:
            f.write("\n" + "=" * 80 + "\n")
            f.write("标准错误:\n")
            f.write(result.stderr)
    
    # 移动生成的结果文件到场景目录
    results_dir = benchmarks_dir / "results" / "benchmarks"
    if results_dir.exists():
        # 查找最新生成的结果文件（所有类型）
        result_files = []
        patterns = [
            "*benchmark_*.json", "*benchmark_*.txt",
        ]
        for pattern in patterns:
            result_files.extend(list(results_dir.glob(pattern)))
        
        # 按修改时间排序，获取最新的
        if result_files:
            latest_files = sorted(result_files, key=lambda x: x.stat().st_mtime, reverse=True)
            
            # 移动最近生成的文件（在测试开始后创建的，增加1秒缓冲）
            moved_count = 0
            for f in latest_files:
                # 检查文件是否在测试期间创建
                if f.stat().st_mtime >= (start_time - 1):  # 1秒缓冲
                    try:
                        dest = scenario_dir / f.name
                        f.rename(dest)
                        print(f"  ✓ 结果文件已移动: {dest.name}")
                        moved_count += 1
                        # 只移动最新的2个文件（.json和.txt）
                        if moved_count >= 10:  # 最多移动10个文件（防止误移动）
                            break
                    except Exception as e:
                        print(f"  ⚠️  移动文件失败 {f.name}: {e}")
            
            if moved_count == 0:
                print(f"  ⚠️  未找到需要移动的结果文件")
    
    # 保存测试配置
    config_file = scenario_dir / "test_config.json"
    test_info = {
        "scenario_name": scenario_name,
        "description": scenario_config['description'],
        "timestamp": timestamp,
        "elapsed_time_seconds": elapsed_time,
        "configuration": scenario_config,
        "exit_code": result.returncode
    }
    
    with open(config_file, 'w', encoding='utf-8') as f:
        json.dump(test_info, f, indent=2, ensure_ascii=False)
    
    print(f"\n[OK] 场景 '{scenario_name}' 测试完成")
    print(f"   用时: {elapsed_time:.2f} 秒")
    print(f"   结果目录: {scenario_dir}")
    
    return test_info


def visualize_scenario_results(scenario_dir: Path) -> None:
    """
    为单个测试场景生成可视化图表
    
    Args:
        scenario_dir: 场景结果目录
    """
    print(f"\n📊 为 {scenario_dir.name} 生成可视化图表...")
    
    # 查找JSON结果文件（所有类型）
    json_files = list(scenario_dir.glob("*benchmark*.json"))
    if not json_files:
        print(f"  ⚠️  未找到JSON结果文件，跳过")
        print(f"     搜索路径: {scenario_dir}")
        print(f"     目录内容: {list(scenario_dir.glob('*'))}")
        return
    
    latest_json = max(json_files, key=lambda x: x.stat().st_mtime)
    
    # 加载测试配置
    config_file = scenario_dir / "test_config.json"
    test_config = {}
    if config_file.exists():
        with open(config_file, 'r', encoding='utf-8') as f:
            test_config = json.load(f)
    
    # 创建plots子目录
    plots_dir = scenario_dir / "plots"
    plots_dir.mkdir(exist_ok=True)
    
    # 调用可视化脚本（修改版，添加测试条件信息）
    create_enhanced_visualizations(latest_json, plots_dir, test_config)
    
    print(f"  [OK] 图表已保存到: {plots_dir}")


def create_enhanced_visualizations(json_file: Path, output_dir: Path, test_config: dict):
    """
    创建增强的可视化图表（包含测试条件信息）
    
    Args:
        json_file: JSON数据文件路径
        output_dir: 输出目录
        test_config: 测试配置信息
    """
    import matplotlib.pyplot as plt
    import numpy as np
    from matplotlib.ticker import FuncFormatter
    from matplotlib.patches import Patch
    
    # 设置中文字体
    plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'DejaVu Sans']
    plt.rcParams['axes.unicode_minus'] = False
    
    # 加载数据
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # 构建测试条件文本（单行，紧凑）
    config = test_config.get('configuration', {})
    
    # 检查是否包含网络延迟模拟
    has_network = 'network' in config.get('tests', [])
    network_note = "（包含网络延迟模拟）" if has_network else "（纯计算性能，无网络延迟）"
    
    condition_text = (
        f"测试场景: {test_config.get('scenario_name', 'unknown')}  |  "
        f"迭代次数: {config.get('iterations', 'N/A')}  |  "
        f"时间: {test_config.get('timestamp', 'N/A')[:13]}  |  "
        f"{network_note}"
    )
    
    # 1. KEM算法比较
    if 'key_exchange' in data and data['key_exchange']:
        create_kem_plot(data['key_exchange'], output_dir, condition_text)
    
    # 2. 签名算法比较
    if 'signature' in data and data['signature']:
        create_signature_plot(data['signature'], output_dir, condition_text)
    
    # 3. 握手性能比较
    if 'handshake_10s' in data and data['handshake_10s']:
        create_handshake_plot(data['handshake_10s'], output_dir, condition_text)
    
    # 4. 综合比较
    if all(k in data for k in ['key_exchange', 'signature', 'handshake_10s']):
        create_comprehensive_plot(data, output_dir, condition_text)
    
    # 5. 网络感知握手比较（如果有）
    if 'network_handshake' in data and data['network_handshake']:
        create_network_handshake_plot(data['network_handshake'], output_dir, test_config)


def create_kem_plot(kem_data, output_dir, condition_text):
    """创建KEM算法比较图（按安全等级分组）"""
    import matplotlib.pyplot as plt
    import numpy as np
    from matplotlib.ticker import FuncFormatter
    
    # 安全等级映射（根据 security_level.md）
    security_level_map = {
        # Level 1: ~ 128-bit
        'Kyber512': 1, 'ML-KEM-512': 1, 
        'NTRU-HPS-2048-509': 1, 'NTRU-HPS-2048-512': 1,
        'P-256+Kyber512': 1, 'P-256+NTRU-HPS-2048-509': 1,
        
        # Level 2: ~ 128-bit
        'NTRU-HPS-2048-677': 2,
        'P-384+NTRU-HPS-2048-677': 2,  # 混合算法遵循PQC部分等级
        
        # Level 3: ~ 192-bit
        'Kyber768': 3, 'ML-KEM-768': 3,
        'P-256+Kyber768': 3,
        
        # Level 5: ~ 256-bit
        'Kyber1024': 5, 'ML-KEM-1024': 5,
        'P-521+Kyber1024': 5,
    }
    
    # 按安全等级分组
    level_groups = {}
    for item in kem_data:
        name = item['name'].replace('KEX-', '')
        # 查找安全等级
        level = 'Unknown'
        for key, lv in security_level_map.items():
            if key in name:
                level = lv
                break
        
        if level not in level_groups:
            level_groups[level] = []
        level_groups[level].append((name, item))
    
    # 按等级排序
    sorted_levels = sorted(level_groups.keys())
    
    # 重新组织数据（按等级分组）
    names = []
    throughputs = []
    avg_times = []
    x_positions = []
    colors = []
    
    # 安全等级颜色
    level_colors = {
        1: '#90EE90',  # Level 1 - 浅绿
        2: '#87CEEB',  # Level 2 - 天蓝
        3: '#FFD700',  # Level 3 - 金色
        4: '#FFA500',  # Level 4 - 橙色
        5: '#FF6347',  # Level 5 - 番茄红
    }
    
    current_x = 0
    group_positions = {}  # 记录每个等级的中心位置
    
    for level in sorted_levels:
        group_start = current_x
        for name, item in level_groups[level]:
            names.append(name)
            throughputs.append(item['throughput'])
            avg_times.append(item['avg_time'])
            x_positions.append(current_x)
            colors.append(level_colors.get(level, '#808080'))
            current_x += 1
        
        # 记录这个等级的中心位置
        group_center = (group_start + current_x - 1) / 2
        group_positions[level] = group_center
        
        # 添加等级间隔
        current_x += 0.5  # 不同等级之间留0.5个单位的间隔
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(18, 6))
    
    # 吞吐量（按等级分组）
    bars1 = ax1.bar(x_positions, throughputs, color=colors, alpha=0.8, width=0.8)
    ax1.set_title('KEM算法吞吐量比较（按安全等级分组）', fontsize=14, fontweight='bold')
    ax1.set_ylabel('吞吐量 (ops/s)', fontsize=12)
    ax1.set_xticks(x_positions)
    ax1.set_xticklabels(names, rotation=45, ha='right', fontsize=9)
    ax1.grid(True, axis='y', linestyle='--', alpha=0.7)
    
    # 添加安全等级分隔线
    for i, level in enumerate(sorted_levels):
        if i > 0:  # 不在第一个等级前画线
            prev_level_end = x_positions[sum(len(level_groups[lv]) for lv in sorted_levels[:i])] - 0.75
            ax1.axvline(x=prev_level_end, color='gray', linestyle='--', alpha=0.3, linewidth=1.5)
            ax2.axvline(x=prev_level_end, color='gray', linestyle='--', alpha=0.3, linewidth=1.5)
    
    # 添加安全等级图例（放在左上角，不遮挡柱子）
    from matplotlib.patches import Patch
    legend_elements = [Patch(facecolor=level_colors[lv], alpha=0.8, label=f'Level {lv}') 
                      for lv in sorted_levels if lv in level_colors]
    ax1.legend(handles=legend_elements, loc='upper left', fontsize=9, title='安全等级', framealpha=0.9)
    
    # 数值标签
    max_height = max(throughputs)
    for i, (x, height) in enumerate(zip(x_positions, throughputs)):
        offset = max_height * 0.02
        ax1.text(x, height + offset, f'{height:.0f}', 
                ha='center', va='bottom', fontsize=8)
    ax1.set_ylim(0, max_height * 1.35)  # 进一步增加上限，确保图例不遮挡柱子
    
    # 平均时间（按等级分组）
    bars2 = ax2.bar(x_positions, avg_times, color=colors, alpha=0.8, width=0.8)
    ax2.set_title('KEM算法平均时间（按安全等级分组）', fontsize=14, fontweight='bold')
    ax2.set_ylabel('平均时间 (ms)', fontsize=12)
    ax2.set_xticks(x_positions)
    ax2.set_xticklabels(names, rotation=45, ha='right', fontsize=9)
    ax2.grid(True, axis='y', linestyle='--', alpha=0.7)
    
    # 添加安全等级图例（放在左上角，不遮挡柱子）
    ax2.legend(handles=legend_elements, loc='upper left', fontsize=9, title='安全等级', framealpha=0.9)
    
    # 数值标签
    max_time = max(avg_times) if avg_times else 1
    for i, (x, height) in enumerate(zip(x_positions, avg_times)):
        offset = max_time * 0.02
        ax2.text(x, height + offset, f'{height:.2f}',
                ha='center', va='bottom', fontsize=8)
    ax2.set_ylim(0, max_time * 1.15)
    
    # 添加测试条件信息到图表底部中央（单行、清晰）
    plt.tight_layout(rect=[0, 0.06, 1, 1])  # 为底部文字留出6%空间
    fig.text(0.5, 0.01, condition_text, ha='center', va='bottom',
             fontsize=9, style='italic', 
             bbox=dict(boxstyle='round,pad=0.4', facecolor='lightgray', alpha=0.4, edgecolor='gray', linewidth=0.5))
    
    plt.savefig(output_dir / 'kem_comparison.pdf', dpi=300, bbox_inches='tight')
    plt.close()
    print("  ✓ kem_comparison.pdf")


def create_signature_plot(sig_data, output_dir, condition_text):
    """创建签名算法比较图（按安全等级分组）"""
    import matplotlib.pyplot as plt
    import numpy as np
    
    # 安全等级映射
    # 安全等级映射（根据 security_level.md）
    security_level_map = {
        # Level 1: ~ 128-bit
        'Falcon512': 1, 'Falcon-512': 1,
        
        # Level 2: 暂无主要推荐（但实际测试包含ML-DSA-44）
        'ML-DSA-44': 2, 'Dilithium2': 2,
        
        # Level 3: ~ 192-bit
        'ML-DSA-65': 3, 'Dilithium3': 3,
        
        # Level 4: ~ 192-bit
        'Falcon1024': 4, 'Falcon-1024': 4,
        
        # Level 5: ~ 256-bit
        'ML-DSA-87': 5, 'Dilithium5': 5,
    }
    
    # 按安全等级分组
    level_groups = {}
    for item in sig_data:
        name = item['name'].replace('SIG-', '')
        level = 'Unknown'
        for key, lv in security_level_map.items():
            if key in name:
                level = lv
                break
        
        if level not in level_groups:
            level_groups[level] = []
        level_groups[level].append((name, item))
    
    # 按等级排序
    sorted_levels = sorted(level_groups.keys())
    
    # 重新组织数据
    names = []
    throughputs = []
    avg_times = []
    x_positions = []
    colors = []
    
    level_colors = {
        1: '#90EE90', 2: '#87CEEB', 3: '#FFD700', 4: '#FFA500', 5: '#FF6347',
    }
    
    current_x = 0
    group_positions = {}
    
    for level in sorted_levels:
        group_start = current_x
        for name, item in level_groups[level]:
            names.append(name)
            throughputs.append(item['throughput'])
            avg_times.append(item['avg_time'])
            x_positions.append(current_x)
            colors.append(level_colors.get(level, '#808080'))
            current_x += 1
        
        group_positions[level] = (group_start + current_x - 1) / 2
        current_x += 0.5  # 等级间隔
    
    # 使用标准的X.509 DER格式证书大小（理论值）
    # 参考标准：公钥大小 + 签名大小 + X.509证书开销（~300-500 bytes）
    cert_size_standard = {
        'falcon512': 2500,      # ~2-3 KB (897 + 657 + overhead)
        'falcon1024': 4500,     # ~4-5 KB (1793 + 1271 + overhead)
        'mldsa44': 5500,        # ~5-6 KB (1312 + 2420 + overhead)
        'dilithium2': 5500,
        'mldsa65': 7500,        # ~7-8 KB (1952 + 3309 + overhead)
        'dilithium3': 7500,
        'mldsa87': 9500,        # ~9-10 KB (2592 + 4627 + overhead)
        'dilithium5': 9500,
    }
    
    cert_sizes = []
    for name, item in [(n, i) for level in sorted_levels for n, i in level_groups[level]]:
        algo_name_lower = name.lower().replace('-', '').replace('_', '')
        
        # 匹配算法并使用标准大小
        cert_size = 0
        for algo_key, size in cert_size_standard.items():
            if algo_key in algo_name_lower:
                cert_size = size
                break
        
        cert_sizes.append(cert_size)
    
    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(20, 6))
    
    # 吞吐量（按等级分组）
    bars1 = ax1.bar(x_positions, throughputs, color=colors, alpha=0.8, width=0.8)
    ax1.set_title('签名算法吞吐量比较（按安全等级分组）', fontsize=13, fontweight='bold')
    ax1.set_ylabel('吞吐量 (ops/s)', fontsize=12)
    ax1.set_xticks(x_positions)
    ax1.set_xticklabels(names, rotation=45, ha='right', fontsize=9)
    ax1.grid(True, axis='y', linestyle='--', alpha=0.7)
    
    # 添加安全等级分隔线
    for i, level in enumerate(sorted_levels):
        if i > 0:
            prev_level_end = x_positions[sum(len(level_groups[lv]) for lv in sorted_levels[:i])] - 0.75
            ax1.axvline(x=prev_level_end, color='gray', linestyle='--', alpha=0.3, linewidth=1.5)
            ax2.axvline(x=prev_level_end, color='gray', linestyle='--', alpha=0.3, linewidth=1.5)
            ax3.axvline(x=prev_level_end, color='gray', linestyle='--', alpha=0.3, linewidth=1.5)
    
    # 添加安全等级图例（放在左上角，不遮挡柱子）
    from matplotlib.patches import Patch
    legend_elements = [Patch(facecolor=level_colors[lv], alpha=0.8, label=f'Level {lv}')
                      for lv in sorted_levels if lv in level_colors]
    ax1.legend(handles=legend_elements, loc='upper left', fontsize=9, title='安全等级', framealpha=0.9)
    
    # 数值标签
    max_height = max(throughputs) if throughputs else 1
    for x, height in zip(x_positions, throughputs):
        offset = max_height * 0.02
        ax1.text(x, height + offset, f'{height:.0f}',
                ha='center', va='bottom', fontsize=8)
    ax1.set_ylim(0, max_height * 1.15)
    
    # 平均时间（按等级分组）
    bars2 = ax2.bar(x_positions, avg_times, color=colors, alpha=0.8, width=0.8)
    ax2.set_title('签名算法平均时间（按安全等级分组）', fontsize=13, fontweight='bold')
    ax2.set_ylabel('平均时间 (ms)', fontsize=12)
    ax2.set_xticks(x_positions)
    ax2.set_xticklabels(names, rotation=45, ha='right', fontsize=9)
    ax2.grid(True, axis='y', linestyle='--', alpha=0.7)
    
    # 添加安全等级图例（放在左上角，不遮挡柱子）
    ax2.legend(handles=legend_elements, loc='upper left', fontsize=9, title='安全等级', framealpha=0.9)
    
    # 数值标签
    max_time = max(avg_times) if avg_times else 1
    for x, height in zip(x_positions, avg_times):
        offset = max_time * 0.02
        ax2.text(x, height + offset, f'{height:.2f}',
                ha='center', va='bottom', fontsize=8)
    ax2.set_ylim(0, max_time * 1.15)
    
    # 证书大小（按等级分组）
    bars3 = ax3.bar(x_positions, cert_sizes, color=colors, alpha=0.8, width=0.8)
    ax3.set_title('证书大小对比（按安全等级分组）', fontsize=13, fontweight='bold')
    ax3.set_ylabel('证书大小 (字节)', fontsize=12)
    ax3.set_xticks(x_positions)
    ax3.set_xticklabels(names, rotation=45, ha='right', fontsize=9)
    ax3.grid(True, axis='y', linestyle='--', alpha=0.7)
    
    # 添加安全等级图例
    ax3.legend(handles=legend_elements, loc='upper left', fontsize=9, title='安全等级', framealpha=0.9)
    
    # 数值标签
    max_cert_size = max(cert_sizes) if cert_sizes and max(cert_sizes) > 0 else 1
    for x, size in zip(x_positions, cert_sizes):
        if size > 0:  # 只显示非零值
            offset = max_cert_size * 0.02
            # 显示KB
            ax3.text(x, size + offset, f'{size/1024:.1f}KB',
                    ha='center', va='bottom', fontsize=7)
    ax3.set_ylim(0, max_cert_size * 1.15)
    
    # 添加测试条件信息到图表底部中央（单行、清晰）
    plt.tight_layout(rect=[0, 0.06, 1, 1])  # 为底部文字留出6%空间
    fig.text(0.5, 0.01, condition_text, ha='center', va='bottom',
             fontsize=9, style='italic',
             bbox=dict(boxstyle='round,pad=0.4', facecolor='lightgray', alpha=0.4, edgecolor='gray', linewidth=0.5))
    
    plt.savefig(output_dir / 'signature_comparison.pdf', dpi=300, bbox_inches='tight')
    plt.close()
    print("  ✓ signature_comparison.pdf")


def create_handshake_plot(handshake_data, output_dir, condition_text):
    """创建握手性能比较图（包含消息长度和网络延迟分析）"""
    import matplotlib.pyplot as plt
    import numpy as np
    
    names = [item['name'].replace('Handshake-10s-', '').upper() for item in handshake_data]
    throughputs = [item['throughput'] for item in handshake_data]
    avg_times = [item['avg_time'] for item in handshake_data]
    
    # 提取消息大小
    client_hello_sizes = [item['sizes']['client_hello'] for item in handshake_data]
    server_hello_sizes = [item['sizes']['server_hello'] for item in handshake_data]
    # 证书大小：优先使用certificate字段，如果没有则用total减去其他消息
    cert_sizes = [item['sizes'].get('certificate', 
                                    item['sizes']['total'] - item['sizes']['client_hello'] - item['sizes']['server_hello']) 
                  for item in handshake_data]
    total_sizes = [item['sizes']['total'] for item in handshake_data]
    
    # 创建2x2子图布局
    fig = plt.figure(figsize=(18, 10))
    gs = fig.add_gridspec(2, 2, hspace=0.3, wspace=0.25)
    ax1 = fig.add_subplot(gs[0, 0])  # 吞吐量
    ax2 = fig.add_subplot(gs[0, 1])  # 平均时间
    ax3 = fig.add_subplot(gs[1, 0])  # 消息长度堆叠
    ax4 = fig.add_subplot(gs[1, 1])  # 证书长度对比（新增）
    
    colors = ['#1f77b4', '#ff7f0e', '#2ca02c']
    
    # 吞吐量
    bars1 = ax1.bar(names, throughputs, color=colors, alpha=0.8)
    ax1.set_title('TLS握手吞吐量比较', fontsize=14, fontweight='bold')
    ax1.set_ylabel('吞吐量 (ops/s)', fontsize=12)
    ax1.tick_params(axis='x', rotation=0)
    ax1.grid(True, axis='y', linestyle='--', alpha=0.7)
    
    # 自动调整标签位置
    max_height = max(throughputs) if throughputs else 1
    for bar in bars1:
        height = bar.get_height()
        offset = max_height * 0.02
        ax1.text(bar.get_x() + bar.get_width()/2., height + offset,
                f'{height:.1f}', ha='center', va='bottom', fontsize=10)
    ax1.set_ylim(0, max_height * 1.15)
    
    # 平均时间
    bars2 = ax2.bar(names, avg_times, color=colors, alpha=0.8)
    ax2.set_title('TLS握手平均时间', fontsize=14, fontweight='bold')
    ax2.set_ylabel('平均时间 (ms)', fontsize=12)
    ax2.tick_params(axis='x', rotation=0)
    ax2.grid(True, axis='y', linestyle='--', alpha=0.7)
    
    # 自动调整标签位置
    max_time = max(avg_times) if avg_times else 1
    for bar in bars2:
        height = bar.get_height()
        offset = max_time * 0.02
        ax2.text(bar.get_x() + bar.get_width()/2., height + offset,
                f'{height:.2f}', ha='center', va='bottom', fontsize=10)
    ax2.set_ylim(0, max_time * 1.15)
    
    # 3. 消息长度堆叠图
    x_pos = np.arange(len(names))
    width = 0.6
    
    # 堆叠柱状图
    p1 = ax3.bar(x_pos, client_hello_sizes, width, color='#3498db', alpha=0.8, label='ClientHello')
    p2 = ax3.bar(x_pos, server_hello_sizes, width, bottom=client_hello_sizes, 
                 color='#e74c3c', alpha=0.8, label='ServerHello')
    p3 = ax3.bar(x_pos, cert_sizes, width,
                 bottom=np.array(client_hello_sizes) + np.array(server_hello_sizes),
                 color='#2ecc71', alpha=0.8, label='Certificate')
    
    ax3.set_title('握手消息长度分布（堆叠）', fontsize=13, fontweight='bold')
    ax3.set_ylabel('消息大小 (字节)', fontsize=11)
    ax3.set_xticks(x_pos)
    ax3.set_xticklabels(names, rotation=0, fontsize=10)
    ax3.legend(loc='upper left', fontsize=9, title='消息类型', framealpha=0.9)
    ax3.grid(True, axis='y', linestyle='--', alpha=0.7)
    
    # 设置Y轴上限，留出足够空间显示标签
    max_total = max(total_sizes) if total_sizes else 1
    ax3.set_ylim(0, max_total * 1.15)
    
    # 在堆叠柱上添加总长度标签
    for i, total in enumerate(total_sizes):
        ax3.text(i, total + max_total * 0.02, f'{total}B',
                ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    # 4. 证书长度对比（突出显示）
    x_pos2 = np.arange(len(names))
    
    bars4 = ax4.bar(x_pos2, cert_sizes, color='#27ae60', alpha=0.8, width=0.6)
    
    ax4.set_title('Certificate消息大小对比', fontsize=13, fontweight='bold')
    ax4.set_ylabel('证书大小 (字节)', fontsize=11)
    ax4.set_xticks(x_pos2)
    ax4.set_xticklabels(names, rotation=0, fontsize=10)
    ax4.grid(True, axis='y', linestyle='--', alpha=0.7)
    
    # 设置Y轴上限，留出足够空间显示标签
    max_cert_size = max(cert_sizes) if cert_sizes else 1
    ax4.set_ylim(0, max_cert_size * 1.15)
    
    # 添加数值标签
    for bar, cert_size in zip(bars4, cert_sizes):
        height = bar.get_height()
        if height > 0:  # 只显示非零值
            ax4.text(bar.get_x() + bar.get_width()/2., height + max_cert_size * 0.02,
                    f'{int(height)}B', ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    # 添加测试条件信息到图表底部中央（单行、清晰）
    plt.suptitle('TLS握手性能综合分析', fontsize=16, fontweight='bold', y=0.98)
    plt.tight_layout(rect=[0, 0.06, 1, 0.96])  # 为底部文字和顶部标题留空间
    fig.text(0.5, 0.01, condition_text, ha='center', va='bottom',
             fontsize=9, style='italic',
             bbox=dict(boxstyle='round,pad=0.4', facecolor='lightgray', alpha=0.4, edgecolor='gray', linewidth=0.5))
    
    plt.savefig(output_dir / 'handshake_comparison.pdf', dpi=300, bbox_inches='tight')
    plt.close()
    print("  ✓ handshake_comparison.pdf")
    
    # 额外创建网络延迟影响分析图
    create_network_impact_plot(handshake_data, output_dir, condition_text)


def create_network_impact_plot(handshake_data, output_dir, condition_text):
    """创建网络延迟影响分析图（理论计算）"""
    import matplotlib.pyplot as plt
    import numpy as np
    
    # 网络配置（传输速率 bps, 距离 km）
    network_configs = {
        'localhost (1Gbps, 0.1km)': (1_000_000_000, 0.1),
        'LAN (100Mbps, 10km)': (100_000_000, 10),
        'WAN (10Mbps, 500km)': (10_000_000, 500),
        '4G (5Mbps, 2000km)': (5_000_000, 2000),
    }
    
    names = [item['name'].replace('Handshake-10s-', '').upper() for item in handshake_data]
    compute_times = [item['avg_time'] for item in handshake_data]  # 计算时间（ms）
    total_msg_sizes = [item['sizes']['total'] * 8 for item in handshake_data]  # 转为bits
    
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
    
    # 为每个网络配置计算延迟
    for idx, (net_name, (rate, distance)) in enumerate(list(network_configs.items())):
        # 计算传输时延和传播时延
        transmission_delays = [size / rate * 1000 for size in total_msg_sizes]  # ms
        propagation_delay = distance / 200000 * 1000  # ms
        
        # 总网络延迟
        network_delays = [td + propagation_delay for td in transmission_delays]
        total_times = [ct + nd for ct, nd in zip(compute_times, network_delays)]
        
        # 选择合适的子图
        axes = [ax1, ax2, ax3, ax4]
        ax = axes[idx]
        
        x = np.arange(len(names))
        width = 0.35
        
        # 堆叠柱状图：计算时间 + 网络延迟
        bars1 = ax.bar(x, compute_times, width, label='计算时间', color='#3498db', alpha=0.8)
        bars2 = ax.bar(x, network_delays, width, bottom=compute_times,
                      label='网络延迟', color='#e74c3c', alpha=0.8)
        
        ax.set_title(f'{net_name}', fontsize=12, fontweight='bold')
        ax.set_ylabel('时间 (ms)', fontsize=10)
        ax.set_xticks(x)
        ax.set_xticklabels(names, rotation=0, fontsize=9)
        ax.legend(fontsize=8, framealpha=0.9)
        ax.grid(True, axis='y', linestyle='--', alpha=0.7)
        
        # 添加详细标签
        for i, (ct, nd, tt) in enumerate(zip(compute_times, network_delays, total_times)):
            # 显示总时间和网络占比
            net_pct = nd / tt * 100 if tt > 0 else 0
            ax.text(i, tt + tt * 0.02, f'{tt:.2f}ms\n(网络{net_pct:.0f}%)',
                   ha='center', va='bottom', fontsize=8, fontweight='bold')
            
            # 在网络延迟部分显示传输和传播时延（改进可读性）
            trans_delay = transmission_delays[i]
            
            # 只在网络延迟部分足够大时显示文字
            if nd > ct * 0.15:  # 如果网络延迟大于计算时间的15%
                # 在传输时延部分显示
                if trans_delay > ct * 0.08:
                    ax.text(i, ct + trans_delay/2, f'传输\n{trans_delay:.2f}ms',
                           ha='center', va='center', fontsize=7, color='white', fontweight='bold',
                           bbox=dict(boxstyle='round,pad=0.2', facecolor='darkred', alpha=0.6, edgecolor='none'))
                
                # 在传播时延部分显示
                if propagation_delay > ct * 0.08:
                    ax.text(i, ct + trans_delay + propagation_delay/2, f'传播\n{propagation_delay:.2f}ms',
                           ha='center', va='center', fontsize=7, color='white', fontweight='bold',
                           bbox=dict(boxstyle='round,pad=0.2', facecolor='darkred', alpha=0.6, edgecolor='none'))
    
    plt.suptitle('TLS握手网络延迟影响分析（理论模拟）', fontsize=16, fontweight='bold')
    plt.tight_layout(rect=[0, 0.1, 1, 0.96])  # 为底部留出更多空间
    
    # 底部显示：测试条件 + 网络延迟计算说明
    network_formula_text = (
        "网络延迟计算：传输时延 = 消息大小(bits) / 传输速率(bps)  |  "
        "传播时延 = 距离(km) / 光速(200,000 km/s)  |  "
        "总延迟 = 计算时间 + 传输时延 + 传播时延"
    )
    
    fig.text(0.5, 0.055, condition_text, ha='center', va='bottom',
             fontsize=9, style='italic',
             bbox=dict(boxstyle='round,pad=0.4', facecolor='lightgray', alpha=0.4, edgecolor='gray', linewidth=0.5))
    
    fig.text(0.5, 0.01, network_formula_text, ha='center', va='bottom',
             fontsize=7, style='italic', color='darkblue',
             bbox=dict(boxstyle='round,pad=0.3', facecolor='lightyellow', alpha=0.5, edgecolor='orange', linewidth=0.5))
    
    plt.savefig(output_dir / 'network_impact_analysis.pdf', dpi=300, bbox_inches='tight')
    plt.close()
    print("  ✓ network_impact_analysis.pdf")


def create_comprehensive_plot(data, output_dir, condition_text):
    """创建综合性能比较图"""
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch
    
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
        all_names.append(item['name'].replace('Handshake-10s-', '').upper())
    
    # 创建图表
    fig, ax = plt.subplots(figsize=(16, 8))
    
    # 设置颜色
    colors = []
    for name in all_names:
        if any(x in name for x in ['X25519', 'P-256', 'ECDSA', 'CLASSIC']):
            colors.append('#1f77b4')
        elif any(x in name for x in ['Kyber', 'Dilithium', 'PQC']):
            colors.append('#ff7f0e')
        else:
            colors.append('#2ca02c')
    
    bars = ax.bar(range(len(all_names)), all_throughputs, color=colors, alpha=0.8, width=0.6)
    
    ax.set_title('TLS算法性能综合比较', fontsize=18, fontweight='bold', pad=20)
    ax.set_ylabel('吞吐量 (ops/s)', fontsize=14, fontweight='bold')
    ax.set_xlabel('算法类型', fontsize=14, fontweight='bold')
    
    ax.set_xticks(range(len(all_names)))
    ax.set_xticklabels(all_names, rotation=45, ha='right', fontsize=10)
    
    ax.grid(True, axis='y', linestyle='--', alpha=0.7)
    
    # 添加数值标签（自动调整位置）
    max_height = max(all_throughputs) if all_throughputs else 1
    for bar in bars:
        height = bar.get_height()
        if height > 1000:
            label = f'{height/1000:.1f}K'
        else:
            label = f'{height:.0f}'
        offset = max_height * 0.015  # 综合图标签更紧凑
        ax.text(bar.get_x() + bar.get_width()/2., height + offset,
                label, ha='center', va='bottom', fontsize=9)
    ax.set_ylim(0, max_height * 1.12)
    
    # 图例
    legend_elements = [
        Patch(facecolor='#1f77b4', alpha=0.8, label='经典算法'),
        Patch(facecolor='#ff7f0e', alpha=0.8, label='PQC算法'),
        Patch(facecolor='#2ca02c', alpha=0.8, label='混合算法')
    ]
    ax.legend(handles=legend_elements, loc='upper right', fontsize=11)
    
    # 添加测试条件信息到图表底部中央（紧凑、不遮挡）
    plt.tight_layout(rect=[0, 0.04, 1, 1])  # 为底部文字留出4%空间
    fig.text(0.5, 0.005, condition_text, ha='center', va='bottom',
             fontsize=7, style='italic',
             bbox=dict(boxstyle='round,pad=0.3', facecolor='lightgray', alpha=0.3, edgecolor='none'))
    
    plt.savefig(output_dir / 'comprehensive_comparison.pdf', dpi=300, bbox_inches='tight')
    plt.close()
    print("  ✓ comprehensive_comparison.pdf")


def create_network_handshake_plot(network_data, output_dir, test_config):
    """创建网络感知握手性能比较图"""
    import matplotlib.pyplot as plt
    import numpy as np
    
    # 按网络配置分组数据
    network_profiles = {}
    for item in network_data:
        net_config = item.get('network_config', {})
        profile_name = f"{net_config.get('rate_profile', 'unknown')}"
        
        if profile_name not in network_profiles:
            network_profiles[profile_name] = {
                'classic': [],
                'pqc': [],
                'hybrid': []
            }
        
        name = item['name'].lower()
        if 'classic' in name:
            network_profiles[profile_name]['classic'].append(item)
        elif 'pqc' in name or 'pure' in name:
            network_profiles[profile_name]['pqc'].append(item)
        elif 'hybrid' in name:
            network_profiles[profile_name]['hybrid'].append(item)
    
    # 为每个网络配置创建子图
    num_profiles = len(network_profiles)
    if num_profiles == 0:
        return
    
    fig, axes = plt.subplots(1, min(num_profiles, 3), figsize=(6*min(num_profiles, 3), 5))
    if num_profiles == 1:
        axes = [axes]
    
    for idx, (profile_name, profile_data) in enumerate(list(network_profiles.items())[:3]):
        ax = axes[idx]
        
        modes = ['classic', 'pqc', 'hybrid']
        mode_labels = ['Classic', 'PQC', 'Hybrid']
        compute_times = []
        network_delays = []
        
        for mode in modes:
            if profile_data[mode]:
                item = profile_data[mode][0]  # 取第一个
                compute_times.append(item.get('avg_compute_time', 0))
                network_delays.append(item.get('avg_network_delay', 0))
            else:
                compute_times.append(0)
                network_delays.append(0)
        
        x = np.arange(len(mode_labels))
        width = 0.35
        
        bars1 = ax.bar(x - width/2, compute_times, width, label='计算时间', color='#1f77b4', alpha=0.8)
        bars2 = ax.bar(x + width/2, network_delays, width, label='网络延迟', color='#ff7f0e', alpha=0.8)
        
        ax.set_title(f'{profile_name.upper()} 网络', fontsize=12, fontweight='bold')
        ax.set_ylabel('时间 (ms)', fontsize=10)
        ax.set_xticks(x)
        ax.set_xticklabels(mode_labels)
        ax.legend(fontsize=9)
        ax.grid(True, axis='y', linestyle='--', alpha=0.7)
    
    # 构建测试条件文本（紧凑格式）
    config = test_config.get('configuration', {})
    net_profiles = ', '.join(config.get('network_profiles', []))
    dist_profiles = ', '.join(config.get('distance_profiles', []))
    condition_text = (
        f"场景: {test_config.get('scenario_name', 'unknown')} | "
        f"迭代: {config.get('iterations', 'N/A')}次 | "
        f"网络: {net_profiles} | 距离: {dist_profiles}"
    )
    
    # 添加测试条件信息到图表底部中央（单行、清晰）
    plt.tight_layout(rect=[0, 0.06, 1, 1])  # 为底部文字留出6%空间
    fig.text(0.5, 0.01, condition_text, ha='center', va='bottom',
             fontsize=9, style='italic',
             bbox=dict(boxstyle='round,pad=0.4', facecolor='lightgray', alpha=0.4, edgecolor='gray', linewidth=0.5))
    
    plt.savefig(output_dir / 'network_handshake_comparison.pdf', dpi=300, bbox_inches='tight')
    plt.close()
    print("  ✓ network_handshake_comparison.pdf")


def run_batch_benchmarks(scenarios: list, output_base_dir: str = "results/batch_tests"):
    """
    批量运行多个测试场景
    
    Args:
        scenarios: 要运行的场景列表
        output_base_dir: 输出基础目录
    """
    # 确定脚本所在目录
    script_dir = Path(__file__).parent
    benchmarks_dir = script_dir  # batch脚本在benchmarks目录中
    
    output_path = benchmarks_dir / output_base_dir
    output_path.mkdir(parents=True, exist_ok=True)
    
    print("\n" + "=" * 80)
    print("🎯 批量基准测试和可视化工具")
    print("=" * 80)
    print(f"将运行 {len(scenarios)} 个测试场景")
    print(f"Benchmarks目录: {benchmarks_dir.absolute()}")
    print(f"输出目录: {output_path.absolute()}")
    
    all_results = []
    
    for scenario_name in scenarios:
        if scenario_name not in TEST_SCENARIOS:
            print(f"\n⚠️  跳过未知场景: {scenario_name}")
            continue
        
        scenario_config = TEST_SCENARIOS[scenario_name]
        
        try:
            result_info = run_benchmark(scenario_name, scenario_config, output_path, benchmarks_dir)
            all_results.append(result_info)
            
            # 立即为该场景生成可视化
            scenario_dir = output_path / f"{scenario_name}_{result_info['timestamp']}"
            if scenario_dir.exists():
                visualize_scenario_results(scenario_dir)
        
        except Exception as e:
            print(f"\n❌ 场景 '{scenario_name}' 运行失败: {e}")
            import traceback
            traceback.print_exc()
    
    # 生成汇总报告
    generate_summary_report(all_results, output_path)
    
    print("\n" + "=" * 80)
    print("[OK] 所有测试完成！")
    print(f"   总场景数: {len(all_results)}")
    print(f"   结果目录: {output_path.absolute()}")
    print("=" * 80)


def generate_summary_report(all_results: list, output_dir: Path):
    """生成汇总报告"""
    if not all_results:
        return
    
    summary_file = output_dir / "summary_report.txt"
    
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("批量测试汇总报告\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"总场景数: {len(all_results)}\n\n")
        
        for result in all_results:
            f.write("-" * 80 + "\n")
            f.write(f"场景: {result['scenario_name']}\n")
            f.write(f"描述: {result['description']}\n")
            f.write(f"时间戳: {result['timestamp']}\n")
            f.write(f"执行时间: {result['elapsed_time_seconds']:.2f} 秒\n")
            f.write(f"退出码: {result['exit_code']}\n")
            f.write(f"配置: {json.dumps(result['configuration'], indent=2, ensure_ascii=False)}\n")
            f.write("\n")
    
    print(f"\n📋 汇总报告已保存: {summary_file}")


def list_scenarios():
    """列出所有可用的测试场景"""
    print("\n可用的测试场景：\n")
    for name, config in TEST_SCENARIOS.items():
        print(f"  {name:20s} - {config['description']}")
        print(f"  {'':20s}   迭代: {config['iterations']}, 测试: {config['tests']}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description='批量运行TLS基准测试并生成可视化图表',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  # 运行快速测试
  python batch_benchmark_and_visualize.py --scenarios quick
  
  # 运行多个场景
  python batch_benchmark_and_visualize.py --scenarios quick standard comprehensive
  
  # 运行所有场景
  python batch_benchmark_and_visualize.py --all
  
  # 列出所有可用场景
  python batch_benchmark_and_visualize.py --list
        """
    )
    
    parser.add_argument('--scenarios', nargs='+', metavar='NAME',
                       help='要运行的测试场景名称（可指定多个）')
    parser.add_argument('--all', action='store_true',
                       help='运行所有预定义的测试场景')
    parser.add_argument('--list', action='store_true',
                       help='列出所有可用的测试场景')
    parser.add_argument('--output-dir', default='results/batch_tests',
                       help='输出目录（默认: results/batch_tests）')
    
    args = parser.parse_args()
    
    if args.list:
        list_scenarios()
        return
    
    # 确定要运行的场景
    if args.all:
        scenarios_to_run = list(TEST_SCENARIOS.keys())
    elif args.scenarios:
        scenarios_to_run = args.scenarios
    else:
        # 默认运行快速测试
        print("未指定场景，运行默认的'quick'场景")
        print("使用 --list 查看所有可用场景，或使用 --all 运行所有场景")
        scenarios_to_run = ['quick']
    
    # 运行批量测试
    run_batch_benchmarks(scenarios_to_run, args.output_dir)


if __name__ == "__main__":
    main()

