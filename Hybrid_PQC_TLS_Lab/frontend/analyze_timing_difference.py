#!/usr/bin/env python3
"""
分析 by_val 和 by_ref 模式的时间差异
找出影响握手时间的主要因素
"""

import json
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict


def load_timing_data(file_path: Path) -> Dict[str, Any]:
    """加载时间追踪数据"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def analyze_step_timings(timing_data: Dict[str, Any]) -> Dict[str, float]:
    """分析各个步骤的耗时"""
    step_timings = {}
    if 'steps' in timing_data:
        for step in timing_data['steps']:
            step_name = step.get('step_name', 'unknown')
            duration = step.get('duration_ms', 0)
            step_timings[step_name] = duration
            
            # 如果有子步骤，也记录
            if 'details' in step and 'sub_steps' in step['details']:
                for sub_step in step['details']['sub_steps']:
                    sub_name = f"{step_name}.{sub_step.get('name', 'unknown')}"
                    sub_duration = sub_step.get('duration_ms', 0)
                    step_timings[sub_name] = sub_duration
    
    return step_timings


def compare_modes(by_val_timing: Dict[str, Any], by_ref_timing: Dict[str, Any]) -> Dict[str, Any]:
    """比较两种模式的时间差异"""
    by_val_steps = analyze_step_timings(by_val_timing)
    by_ref_steps = analyze_step_timings(by_ref_timing)
    
    # 找出所有步骤
    all_steps = set(by_val_steps.keys()) | set(by_ref_steps.keys())
    
    # 计算差异
    differences = {}
    for step in all_steps:
        by_val_time = by_val_steps.get(step, 0)
        by_ref_time = by_ref_steps.get(step, 0)
        diff = by_ref_time - by_val_time
        differences[step] = {
            'by_val_ms': by_val_time,
            'by_ref_ms': by_ref_time,
            'difference_ms': diff,
            'difference_percent': (diff / by_val_time * 100) if by_val_time > 0 else 0
        }
    
    # 找出差异最大的步骤
    sorted_diffs = sorted(
        differences.items(),
        key=lambda x: abs(x[1]['difference_ms']),
        reverse=True
    )
    
    return {
        'differences': differences,
        'sorted_by_difference': sorted_diffs,
        'total_by_val_ms': by_val_timing.get('total_time_ms', 0),
        'total_by_ref_ms': by_ref_timing.get('total_time_ms', 0),
        'total_difference_ms': by_ref_timing.get('total_time_ms', 0) - by_val_timing.get('total_time_ms', 0)
    }


def extract_http_timings(timing_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """提取所有HTTP请求的时间信息"""
    http_timings = []
    
    if 'steps' in timing_data:
        for step in timing_data['steps']:
            step_name = step.get('step_name', '')
            details = step.get('details', {})
            
            # 检查是否是HTTP相关步骤
            if 'HTTP' in step_name or 'http_time_ms' in details:
                http_timings.append({
                    'step': step_name,
                    'duration_ms': step.get('duration_ms', 0),
                    'http_time_ms': details.get('http_time_ms', 0),
                    'size': details.get('size', 0),
                    'algorithm': details.get('algorithm', 'unknown')
                })
    
    return http_timings


def generate_report(comparison_result: Dict[str, Any], by_val_http: List[Dict], by_ref_http: List[Dict]) -> str:
    """生成分析报告"""
    report = []
    report.append("=" * 80)
    report.append("by_val vs by_ref 模式时间差异分析报告")
    report.append("=" * 80)
    report.append("")
    
    # 总时间对比
    report.append("总时间对比:")
    report.append(f"  by_val: {comparison_result['total_by_val_ms']:.2f} ms")
    report.append(f"  by_ref: {comparison_result['total_by_ref_ms']:.2f} ms")
    report.append(f"  差异: {comparison_result['total_difference_ms']:.2f} ms ({comparison_result['total_difference_ms']/comparison_result['total_by_val_ms']*100:.1f}%)")
    report.append("")
    
    # 差异最大的步骤
    report.append("差异最大的步骤（前10个）:")
    report.append("-" * 80)
    for i, (step, diff_info) in enumerate(comparison_result['sorted_by_difference'][:10], 1):
        report.append(f"{i}. {step}")
        report.append(f"   by_val: {diff_info['by_val_ms']:.2f} ms")
        report.append(f"   by_ref: {diff_info['by_ref_ms']:.2f} ms")
        report.append(f"   差异: {diff_info['difference_ms']:.2f} ms ({diff_info['difference_percent']:.1f}%)")
        report.append("")
    
    # HTTP请求分析
    report.append("HTTP请求分析:")
    report.append("-" * 80)
    if by_ref_http:
        report.append("by_ref模式的HTTP请求:")
        total_http_time = 0
        for http_req in by_ref_http:
            report.append(f"  {http_req['step']}:")
            report.append(f"    总耗时: {http_req['duration_ms']:.2f} ms")
            report.append(f"    HTTP请求: {http_req.get('http_time_ms', 0):.2f} ms")
            report.append(f"    数据大小: {http_req.get('size', 0)} 字节")
            report.append(f"    算法: {http_req.get('algorithm', 'unknown')}")
            total_http_time += http_req.get('http_time_ms', 0)
        report.append(f"  HTTP请求总耗时: {total_http_time:.2f} ms")
        report.append("")
    else:
        report.append("by_ref模式未检测到HTTP请求")
        report.append("")
    
    # 主要影响因素
    report.append("主要影响因素分析:")
    report.append("-" * 80)
    
    # 找出by_ref模式特有的步骤
    by_ref_only_steps = []
    for step, diff_info in comparison_result['differences'].items():
        if diff_info['by_val_ms'] == 0 and diff_info['by_ref_ms'] > 0:
            by_ref_only_steps.append((step, diff_info['by_ref_ms']))
    
    if by_ref_only_steps:
        report.append("by_ref模式特有的步骤:")
        for step, duration in sorted(by_ref_only_steps, key=lambda x: x[1], reverse=True):
            report.append(f"  {step}: {duration:.2f} ms")
        report.append("")
    
    # 计算HTTP请求占总时间的比例
    if by_ref_http:
        total_http = sum(h.get('http_time_ms', 0) for h in by_ref_http)
        total_time = comparison_result['total_by_ref_ms']
        if total_time > 0:
            http_percent = (total_http / total_time) * 100
            report.append(f"HTTP请求时间占比: {http_percent:.1f}% ({total_http:.2f} ms / {total_time:.2f} ms)")
            report.append("")
    
    return "\n".join(report)


def main():
    """主函数"""
    import sys
    
    if len(sys.argv) < 3:
        print("用法: python analyze_timing_difference.py <by_val_timing.json> <by_ref_timing.json>")
        print("示例: python analyze_timing_difference.py by_val_timing.json by_ref_timing.json")
        sys.exit(1)
    
    by_val_file = Path(sys.argv[1])
    by_ref_file = Path(sys.argv[2])
    
    if not by_val_file.exists():
        print(f"错误: 文件不存在: {by_val_file}")
        sys.exit(1)
    
    if not by_ref_file.exists():
        print(f"错误: 文件不存在: {by_ref_file}")
        sys.exit(1)
    
    # 加载数据
    print("加载时间追踪数据...")
    by_val_timing = load_timing_data(by_val_file)
    by_ref_timing = load_timing_data(by_ref_file)
    
    # 比较
    print("分析时间差异...")
    comparison = compare_modes(by_val_timing, by_ref_timing)
    
    # 提取HTTP请求时间
    by_val_http = extract_http_timings(by_val_timing)
    by_ref_http = extract_http_timings(by_ref_timing)
    
    # 生成报告
    report = generate_report(comparison, by_val_http, by_ref_http)
    
    # 输出报告
    print("\n" + report)
    
    # 保存报告
    output_file = Path("timing_analysis_report.txt")
    output_file.write_text(report, encoding='utf-8')
    print(f"\n报告已保存到: {output_file}")


if __name__ == "__main__":
    main()

