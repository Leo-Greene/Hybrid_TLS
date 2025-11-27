#!/usr/bin/env python3
"""
握手时间追踪工具
用于记录TLS握手过程中每个步骤的耗时
"""

import time
from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class TimingStep:
    """单个步骤的时间记录"""
    step_name: str
    start_time: float
    end_time: Optional[float] = None
    duration_ms: Optional[float] = None
    details: Dict = field(default_factory=dict)
    
    def finish(self, details: Optional[Dict] = None):
        """完成步骤并计算耗时"""
        self.end_time = time.time()
        self.duration_ms = (self.end_time - self.start_time) * 1000
        if details:
            self.details.update(details)


class HandshakeTimingTracker:
    """握手时间追踪器"""
    
    def __init__(self):
        self.steps: List[TimingStep] = []
        self.start_time = time.time()
        self.current_step: Optional[TimingStep] = None
    
    def start_step(self, step_name: str, details: Optional[Dict] = None) -> TimingStep:
        """开始一个新步骤"""
        if self.current_step:
            self.current_step.finish()
        
        step = TimingStep(
            step_name=step_name,
            start_time=time.time(),
            details=details or {}
        )
        self.steps.append(step)
        self.current_step = step
        return step
    
    def finish_step(self, details: Optional[Dict] = None):
        """完成当前步骤"""
        if self.current_step:
            self.current_step.finish(details)
            self.current_step = None
    
    def add_sub_step(self, sub_step_name: str, duration_ms: float, details: Optional[Dict] = None):
        """添加子步骤（不创建新的主步骤）"""
        if self.current_step:
            if 'sub_steps' not in self.current_step.details:
                self.current_step.details['sub_steps'] = []
            self.current_step.details['sub_steps'].append({
                'name': sub_step_name,
                'duration_ms': duration_ms,
                'details': details or {}
            })
    
    def get_summary(self) -> Dict:
        """获取时间摘要"""
        total_time = (time.time() - self.start_time) * 1000
        
        steps_data = []
        for step in self.steps:
            step_data = {
                'step_name': step.step_name,
                'duration_ms': step.duration_ms or 0,
                'details': step.details
            }
            steps_data.append(step_data)
        
        return {
            'total_time_ms': total_time,
            'steps': steps_data,
            'step_count': len(self.steps)
        }
    
    def get_steps_summary(self) -> List[Dict]:
        """获取步骤摘要列表"""
        return [
            {
                'name': step.step_name,
                'duration_ms': step.duration_ms or 0,
                'details': step.details
            }
            for step in self.steps
        ]


