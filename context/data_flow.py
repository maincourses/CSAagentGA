import re
from typing import Dict, Optional


class DataFlowTracer:
    """
    轻量级数据流追踪：在函数源码中追踪变量的定义点和赋值点。
    不依赖 libclang，基于正则表达式，适合快速提取变量上下文。
    """

    def find_variable_definitions(
        self, function_source: str, variable_name: str
    ) -> Dict[str, str]:
        """
        在函数源码中搜索变量的定义和赋值语句。
        返回 {line_content: reason}，其中 reason 解释为何该行与该变量相关。
        """
        results = {}
        lines = function_source.splitlines()

        # 匹配定义：类型 变量名 = ...  或  类型* 变量名
        def_pattern = re.compile(
            rf"\b(?:[\w:<>*&]+\s+)+\*?\s*{re.escape(variable_name)}\s*(?:[=;(]|$)"
        )
        # 匹配赋值：变量名 = ...  或  变量名 op= ...
        assign_pattern = re.compile(
            rf"\b{re.escape(variable_name)}\s*(?:\+|-|\*|/|%|&|\||\^|<<|>>)?="
        )
        # 匹配 NULL / nullptr 检查
        null_pattern = re.compile(
            rf"\b{re.escape(variable_name)}\s*(?:==|!=)\s*(?:NULL|nullptr|0)\b"
            rf"|\b(?:NULL|nullptr|0)\s*(?:==|!=)\s*{re.escape(variable_name)}\b"
        )

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if def_pattern.search(stripped):
                results[f"L{i}: {stripped}"] = "definition"
            elif assign_pattern.search(stripped):
                results[f"L{i}: {stripped}"] = "assignment"
            elif null_pattern.search(stripped):
                results[f"L{i}: {stripped}"] = "null_check"

        return results

    def find_null_checks(
        self, source: str, variable_name: str, start_line: int, end_line: int
    ) -> bool:
        """判断在 [start_line, end_line] 范围内是否存在对 variable_name 的非空检查"""
        lines = source.splitlines()
        null_pattern = re.compile(
            rf"\b{re.escape(variable_name)}\s*(?:==|!=)\s*(?:NULL|nullptr|0)\b"
            rf"|\b(?:NULL|nullptr|0)\s*(?:==|!=)\s*{re.escape(variable_name)}\b"
            rf"|if\s*\(\s*{re.escape(variable_name)}\s*\)"
            rf"|if\s*\(\s*!\s*{re.escape(variable_name)}\s*\)"
        )
        for i, line in enumerate(lines, start=1):
            if start_line <= i <= end_line and null_pattern.search(line):
                return True
        return False
