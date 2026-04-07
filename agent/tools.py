import json
import os
from typing import Dict, List, Optional
from models.finding import EnrichedFinding
from context.function_extractor import FunctionExtractor
from context.call_graph import CallGraphBuilder
from context.data_flow import DataFlowTracer
from context.cross_file_search import CrossFileSearcher


# Agent 可调用工具的定义（用于 LLM function calling）
TOOL_SCHEMAS = [
    {
        "name": "get_source_code",
        "description": "获取指定文件中指定行范围的源代码",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "文件绝对路径"},
                "start_line": {"type": "integer", "description": "起始行号（从1开始）"},
                "end_line":   {"type": "integer", "description": "结束行号"},
            },
            "required": ["file_path", "start_line", "end_line"],
        },
    },
    {
        "name": "get_function_context",
        "description": "获取指定函数的完整定义（包含函数签名和函数体）",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path":     {"type": "string"},
                "function_name": {"type": "string"},
            },
            "required": ["file_path", "function_name"],
        },
    },
    {
        "name": "find_variable_definition",
        "description": "在函数源码中追踪变量的定义位置、初始值和赋值语句",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path":     {"type": "string"},
                "function_name": {"type": "string", "description": "变量所在的函数名"},
                "variable_name": {"type": "string"},
            },
            "required": ["file_path", "function_name", "variable_name"],
        },
    },
    {
        "name": "get_callers",
        "description": "在同一文件中查找调用指定函数的所有调用点（调用者列表）",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path":     {"type": "string"},
                "function_name": {"type": "string"},
            },
            "required": ["file_path", "function_name"],
        },
    },
    {
        "name": "get_callees",
        "description": "获取指定函数内调用的所有函数名列表",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path":     {"type": "string"},
                "function_name": {"type": "string"},
            },
            "required": ["file_path", "function_name"],
        },
    },
    {
        "name": "search_null_checks",
        "description": "在函数源码中搜索对特定变量的空指针检查（if/assert/比较）",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path":     {"type": "string"},
                "function_name": {"type": "string"},
                "variable_name": {"type": "string"},
                "start_line":    {"type": "integer", "description": "搜索范围起始行"},
                "end_line":      {"type": "integer", "description": "搜索范围结束行"},
            },
            "required": ["file_path", "function_name", "variable_name"],
        },
    },
    {
        "name": "get_callers_cross_file",
        "description": "跨文件搜索调用指定函数的所有调用者（在整个项目目录中递归搜索）",
        "parameters": {
            "type": "object",
            "properties": {
                "function_name": {"type": "string", "description": "要搜索调用者的函数名"},
                "search_dir":    {"type": "string", "description": "搜索根目录（绝对路径）"},
                "max_files":     {"type": "integer", "description": "最多扫描文件数（默认 50）"},
            },
            "required": ["function_name", "search_dir"],
        },
    },
    {
        "name": "get_file_context",
        "description": "读取任意源文件或头文件的指定行范围内容（支持 .h/.hpp/.cpp 等）",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path":  {"type": "string", "description": "文件绝对路径"},
                "start_line": {"type": "integer", "description": "起始行号（默认 1）"},
                "end_line":   {"type": "integer", "description": "结束行号（默认 start_line+199）"},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "search_symbol",
        "description": "在项目目录中搜索宏定义、类型声明(class/struct/typedef/enum)、全局变量或函数声明",
        "parameters": {
            "type": "object",
            "properties": {
                "symbol_name": {"type": "string", "description": "要搜索的符号名（精确匹配）"},
                "search_dir":  {"type": "string", "description": "搜索根目录（绝对路径）"},
                "symbol_type": {"type": "string", "description": "过滤类型: macro|type|variable|function|any（默认 any）"},
            },
            "required": ["symbol_name", "search_dir"],
        },
    },
]


class ToolExecutor:
    """执行 Agent 调用的工具，返回观察结果字符串"""

    def __init__(self, libclang_path: str = "", compile_args: List[str] = None):
        self.compile_args = compile_args or ["-std=c++17"]
        from context.libclang_config import configure_libclang
        configure_libclang(libclang_path)
        self._extractor = FunctionExtractor()
        self._call_graph = CallGraphBuilder()
        self._data_flow = DataFlowTracer()
        self._cross_file = CrossFileSearcher()

    def execute(self, tool_name: str, args: Dict) -> str:
        try:
            handler = getattr(self, f"_tool_{tool_name}", None)
            if handler is None:
                return f"[错误] 未知工具: {tool_name}"
            return handler(**args)
        except Exception as e:
            return f"[工具执行错误] {tool_name}: {e}"

    def _tool_get_source_code(self, file_path: str, start_line: int, end_line: int) -> str:
        source = self._extractor._read_lines(file_path, start_line, end_line)
        if not source:
            return f"[无法读取] {file_path} L{start_line}-{end_line}"
        numbered = "\n".join(f"{start_line + i:4d} | {l}"
                             for i, l in enumerate(source.splitlines()))
        return f"```cpp\n{numbered}\n```"

    def _tool_get_function_context(self, file_path: str, function_name: str) -> str:
        # 简化：扫描文件找到函数名，提取整个函数体
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            return f"[无法读取] {file_path}"

        start = None
        for i, line in enumerate(lines, start=1):
            if function_name in line and ("(" in line):
                start = i
                break
        if start is None:
            return f"[未找到函数] {function_name} in {file_path}"

        _, source, s, e = self._extractor.extract_function(file_path, start, self.compile_args)
        if not source:
            return f"[无法提取函数体] {function_name}"
        return f"// {function_name} (L{s}-{e})\n```cpp\n{source}\n```"

    def _tool_find_variable_definition(self, file_path: str, function_name: str,
                                        variable_name: str) -> str:
        # 先扫描文件，找到 function_name 出现的行号（复用 get_function_context 的逻辑）
        start_line = 1
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f, start=1):
                    if function_name in line and "(" in line:
                        start_line = i
                        break
        except OSError:
            return f"[无法读取] {file_path}"

        _, source, func_start, func_end = self._extractor.extract_function(
            file_path, start_line, self.compile_args
        )
        if not source:
            return f"[无法提取函数] {function_name}"

        defs = self._data_flow.find_variable_definitions(source, variable_name)
        if not defs:
            return f"[未找到] 变量 '{variable_name}' 在函数 '{function_name}' 中没有定义或赋值语句"
        lines = [f"- [{reason}] {code}" for code, reason in defs.items()]
        return f"// '{function_name}' (L{func_start}-{func_end}) 中 '{variable_name}' 的定义/赋值:\n" + "\n".join(lines)

    def _tool_get_callers(self, file_path: str, function_name: str) -> str:
        callers = self._call_graph.get_callers(file_path, function_name, self.compile_args)
        if not callers:
            return f"[未找到] 在 {file_path} 中没有找到调用 '{function_name}' 的函数"
        return "调用者列表:\n" + "\n".join(f"- {c}" for c in callers)

    def _tool_get_callees(self, file_path: str, function_name: str) -> str:
        callees = self._call_graph.get_callees(file_path, function_name, self.compile_args)
        if not callees:
            return f"[未找到] '{function_name}' 内没有检测到函数调用"
        return "被调用函数列表:\n" + "\n".join(f"- {c}" for c in callees)

    def _tool_search_null_checks(self, file_path: str, function_name: str,
                                  variable_name: str,
                                  start_line: int = 1, end_line: int = 9999) -> str:
        _, source, func_start, _ = self._extractor.extract_function(
            file_path, start_line, self.compile_args
        )
        if not source:
            return f"[无法提取函数] {function_name}"
        found = self._data_flow.find_null_checks(source, variable_name, 1, end_line - func_start + 1)
        if found:
            return f"[找到] 在函数 '{function_name}' 中存在对 '{variable_name}' 的 NULL/nullptr 检查。"
        return f"[未找到] 在函数 '{function_name}' 的指定范围内没有找到对 '{variable_name}' 的空指针检查。"

    # ----------------------------------------------------------------
    # 新增工具：跨文件调用者追踪
    # ----------------------------------------------------------------
    def _tool_get_callers_cross_file(self, function_name: str, search_dir: str,
                                      max_files: int = 50) -> str:
        results = self._cross_file.find_callers(
            function_name, search_dir, self.compile_args, max_files
        )
        if not results:
            return f"[未找到] 在 {search_dir} 下（扫描最多 {max_files} 个文件）未找到调用 '{function_name}' 的函数"
        lines = []
        for fpath, callers in results.items():
            basename = os.path.basename(fpath)
            for caller in callers:
                lines.append(f"- {basename}: {caller}() 调用了 {function_name}()")
        return f"跨文件调用者（共 {len(lines)} 处）:\n" + "\n".join(lines)

    # ----------------------------------------------------------------
    # 新增工具：跨文件读取任意源文件/头文件
    # ----------------------------------------------------------------
    def _tool_get_file_context(self, file_path: str,
                                start_line: int = 1, end_line: int = 0) -> str:
        if end_line <= 0:
            end_line = start_line + 199  # 默认读200行
        # 限制单次最多读 500 行
        if end_line - start_line > 500:
            end_line = start_line + 500
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                all_lines = f.readlines()
        except OSError:
            return f"[无法读取] {file_path}"

        total = len(all_lines)
        start_line = max(1, start_line)
        end_line = min(total, end_line)
        selected = all_lines[start_line - 1:end_line]
        numbered = "\n".join(f"{start_line + i:4d} | {l.rstrip()}"
                             for i, l in enumerate(selected))
        header = f"// {os.path.basename(file_path)} (L{start_line}-{end_line}, 共 {total} 行)"
        return f"{header}\n```cpp\n{numbered}\n```"

    # ----------------------------------------------------------------
    # 新增工具：全局符号搜索
    # ----------------------------------------------------------------
    def _tool_search_symbol(self, symbol_name: str, search_dir: str,
                             symbol_type: str = "any") -> str:
        results = self._cross_file.search_symbol(
            symbol_name, search_dir, self.compile_args, symbol_type
        )
        if not results:
            return f"[未找到] 在 {search_dir} 下未找到符号 '{symbol_name}' 的定义/声明"
        lines = []
        seen = set()
        for r in results[:20]:  # 最多返回20条，防止上下文溢出
            key = (r["file"], r["line"])
            if key in seen:
                continue
            seen.add(key)
            basename = os.path.basename(r["file"])
            lines.append(f"- {basename}:{r['line']} [{r['kind']}]\n  {r['snippet']}")
        return f"符号 '{symbol_name}' 搜索结果（{len(lines)} 处）:\n" + "\n".join(lines)
