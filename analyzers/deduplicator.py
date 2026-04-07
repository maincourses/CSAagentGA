from typing import List, Dict, Tuple
from models.finding import RawFinding


class Deduplicator:
   
    def deduplicate(self, findings: List[RawFinding]) -> List[RawFinding]:
        groups: Dict[str, List[RawFinding]] = {}

        for f in findings:
            key = self._group_key(f, groups)
            groups.setdefault(key, []).append(f)

        result = []
        for group in groups.values():
            merged = self._merge(group)
            result.append(merged)

        return result

    def _group_key(self, f: RawFinding, existing: Dict) -> str:
        # 先尝试与已有 key 合并（行号相近）
        for key in existing:
            parts = key.split("::")
            if parts[0] == f.file_path and parts[2] == (f.cwe or f.defect_id):
                existing_line = int(parts[1])
                if abs(existing_line - f.line) <= 3:
                    return key
        return f"{f.file_path}::{f.line}::{f.cwe or f.defect_id}"

    def _merge(self, group: List[RawFinding]) -> RawFinding:
        """保留第一个作为主 Finding，将其他工具来源记入 extra"""
        primary = group[0]
        corroborating = [f.tool for f in group[1:]]
        primary.extra["corroborating_tools"] = corroborating
        return primary
