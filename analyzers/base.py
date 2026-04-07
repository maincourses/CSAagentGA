from abc import ABC, abstractmethod
from typing import List
from models.finding import RawFinding


class BaseAnalyzer(ABC):
    """静态分析工具封装基类"""

    def run(self, src_dir: str, compile_commands: str = "") -> List[RawFinding]:
        raw_output = self._execute(src_dir, compile_commands)
        return self._parse(raw_output, src_dir)

    @abstractmethod
    def _execute(self, src_dir: str, compile_commands: str) -> str: ...

    @abstractmethod
    def _parse(self, output: str, src_dir: str) -> List[RawFinding]: ...
