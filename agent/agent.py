import time
from typing import Dict, List

from models.finding import EnrichedFinding
from models.report import DefectReport

from .llm_client import LLMClient
from .prompts import SYSTEM_PROMPT, build_initial_prompt
from .tools import TOOL_SCHEMAS, ToolExecutor
from .verdict import VerdictResult, parse_verdict


class DefectVerificationAgent:
    """
    ReAct agent loop:
    Thought -> Tool Call -> Observation -> ... -> Final Verdict
    """

    def __init__(
        self,
        llm_config: Dict,
        agent_config: Dict,
        libclang_path: str = "",
        compile_args: List[str] = None,
    ):
        self.llm = LLMClient(llm_config)
        self.max_steps = self._normalize_max_steps(agent_config.get("max_steps", 8))
        self.confidence_threshold = self._normalize_threshold(
            agent_config.get("confidence_threshold", 0.7)
        )
        self.tool_executor = ToolExecutor(libclang_path, compile_args)

    @staticmethod
    def _normalize_max_steps(value) -> int:
        try:
            steps = int(value)
        except (TypeError, ValueError):
            steps = 8
        return max(1, steps)

    @staticmethod
    def _normalize_threshold(value) -> float:
        try:
            threshold = float(value)
        except (TypeError, ValueError):
            threshold = 0.7
        return max(0.0, min(1.0, threshold))

    def _apply_confidence_threshold(self, verdict_result: VerdictResult) -> VerdictResult:
        """
        If model predicts TP/FP but confidence is below threshold,
        downgrade verdict to UNCERTAIN.
        """
        if verdict_result.verdict in ("TRUE_POSITIVE", "FALSE_POSITIVE"):
            if verdict_result.confidence < self.confidence_threshold:
                verdict_result.reasoning.append(
                    f"Confidence {verdict_result.confidence:.2f} is below threshold "
                    f"{self.confidence_threshold:.2f}; downgrade to UNCERTAIN."
                )
                verdict_result.verdict = "UNCERTAIN"
        return verdict_result

    def _build_report(
        self,
        finding: EnrichedFinding,
        verdict_result: VerdictResult,
        tool_calls_log: List[Dict],
        start_time: float,
        tokens_used: int,
    ) -> DefectReport:
        return DefectReport(
            finding=finding,
            verdict=verdict_result.verdict,
            confidence=verdict_result.confidence,
            reasoning_chain=verdict_result.reasoning,
            tool_calls_log=tool_calls_log,
            fixed_code=verdict_result.fixed_code,
            fix_explanation=verdict_result.fix_explanation,
            processing_time=time.time() - start_time,
            llm_tokens_used=tokens_used,
        )

    def verify(self, finding: EnrichedFinding) -> DefectReport:
        start_time = time.time()
        tool_calls_log: List[Dict] = []
        tokens_used = 0

        finding_info = self._format_finding_info(finding)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": build_initial_prompt(
                    finding_info,
                    defect_id=finding.raw.defect_id,
                    cwe=finding.raw.cwe or "",
                ),
            },
        ]

        for step in range(self.max_steps):
            response = self.llm.chat(messages, tools=TOOL_SCHEMAS)
            tokens_used += response.get("tokens_used", 0)
            content = response.get("content", "")
            tool_calls = response.get("tool_calls", [])

            if content:
                messages.append({"role": "assistant", "content": content})

            if response.get("is_final_answer"):
                verdict_result = self._apply_confidence_threshold(parse_verdict(content))
                return self._build_report(
                    finding,
                    verdict_result,
                    tool_calls_log,
                    start_time,
                    tokens_used,
                )

            if tool_calls:
                for tc in tool_calls:
                    observation = self.tool_executor.execute(tc["name"], tc["args"])
                    tool_calls_log.append(
                        {
                            "step": step,
                            "tool": tc["name"],
                            "args": tc["args"],
                            "observation": observation,
                        }
                    )
                    messages.append(
                        {
                            "role": "user",
                            "content": f"[Tool Result: {tc['name']}]\n{observation}",
                        }
                    )
            else:
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Please provide the final verdict now in the required format."
                        ),
                    }
                )

        messages.append(
            {
                "role": "user",
                "content": (
                    "You have reached max reasoning steps. "
                    "Do not call tools anymore; output final VERDICT format immediately."
                ),
            }
        )
        response = self.llm.chat(messages, tools=None)
        tokens_used += response.get("tokens_used", 0)
        content = response.get("content", "")

        if content:
            verdict_result = self._apply_confidence_threshold(parse_verdict(content))
            return self._build_report(
                finding,
                verdict_result,
                tool_calls_log,
                start_time,
                tokens_used,
            )

        return DefectReport(
            finding=finding,
            verdict="UNCERTAIN",
            confidence=0.3,
            reasoning_chain=["Exceeded max steps without final parsable verdict."],
            tool_calls_log=tool_calls_log,
            processing_time=time.time() - start_time,
            llm_tokens_used=tokens_used,
        )

    def _format_finding_info(self, finding: EnrichedFinding) -> str:
        raw = finding.raw
        lines = [
            f"**Tool**: {raw.tool}",
            f"**File**: {raw.file_path}",
            f"**Location**: line {raw.line}, column {raw.column}",
            f"**Severity**: {raw.severity}",
            f"**Defect Type**: {raw.defect_id}" + (f" ({raw.cwe})" if raw.cwe else ""),
            f"**Message**: {raw.message}",
        ]
        if finding.corroborating_tools:
            lines.append(f"**Corroborating Tools**: {', '.join(finding.corroborating_tools)}")

        if finding.function_name:
            lines.append(f"\n**Function**: `{finding.function_name}`")
        if finding.function_source:
            lines.append(f"\n**Function Source**:\n```cpp\n{finding.function_source}\n```")
        if finding.surrounding_context and not finding.function_source:
            lines.append(
                f"\n**Surrounding Context**:\n```cpp\n{finding.surrounding_context}\n```"
            )
        if finding.callers:
            lines.append(f"\n**Callers**: {', '.join(finding.callers[:5])}")
        if finding.callees:
            lines.append(f"\n**Callees**: {', '.join(finding.callees[:5])}")
        if finding.variable_definitions:
            defs_str = "\n".join(
                f"  {code} [{reason}]" for code, reason in finding.variable_definitions.items()
            )
            lines.append(f"\n**Variable Definitions/Assignments**:\n{defs_str}")

        return "\n".join(lines)
