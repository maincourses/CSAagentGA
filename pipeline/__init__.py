"""
Pipeline package.

Keep package import side effects minimal so submodules can be imported
independently in CI and tooling contexts.
"""

__all__ = ["runner", "report_generator"]
