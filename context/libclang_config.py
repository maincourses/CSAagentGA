"""
libclang 全局配置模块。
确保 set_compatibility_check 和 set_library_file 只在首次调用时执行。
"""
import os
import clang.cindex as cindex

_configured = False


def configure_libclang(libclang_path: str = ""):
    """配置 libclang，保证全局只执行一次。"""
    global _configured
    if _configured:
        return
    cindex.Config.set_compatibility_check(False)
    if libclang_path and os.path.exists(libclang_path):
        cindex.Config.set_library_file(libclang_path)
    _configured = True
