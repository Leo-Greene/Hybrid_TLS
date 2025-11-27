"""TLS实现模块"""

# 延迟导入避免循环依赖
__all__ = [
    'ServerConfig',
    'ClientConfig',
]

def __getattr__(name):
    if name in __all__:
        from .config import ServerConfig, ClientConfig
        return locals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

