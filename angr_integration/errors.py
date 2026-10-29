"""Errors at the boundary between the CAP pipeline and angr."""


class LoaderError(ValueError):
    pass


class DependencyError(RuntimeError):
    pass


class ExecutionNotReady(LoaderError):
    """Loading succeeded, but this method needs more execution support."""


class HeapError(LoaderError):
    """Invalid or unsupported heap operation; no Java handler is dispatched yet."""

    def __init__(self, code, message, *, condition=None):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.condition = condition

