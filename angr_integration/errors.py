"""Errors at the boundary between the CAP pipeline and angr."""


class LoaderError(ValueError):
    pass


class DependencyError(RuntimeError):
    pass


class ExecutionNotReady(LoaderError):
    """Loading succeeded, but this method needs more execution support."""

