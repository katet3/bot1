"""Errors at the boundary between our IR and the pysoot object model."""


class AdapterError(ValueError):
    pass


class DependencyError(RuntimeError):
    pass
