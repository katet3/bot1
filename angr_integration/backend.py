"""CLE backend for already constructed pysoot objects. No Lifter, JVM or JAR."""
from archinfo.arch_soot import ArchSoot
from cle.backends.backend import Backend
from cle.backends.java.soot import Soot


class CAPSootBackend(Soot):
    def __init__(self, program, index, readiness, entry_key=None, *, max_array_length=4096):
        # Deliberately initialize Backend, not Soot.__init__: the latter calls
        # pysoot.Lifter. Soot's lookup and address properties are reused unchanged.
        Backend.__init__(self, "cap2soot-memory", None, is_main_bin=True,
                         has_memory=False, arch=ArchSoot())
        self._classes = program.classes
        self._entry = index.entry(entry_key) if entry_key is not None else None
        self.os = "javavm"
        self.rebase_addr = None
        self.jni_support = False
        self.cap_program = program
        self.cap_index = index
        self.cap_readiness = readiness
        self.cap_api = readiness.api
        self.cap_heap_schema = readiness.heap_schema
        self.cap_max_array_length = max_array_length

