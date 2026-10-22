"""Small integration overrides; instruction semantics remain angr's Soot engine.

Pinned to angr 10.0.4.post1. The stock engine skips SimEngineError statements and
fabricates returns for unloaded methods. Both behaviors are inappropriate for
verification, so this boundary propagates errors into SimulationManager.errored.
"""
from archinfo.arch_soot import SootAddressDescriptor, SootAddressTerminator

from angr import SimState, claripy
from angr.engines import UberEngine
from angr.engines.soot.statements import SimSootStmt_Return, SimSootStmt_ReturnVoid, translate_stmt
from angr.errors import SimEngineError
from angr.simos.javavm import SimJavaVM

from .errors import LoaderError


class CAPSimOS(SimJavaVM):
    def state_blank(self, addr=None, **kwargs):
        """Create Java frames without desktop System.in/out or implicit applet init."""
        address = addr if addr is not None else self.project.entry
        if not isinstance(address, SootAddressDescriptor) or isinstance(address, SootAddressTerminator):
            raise LoaderError("Choose a concrete CAP method before creating a state")
        self.project.loader.main_object.cap_index.source(address)
        kwargs.setdefault("mode", self.project._default_analysis_mode)
        kwargs.setdefault("os_name", self.name)
        state = SimState(project=self.project, **kwargs)
        state.regs._ip = address
        state.regs._ip_binary = self.project.loader.main_object
        state.regs._invoke_return_target = None
        state.regs._invoke_return_variable = None
        state.memory.push_stack_frame()
        frame = state.callstack.copy()
        frame.ret_addr = SootAddressTerminator()
        state.callstack.push(frame)
        return state


class CheckedSootEngine(UberEngine):
    def process_successors(self, successors, **kwargs):
        address = self.state._ip
        if not isinstance(address, SootAddressDescriptor):
            raise SimEngineError("The CAP loader does not enable native/JNI execution")
        if not isinstance(address, SootAddressTerminator):
            backend = self.project.loader.main_object
            try:
                key = backend.cap_index.key_for_descriptor(address.method)
                backend.cap_index.source(address)
                backend.cap_readiness.require(key)
            except LoaderError as exc:
                raise SimEngineError(str(exc)) from exc
        return super().process_successors(successors, **kwargs)

    def get_unconstrained_simprocedure(self):
        raise SimEngineError(f"Missing explicit method/API model: {self.state.addr.method}")

    def _handle_soot_stmt(self, state, successors, stmt_idx, stmt):
        # Mirrors SootMixin's invocation/jump/return protocol, but never catches
        # and skips an instruction. Expressions are translated once, by angr.
        try:
            translated = translate_stmt(stmt, state)
            if translated is None:
                raise SimEngineError(f"Unsupported statement {type(stmt).__name__}")
            if translated.has_invoke_target:
                invoke = translated.invoke_expr
                if not invoke.method.is_loaded or "NATIVE" in invoke.method.attrs:
                    raise SimEngineError(f"Missing explicit method/API model: {invoke.method}")
                invoke_state = state.copy()
                ret_addr = self._get_next_linear_instruction(state, stmt_idx)
                self.setup_callsite(invoke_state, invoke.args, ret_addr, getattr(invoke, "ret_var", None))
                successors.add_successor(invoke_state, SootAddressDescriptor(invoke.method, 0, 0),
                                         claripy.true(), "Ijk_Call")
                return True
            if translated.has_jump_targets:
                for target, condition in translated.jmp_targets_with_conditions:
                    if target is None:
                        target = self._get_next_linear_instruction(state, stmt_idx)
                    successors.add_successor(state.copy(), target, condition, "Ijk_Boring")
                return True
            if isinstance(translated, (SimSootStmt_Return, SimSootStmt_ReturnVoid)):
                self._add_return_exit(state, successors, translated.return_value)
                return True
            return False
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise SimEngineError(f"{state.addr.method}, Unit {stmt.label}: {exc}") from exc

