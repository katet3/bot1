"""Explicit install/command harness; persistent state is retained per path."""
from dataclasses import dataclass

from angr import claripy

from .errors import HeapError, LoaderError
from .javacard_api import FW, byte_values, integer


@dataclass(frozen=True)
class CommandFault:
    state: object
    error: Exception


@dataclass(frozen=True)
class CommandRun:
    completed: tuple
    errored: tuple
    active: tuple

    def summary(self):
        return {
            'completed': [{'sw': f'{integer(s, s.javacard.status, "status", signed=False):04X}',
                           'response_hex': byte_values(s, s.javacard.response, 'response').hex().upper(),
                           'exception': s.javacard.exception} for s in self.completed],
            'errors': [{'code': getattr(r.error, 'code', type(r.error).__name__),
                        'message': str(r.error),
                        'source': r.error.source.to_dict() if hasattr(r.error, 'source') else None}
                       for r in self.errored],
            'active_paths': len(self.active),
        }


class JavaCardSession:
    """One installed applet and one logical channel; no power-loss emulation."""
    def __init__(self, loaded):
        if loaded.readiness.api is None:
            raise LoaderError('JavaCardSession requires an explicit API profile')
        if len(loaded.program.metadata.applets) != 1:
            raise LoaderError('This harness requires exactly one CAP applet')
        self.loaded = loaded
        self.applet = loaded.program.metadata.applets[0]
        self.aid = bytes.fromhex(self.applet.aid)
        self.state = None
        self.process_key = None

    def run(self, state, *, max_steps=500):
        if type(max_steps) is not int or max_steps < 1:
            raise LoaderError('max_steps must be a positive integer')
        manager = self.loaded.project.factory.simgr(state).run(n=max_steps)
        completed, errors = [], list(manager.errored)
        for end in manager.deadended:
            if end.javacard.transaction is not None:
                end.javacard.abort()
                if end.javacard.exception is None:
                    # JCRE 7.6.2: returning with an open transaction is treated
                    # as an uncaught exception, never as successful SW=9000.
                    end.javacard.exception = 'uncommitted_transaction'
                    errors.append(CommandFault(end, HeapError('uncommitted_transaction',
                        'Applet returned with an open transaction; rolled back at the command boundary')))
                    continue
            if end.javacard.status is None:
                end.javacard.status = claripy.BVV(0x9000, 16)
            completed.append(end)
        return CommandRun(tuple(completed), tuple(errors), tuple(manager.active))

    def install(self, *, max_steps=500):
        if self.state is not None:
            raise LoaderError('Applet is already installed in this session')
        base = self.loaded.create_heap_state(self.applet.install_method_key)
        base.javacard.installing = True
        # AID length + AID + zero control-info length + zero applet-data length.
        data = bytes([len(self.aid)]) + self.aid + b'\x00\x00'
        array = base.cap_heap.new_array('byte', len(data))
        base.cap_heap.write_slice(array, 0, data)
        state = self.loaded.create_call_state(self.applet.install_method_key,
                                             [array, 0, len(data)], base_state=base)
        result = self.run(state, max_steps=max_steps)
        if result.errored or result.active or len(result.completed) != 1:
            raise LoaderError(f'Installation did not complete: {result.summary()}')
        end = result.completed[0]
        if end.javacard.exception or set(end.javacard.registrations) != {self.aid}:
            raise LoaderError('install failed or registered an unexpected AID')
        end.javacard.installing = False
        receiver = end.javacard.registrations[self.aid]
        self.process_key = self.loaded.index.by_signature.get((receiver.type, 'process', (FW+'APDU',)))
        if self.process_key is None:
            raise LoaderError('No bound process(APDU) method for the registered applet')
        self.state = end
        return result

    @staticmethod
    def _byte(value):
        if type(value) is int and 0 <= value <= 255:
            return value
        if isinstance(value, claripy.ast.BV) and value.size() == 8:
            return value
        raise LoaderError('APDU bytes must be integers 0..255 or 8-bit bitvectors')

    def prepare_command(self, ins, p1=0, p2=0, data=b'', *, cla=0, selecting=False, receive_length=None):
        if self.state is None:
            raise LoaderError('Run install before preparing an APDU')
        data = tuple(self._byte(b) for b in data)
        if len(data) > 255:
            raise LoaderError('Only short APDUs with up to 255 incoming bytes are supported')
        count = len(data) if receive_length is None else receive_length
        if type(count) is not int or not 0 <= count <= len(data):
            raise LoaderError('receive_length must be between zero and the supplied data length')
        # A new command is a fresh JCRE entry, not a continuation of a terminated
        # Java frame. In particular an earlier ISOException may leave Ijk_Exit
        # and several abandoned frames in its diagnostic state.
        base = self.loaded.create_heap_state(self.process_key)
        base.register_plugin('cap_heap', self.state.cap_heap.copy({}))
        base.register_plugin('javacard', self.state.javacard.copy({}))
        base.solver.add(*self.state.solver.constraints)
        card, heap = base.javacard, base.cap_heap
        if card.apdu is None:
            card.apdu = heap.new_object(FW+'APDU')
            card.buffer = heap.new_array('byte', 260)
            card.transient_arrays |= {card.buffer.allocation_id}
            card.global_references |= {card.apdu.allocation_id, card.buffer.allocation_id}
        # The Java Card APDU contract clears the entire buffer for each command.
        heap.write_slice(card.buffer, 0, (0,) * 260)
        heap.write_slice(card.buffer, 0, [self._byte(x) for x in (cla, ins, p1, p2, len(data))])
        card.incoming = tuple(heap.normalize(v, 'byte') for v in data)
        card.receive_length = count
        card.selecting = bool(selecting)
        card.received = card.sent = False
        card.response, card.events = (), ()
        card.status = card.exception = None
        receiver = card.registrations[self.aid]
        return self.loaded.create_call_state(self.process_key, [card.apdu], receiver=receiver, base_state=base)

    def transmit(self, ins, p1=0, p2=0, data=b'', *, max_steps=500, **kwargs):
        result = self.run(self.prepare_command(ins, p1, p2, data, **kwargs), max_steps=max_steps)
        # Never choose an arbitrary symbolic outcome, discard a fault, or treat a
        # step-budget cutoff as completion. Forked paths remain available to callers.
        if len(result.completed) == 1 and not result.errored and not result.active:
            self.state = result.completed[0]
        return result

    def choose(self, completed_state):
        if completed_state.project is not self.loaded.project or not completed_state.has_plugin('javacard'):
            raise LoaderError('State belongs to another session/project')
        from archinfo.arch_soot import SootAddressTerminator
        if not isinstance(completed_state.addr, SootAddressTerminator) or completed_state.javacard.status is None:
            raise LoaderError('Choose only a completed command state')
        self.state = completed_state.copy()
