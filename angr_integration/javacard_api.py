"""Explicit, bounded Java Card API models used by the supplied name1 applet.

Single applet/channel, short APDUs, transient DES keys and concrete DES data.
This is an analysis model, not the supplied native firmware or a complete JCRE.
"""
from dataclasses import dataclass, replace

from angr import claripy
from angr.errors import SimMergeError
from angr.state_plugins import SimStatePlugin

from pysoot_adapter import ClassMetadata
from .errors import DependencyError, HeapError


FW = 'javacard.framework.'
SEC = 'javacard.security.'
CIPHER = 'javacardx.crypto.Cipher'
KEY_IMPL = 'cap2soot.api.TransientDESKey'
CIPHER_IMPL = 'cap2soot.api.DESCipher'


class ISOExit(Exception):
    """Uncaught ISOException at the command boundary (no Java catch dispatch)."""
    def __init__(self, status):
        self.status = status


@dataclass(frozen=True)
class APIModel:
    key: str
    owner: str
    name: str
    params: tuple[str, ...]
    returns: str
    static: bool
    handler: str
    token: int | None = None


@dataclass(frozen=True)
class DESKeyState:
    bits: int
    data: tuple | None = None
    version: int = 0


@dataclass(frozen=True)
class CipherState:
    algorithm: int
    key: object | None = None
    key_version: int = -1
    mode: int = 0
    iv: tuple = (0,) * 8


class JavaCardState(SimStatePlugin):
    def __init__(self):
        super().__init__()
        self.installing = False
        self.constructed = frozenset()
        self.registrations = {}
        self.selecting = False
        self.apdu = self.buffer = None
        self.incoming = ()
        self.receive_length = 0
        self.received = self.sent = False
        self.response = ()
        self.status = None
        self.exception = None
        self.keys = {}
        self.ciphers = {}
        self.deletion_requested = False
        self.transaction = None
        self.transient_arrays = frozenset()
        self.global_references = frozenset()
        self.events = ()

    @SimStatePlugin.memo
    def copy(self, memo):
        result = JavaCardState()
        # All values except these dictionaries are immutable, including snapshots.
        for name, value in self.__dict__.items():
            if name != 'state':
                setattr(result, name, value.copy() if isinstance(value, dict) else value)
        return result

    def merge(self, others, merge_conditions, common_ancestor=None):
        raise SimMergeError('Java Card API state merging is not implemented')

    def widen(self, others):
        raise SimMergeError('Java Card API state widening is not implemented')

    def event(self, name):
        self.events += (name,)

    def begin(self):
        if self.transaction is not None:
            raise HeapError('transaction_in_progress', 'TransactionException.IN_PROGRESS')
        self.transaction = self.state.cap_heap.transaction_snapshot(self.transient_arrays)
        self.event('beginTransaction')

    def commit(self):
        if self.transaction is None:
            raise HeapError('transaction_not_in_progress', 'TransactionException.NOT_IN_PROGRESS')
        self.transaction = None
        self.event('commitTransaction')

    def abort(self):
        if self.transaction is None:
            raise HeapError('transaction_not_in_progress', 'TransactionException.NOT_IN_PROGRESS')
        self.state.cap_heap.restore_transaction(self.transaction)
        self.transaction = None
        self.event('abortTransaction')

    def deselect(self):
        if self.transaction is not None:
            self.abort()
        self.keys = {k: replace(v, data=None, version=v.version + 1) for k, v in self.keys.items()}
        self.selecting = False
        self.event('clearTransientKeysOnDeselect')


def integer(state, value, label, *, signed=True):
    if type(value) is int:
        return value
    if not isinstance(value, claripy.ast.BV):
        raise HeapError('api_argument', f'{label}: expected integer bitvector')
    possible = state.solver.eval_upto(value, 2)
    if len(possible) != 1:
        raise HeapError('symbolic_api_argument', f'{label} must be uniquely determined; no concretization performed')
    result = possible[0]
    return result - (1 << value.size()) if signed and result & (1 << (value.size() - 1)) else result


def byte_values(state, values, label):
    return bytes(integer(state, v[7:0] if isinstance(v, claripy.ast.BV) else v, label, signed=False) & 255
                 for v in values)


def des_crypt(data, key, mode, algorithm, iv):
    """DES and EDE 2/3-key DES; primitive composition permits degenerate keys."""
    from Crypto.Cipher import DES
    if len(key) not in (8, 16, 24) or len(data) % 8 or len(iv) != 8 or mode not in (1, 2) or algorithm not in (1, 5):
        raise HeapError('crypto_arguments', 'Invalid DES profile arguments')
    k1 = DES.new(key[:8], DES.MODE_ECB)
    k2 = DES.new(key[8:16], DES.MODE_ECB) if len(key) > 8 else None
    k3 = DES.new(key[16:24] if len(key) == 24 else key[:8], DES.MODE_ECB) if k2 else None
    def transform(block):
        if mode == 2:
            return k3.encrypt(k2.decrypt(k1.encrypt(block))) if k2 else k1.encrypt(block)
        return k1.decrypt(k2.encrypt(k3.decrypt(block))) if k2 else k1.decrypt(block)
    output, chain = bytearray(), iv
    for offset in range(0, len(data), 8):
        block = data[offset:offset + 8]
        if algorithm == 1 and mode == 2:
            encoded = transform(bytes(a ^ b for a, b in zip(block, chain, strict=True)))
            chain = encoded
        elif algorithm == 1:
            encoded = bytes(a ^ b for a, b in zip(transform(block), chain, strict=True))
            chain = block
        else:
            encoded = transform(block)
        output.extend(encoded)
    return bytes(output)


class Name1API:
    name = 'name1-jc304-subset-v1'
    classes = (
        ClassMetadata(FW + 'Applet', 'java.lang.Object', attrs=('PUBLIC', 'ABSTRACT')),
        ClassMetadata(FW + 'APDU', 'java.lang.Object', attrs=('PUBLIC', 'FINAL')),
        ClassMetadata(SEC + 'Key', 'java.lang.Object', attrs=('PUBLIC', 'INTERFACE')),
        ClassMetadata(SEC + 'SecretKey', 'java.lang.Object', (SEC + 'Key',), ('PUBLIC', 'INTERFACE')),
        ClassMetadata(SEC + 'DESKey', 'java.lang.Object', (SEC + 'SecretKey',), ('PUBLIC', 'INTERFACE')),
        ClassMetadata(CIPHER, 'java.lang.Object', attrs=('PUBLIC', 'ABSTRACT')),
        ClassMetadata(KEY_IMPL, 'java.lang.Object', (SEC + 'DESKey',), ('FINAL',)),
        ClassMetadata(CIPHER_IMPL, CIPHER, attrs=('FINAL',)),
    )

    def __init__(self):
        try:
            from Crypto.Cipher import DES  # noqa: F401 -- verify the optional concrete backend.
        except (ImportError, OSError) as exc:
            raise DependencyError('DES backend unavailable; install requirements-javacard.txt in the active environment') from exc
        self.models = {}
        def add(package, cls, tag, token, owner, name, params, ret, static, handler):
            key = f'{package}@1.5:c{cls}:t{tag}:m{token}'
            self.models[key] = APIModel(key, owner, name, tuple(params), ret, static, handler,
                                       None if static or name == '<init>' else token)
        fw, sec, crypto = 'a0000000620101', 'a0000000620102', 'a0000000620201'
        add(fw, 3, 6, 0, FW+'Applet', '<init>', (), 'void', False, 'applet_init')
        add(fw, 3, 3, 2, FW+'Applet', 'register', ('byte[]','short','byte'), 'void', False, 'register')
        add(fw, 3, 3, 3, FW+'Applet', 'selectingApplet', (), 'boolean', False, 'selecting')
        add(fw, 10, 3, 1, FW+'APDU', 'getBuffer', (), 'byte[]', False, 'get_buffer')
        add(fw, 10, 3, 6, FW+'APDU', 'setIncomingAndReceive', (), 'short', False, 'receive')
        add(fw, 10, 3, 8, FW+'APDU', 'setOutgoingAndSend', ('short','short'), 'void', False, 'send')
        add(fw, 7, 6, 1, FW+'ISOException', 'throwIt', ('short',), 'void', True, 'throw_iso')
        add(fw, 8, 6, 1, FW+'JCSystem', 'beginTransaction', (), 'void', True, 'begin')
        add(fw, 8, 6, 2, FW+'JCSystem', 'commitTransaction', (), 'void', True, 'commit')
        add(fw, 8, 6, 18, FW+'JCSystem', 'requestObjectDeletion', (), 'void', True, 'request_deletion')
        add(fw, 16, 6, 1, FW+'Util', 'arrayCopy', ('byte[]','short','byte[]','short','short'), 'short', True, 'array_copy')
        add(sec, 13, 6, 0, SEC+'KeyBuilder', 'buildKey', ('byte','short','boolean'), SEC+'Key', True, 'build_key')
        add(sec, 10, 1, 5, SEC+'DESKey', 'setKey', ('byte[]','short'), 'void', False, 'set_key')
        add(crypto, 1, 6, 0, CIPHER, 'getInstance', ('byte','boolean'), CIPHER, True, 'cipher_instance')
        add(crypto, 1, 3, 3, CIPHER, 'init', (SEC+'Key','byte'), 'void', False, 'cipher_init')
        add(crypto, 1, 3, 4, CIPHER, 'init', (SEC+'Key','byte','byte[]','short','short'), 'void', False, 'cipher_init')
        add(crypto, 1, 3, 1, CIPHER, 'doFinal', ('byte[]','short','short','byte[]','short'), 'short', False, 'cipher_final')

    def lookup(self, ref):
        model = self.models.get(ref.key)
        if model and (model.owner, model.name, model.params, model.returns, model.static) != (
                ref.owner, ref.name, tuple(ref.params), ref.returns, ref.is_static):
            raise HeapError('api_binding', f'API name/signature disagrees with token identity: {ref.key}')
        return model

    def accepts_receiver(self, model, actual, schema):
        expected = {FW+'APDU': FW+'APDU', SEC+'DESKey': KEY_IMPL, CIPHER: CIPHER_IMPL}
        if model.owner in expected:
            return actual == expected[model.owner]
        return model.owner == FW+'Applet' and schema.assignable(actual, model.owner)

    @staticmethod
    def _slice(state, array, offset, length):
        state.cap_heap.validate_reference(array, 'byte[]', nullable=False)
        return state.cap_heap.read_slice(array, offset, length)

    def invoke(self, state, model, receiver, args):
        h, card = state.cap_heap, state.javacard
        card.event(model.owner + '.' + model.name)
        if not model.static:
            h.validate_reference(receiver, model.owner, nullable=False)
        return getattr(self, '_'+model.handler)(state, receiver, *args)

    def _applet_init(self, state, receiver):
        if not state.javacard.installing:
            raise HeapError('applet_lifecycle', 'Applet construction requires an installation context')
        state.javacard.constructed |= {receiver.allocation_id}

    def _register(self, state, receiver, array, offset, length):
        card = state.javacard
        if not card.installing or receiver.allocation_id not in card.constructed:
            raise HeapError('applet_lifecycle', 'register requires a constructed applet during install')
        off, count = integer(state, offset, 'AID offset'), integer(state, length, 'AID length')
        if not 5 <= count <= 16:
            raise HeapError('applet_aid', 'Registration AID must contain 5..16 bytes')
        aid = byte_values(state, self._slice(state, array, off, count), 'registration AID')
        if card.registrations:
            raise HeapError('applet_lifecycle', 'This profile supports one registration per installation')
        card.registrations[aid] = receiver

    def _selecting(self, state, receiver):
        return int(state.javacard.selecting)

    def _get_buffer(self, state, receiver):
        if receiver != state.javacard.apdu:
            raise HeapError('apdu_context', 'Only the current APDU object is supported')
        return state.javacard.buffer

    def _receive(self, state, receiver):
        self._get_buffer(state, receiver)
        card = state.javacard
        if card.received or card.sent:
            raise HeapError('apdu_illegal_use', 'APDUException.ILLEGAL_USE')
        state.cap_heap.write_slice(card.buffer, 5, card.incoming[:card.receive_length])
        card.received = True
        return card.receive_length

    def _send(self, state, receiver, offset, length):
        self._get_buffer(state, receiver)
        card = state.javacard
        off, count = integer(state, offset, 'outgoing offset'), integer(state, length, 'outgoing length')
        if card.sent or count < 0 or count > 256:
            raise HeapError('apdu_illegal_use', 'Invalid short APDU outgoing state or length')
        card.response = self._slice(state, card.buffer, off, count)
        card.sent = True

    def _throw_iso(self, state, receiver, status):
        raise ISOExit(status[15:0])

    def _begin(self, state, receiver):
        state.javacard.begin()

    def _commit(self, state, receiver):
        state.javacard.commit()

    def _request_deletion(self, state, receiver):
        state.javacard.deletion_requested = True

    def _array_copy(self, state, receiver, source, source_offset, dest, dest_offset, length):
        src, dst, count = (integer(state, v, label) for v, label in
                           ((source_offset, 'copy source offset'), (dest_offset, 'copy destination offset'), (length, 'copy length')))
        # Snapshot all source elements before writing, including overlapping arrays.
        values = self._slice(state, source, src, count)
        self._slice(state, dest, dst, count)
        state.cap_heap.write_slice(dest, dst, values)
        return dst + count

    def _build_key(self, state, receiver, key_type, size, encryption):
        kind, bits, encrypted = (integer(state, v, label) for v, label in
                                 ((key_type, 'key type'), (size, 'key size'), (encryption, 'key encryption')))
        if kind != 2 or bits not in (64, 128, 192) or encrypted:
            raise HeapError('api_unsupported', 'Only plain TYPE_DES_TRANSIENT_DESELECT keys of 64/128/192 bits are modeled')
        ref = state.cap_heap.new_object(KEY_IMPL)
        state.javacard.keys[ref.allocation_id] = DESKeyState(bits)
        return ref

    def _set_key(self, state, receiver, array, offset):
        key = state.javacard.keys.get(receiver.allocation_id)
        if key is None:
            raise HeapError('api_object', 'DES key was not created by KeyBuilder model')
        data = self._slice(state, array, integer(state, offset, 'key offset'), key.bits // 8)
        state.javacard.keys[receiver.allocation_id] = replace(key, data=data, version=key.version + 1)

    def _cipher_instance(self, state, receiver, algorithm, external):
        alg = integer(state, algorithm, 'cipher algorithm')
        if alg not in (1, 5) or integer(state, external, 'externalAccess'):
            raise HeapError('api_unsupported', 'Only private DES ECB/CBC NOPAD ciphers are modeled')
        ref = state.cap_heap.new_object(CIPHER_IMPL)
        state.javacard.ciphers[ref.allocation_id] = CipherState(alg)
        return ref

    def _cipher_init(self, state, receiver, key_ref, mode, *params):
        state.cap_heap.validate_reference(key_ref, SEC+'DESKey', nullable=False)
        key = state.javacard.keys.get(key_ref.allocation_id)
        cipher = state.javacard.ciphers.get(receiver.allocation_id)
        if key is None or cipher is None:
            raise HeapError('api_object', 'Cipher/key was not created by the API model')
        if key.data is None:
            raise HeapError('crypto_uninitialized_key', 'CryptoException.UNINITIALIZED_KEY')
        mode = integer(state, mode, 'cipher mode')
        if mode not in (1, 2):
            raise HeapError('crypto_illegal_value', 'CryptoException.ILLEGAL_VALUE: mode')
        iv = (0,) * 8
        if params:
            array, offset, length = params
            if cipher.algorithm != 1 or integer(state, length, 'IV length') != 8:
                raise HeapError('crypto_illegal_value', 'DES CBC requires an 8-byte IV')
            iv = self._slice(state, array, integer(state, offset, 'IV offset'), 8)
        state.javacard.ciphers[receiver.allocation_id] = replace(cipher, key=key_ref,
            key_version=key.version, mode=mode, iv=iv)

    def _cipher_final(self, state, receiver, source, source_offset, length, dest, dest_offset):
        cipher = state.javacard.ciphers.get(receiver.allocation_id)
        if cipher is None or cipher.key is None:
            raise HeapError('crypto_invalid_init', 'CryptoException.INVALID_INIT')
        key = state.javacard.keys[cipher.key.allocation_id]
        if key.data is None:
            raise HeapError('crypto_uninitialized_key', 'CryptoException.UNINITIALIZED_KEY')
        if key.version != cipher.key_version:
            raise HeapError('api_unspecified', 'Key changed after Cipher.init; API behavior is unspecified')
        src, count, dst = (integer(state, v, label) for v, label in
                           ((source_offset, 'cipher input offset'), (length, 'cipher input length'), (dest_offset, 'cipher output offset')))
        if count < 0 or count % 8:
            raise HeapError('crypto_illegal_use', 'CryptoException.ILLEGAL_USE: DES input is not block aligned')
        data = self._slice(state, source, src, count)
        self._slice(state, dest, dst, count)
        output = des_crypt(byte_values(state, data, 'DES input'), byte_values(state, key.data, 'DES key'),
                           cipher.mode, cipher.algorithm, byte_values(state, cipher.iv, 'DES IV'))
        state.cap_heap.write_slice(dest, dst, output)
        # doFinal restores default IV (zero), even after init with an explicit IV.
        state.javacard.ciphers[receiver.allocation_id] = replace(cipher, iv=(0,) * 8)
        return len(output)
