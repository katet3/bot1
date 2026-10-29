"""Path-local Java heap. Allocation is explicit; no API or persistence stubs.

Locals/call frames stay in angr's Java memory. All object/array data lives in
this plugin so stock lazy initialization and index concretization cannot hide
faults. Immutable values and replacement writes make state.copy() independent.
"""
from dataclasses import dataclass
from uuid import uuid4

from angr import claripy
from angr.errors import SimMergeError
from angr.state_plugins import SimStatePlugin
from archinfo.arch_soot import SootNullConstant

from .errors import HeapError
from .heap_types import PRIMITIVES, is_reference_type, is_value_type


@dataclass(frozen=True)
class HeapReference:
    allocation_id: str
    type: str  # Actual allocated type, never changed by checkcast.


@dataclass(frozen=True)
class _Array:
    element_type: str
    values: tuple


class CAPHeap(SimStatePlugin):
    def __init__(self, schema, max_array_length=4096):
        super().__init__()
        self.schema = schema
        self.max_array_length = max_array_length
        self._references = {}
        self._fields = {}
        self._arrays = {}

    @SimStatePlugin.memo
    def copy(self, memo):
        result = CAPHeap(self.schema, self.max_array_length)
        result._references = self._references.copy()
        result._fields = self._fields.copy()
        result._arrays = self._arrays.copy()
        return result

    def merge(self, others, merge_conditions, common_ancestor=None):
        raise SimMergeError("CAP heap merging is not implemented; keep paths separate")

    def widen(self, others):
        raise SimMergeError("CAP heap widening is not implemented; keep paths separate")

    def _require(self, condition, code, message):
        if self.state.solver.satisfiable(extra_constraints=[~condition]):
            # Do not add the opposite constraint or select a convenient model.
            raise HeapError(code, message, condition=~condition)

    @staticmethod
    def default(type_):
        if type_ in PRIMITIVES:
            return claripy.BVV(0, 32)
        if is_reference_type(type_):
            return SootNullConstant()
        raise HeapError("value_type", f"Unsupported type {type_}")

    def validate_reference(self, ref, expected=None, *, nullable=True):
        if isinstance(ref, SootNullConstant):
            if nullable:
                return ref
            raise HeapError("null_reference", "Null dereference (java.lang.NullPointerException)")
        if not isinstance(ref, HeapReference) or self._references.get(ref.allocation_id) != ref:
            raise HeapError("foreign_reference", "Reference was not allocated in this state's CAP heap")
        if expected is not None and not self.schema.assignable(ref.type, expected):
            raise HeapError("reference_type", f"Cannot use {ref.type} as {expected}")
        return ref

    def normalize(self, value, type_):
        """Normalize storage to the declared width, then extend to Soot int32."""
        if is_reference_type(type_):
            return self.validate_reference(SootNullConstant() if value is None else value, type_)
        if type_ not in PRIMITIVES:
            raise HeapError("value_type", f"Unsupported storage type {type_}")
        if isinstance(value, int):
            if not -(1 << 31) <= value < (1 << 32):
                raise HeapError("value_width", "Primitive storage requires at most 32 bits")
            value = claripy.BVV(value & 0xffffffff, 32)
        if not isinstance(value, claripy.ast.BV) or value.size() not in {1, 8, 16, 32}:
            raise HeapError("value_width", f"Expected a 1/8/16/32-bit value for {type_}")
        if value.size() < 32:
            value = value.zero_extend(32 - value.size()) if type_ == "boolean" else value.sign_extend(32 - value.size())
        if type_ == "boolean":
            self._require((value == 0) | (value == 1), "boolean_value", "Boolean storage accepts only 0 or 1")
        bits = PRIMITIVES[type_]
        raw = value[bits - 1:0]
        if bits == 32:
            return raw
        return raw.zero_extend(32 - bits) if type_ == "boolean" else raw.sign_extend(32 - bits)

    def new_object(self, class_name):
        self._check_allocation()
        fields = self.schema.allocation_fields(class_name)
        ref = HeapReference(uuid4().hex, class_name)
        self._references[ref.allocation_id] = ref
        for owner, field in fields:
            self._fields[(ref.allocation_id, owner, field.name)] = self.default(field.type)
        return ref

    def _field_key(self, ref, owner, name, type_):
        self.validate_reference(ref, owner, nullable=False)
        self.schema.field(owner, name, type_)
        key = ref.allocation_id, owner, name
        if key not in self._fields:
            raise HeapError("field_declaration", f"Object has no declared field {owner}.{name}")
        return key

    def read_field(self, ref, owner, name, type_):
        return self._fields[self._field_key(ref, owner, name, type_)]

    def write_field(self, ref, owner, name, type_, value):
        key = self._field_key(ref, owner, name, type_)
        self._check_stored_reference(value)
        self._fields[key] = self.normalize(value, type_)

    def _check_allocation(self):
        if self.state.has_plugin('javacard') and self.state.javacard.transaction is not None:
            raise HeapError('transaction_allocation', 'Allocation inside a transaction is outside this API profile')

    def _check_stored_reference(self, value):
        if (self.state.has_plugin('javacard') and isinstance(value, HeapReference)
                and value.allocation_id in self.state.javacard.global_references):
            raise HeapError('global_reference', 'APDU/global buffer references cannot be stored in fields or arrays')

    @staticmethod
    def _int32(value):
        if isinstance(value, int):
            if not -(1 << 31) <= value < (1 << 31):
                raise HeapError("integer_width", "Array size/index is outside signed int32")
            return claripy.BVV(value & 0xffffffff, 32)
        if isinstance(value, claripy.ast.BV) and value.size() == 32:
            return value
        raise HeapError("integer_width", "Array size/index must be int32")

    def new_array(self, element_type, length):
        self._check_allocation()
        if not is_value_type(element_type):
            raise HeapError("array_type", f"Unsupported element type {element_type}")
        size = self._int32(length)
        self._require(size.SGE(0), "negative_array_size", "Possible java.lang.NegativeArraySizeException")
        sizes = self.state.solver.eval_upto(size, 2)
        if len(sizes) != 1:
            raise HeapError("symbolic_array_size", "Array allocation needs a uniquely determined length")
        count = sizes[0]
        if count > self.max_array_length:
            raise HeapError("array_resource_limit", f"Array length {count} exceeds analysis limit {self.max_array_length}; no truncation performed")
        ref = HeapReference(uuid4().hex, element_type + "[]")
        self._references[ref.allocation_id] = ref
        self._arrays[ref.allocation_id] = _Array(element_type, (self.default(element_type),) * count)
        return ref

    def _array(self, ref):
        self.validate_reference(ref, nullable=False)
        array = self._arrays.get(ref.allocation_id)
        if array is None:
            raise HeapError("array_type", f"{ref.type} is not an allocated array")
        return array

    def array_length(self, ref):
        return claripy.BVV(len(self._array(ref).values), 32)

    def _index(self, array, index):
        index = self._int32(index)
        valid = index.SGE(0) & index.SLT(len(array.values))
        self._require(valid, "array_bounds", "Possible java.lang.ArrayIndexOutOfBoundsException; exception dispatch is not implemented")
        return index

    def read_array(self, ref, index):
        array = self._array(ref)
        index = self._index(array, index)
        if array.element_type not in PRIMITIVES:
            indices = self.state.solver.eval_upto(index, 2)
            if len(indices) != 1:
                raise HeapError("symbolic_reference_index", "Reference array access requires a uniquely determined index")
            return array.values[indices[0]]
        result = array.values[-1]
        for i in reversed(range(len(array.values) - 1)):
            result = claripy.If(index == i, array.values[i], result)
        return result

    def write_array(self, ref, index, value):
        array = self._array(ref)
        index = self._index(array, index)
        self._check_stored_reference(value)
        try:
            value = self.normalize(value, array.element_type)
        except HeapError as exc:
            if exc.code == "reference_type":
                raise HeapError("array_store", f"java.lang.ArrayStoreException: {exc}") from exc
            raise
        if array.element_type not in PRIMITIVES:
            indices = self.state.solver.eval_upto(index, 2)
            if len(indices) != 1:
                raise HeapError("symbolic_reference_index", "Reference array access requires a uniquely determined index")
            values = list(array.values)
            values[indices[0]] = value
            values = tuple(values)
        else:
            values = tuple(claripy.If(index == i, value, old) for i, old in enumerate(array.values))
        self._arrays[ref.allocation_id] = _Array(array.element_type, values)

    def read_slice(self, ref, offset, length):
        array = self._array(ref)
        if type(offset) is not int or type(length) is not int or offset < 0 or length < 0 or offset + length > len(array.values):
            raise HeapError('array_bounds', 'Invalid concrete array range')
        return array.values[offset:offset + length]

    def write_slice(self, ref, offset, values):
        array = self._array(ref)
        values = tuple(values)
        self.read_slice(ref, offset, len(values))
        for value in values:
            self._check_stored_reference(value)
        normalized = tuple(self.normalize(v, array.element_type) for v in values)
        self._arrays[ref.allocation_id] = _Array(array.element_type,
            array.values[:offset] + normalized + array.values[offset + len(values):])

    def transaction_snapshot(self, transient_arrays):
        return (tuple(self._fields.items()), tuple((k, v) for k, v in self._arrays.items()
                                                    if k not in transient_arrays))

    def restore_transaction(self, snapshot):
        fields, arrays = snapshot
        self._fields = dict(fields)
        self._arrays.update(arrays)

    def cast_reference(self, value, type_):
        self.validate_reference(value)
        if isinstance(value, SootNullConstant):
            return value
        if not self.schema.assignable(value.type, type_):
            raise HeapError("class_cast", f"java.lang.ClassCastException: {value.type} to {type_}")
        return value
