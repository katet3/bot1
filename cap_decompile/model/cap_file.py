# model/cap_file.py

from cap_decompile.components.header import HeaderComponent
from cap_decompile.components.directory import DirectoryComponent
from cap_decompile.components.applet import AppletComponent
from cap_decompile.components.import_component import ImportComponent
from cap_decompile.components.constant_pool import ConstantPoolComponent
from cap_decompile.components.class_component import ClassComponent
from cap_decompile.components.method_component import MethodComponent
from cap_decompile.components.static_field import StaticFieldComponent
from cap_decompile.components.reference_location import ReferenceLocationComponent

from cap_decompile.components.descriptor import DescriptorComponent


from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from jcvm_ir.adapter import MethodInput


@dataclass
class CAPFile:
    header: HeaderComponent
    directory: DirectoryComponent
    applet: AppletComponent
    import_componet: ImportComponent
    constant_pool: ConstantPoolComponent
    class_component: ClassComponent
    method_component: MethodComponent
    static_field: StaticFieldComponent
    reference_location: ReferenceLocationComponent

    descriptor: DescriptorComponent


    def validate(self):
        """
        Structural validation between Header and Directory.
        """
        if self.directory.component_sizes[0] != self.header.size:
            raise ValueError("Header size mismatch with Directory")


    def link(self):
        self.method_component.link_with_descriptor(self.descriptor)


    def to_model(self) -> list["MethodInput"]:
        """Return the same validated typed input as jcvm_ir.methods_from_cap.

        Replaces the lossy legacy Method projection. Method offsets are now
        Method.cap info-relative; handlers use method-local bytecode offsets.
        Unsupported method profiles raise IRValidationError through the adapter.
        Import locally so binary parsing alone does not load the IR stages.
        """
        from jcvm_ir.adapter import methods_from_cap

        return methods_from_cap(self)


class CAPFileBuilder:

    @staticmethod
    def build(container) -> CAPFile:
        header_bytes = container.get_component("Header.cap")
        directory_bytes = container.get_component("Directory.cap")
        applet_bytes = container.get_component("Applet.cap")
        import_component_bytes = container.get_component("Import.cap")
        constant_pool_bytes = container.get_component("ConstantPool.cap")
        class_component_bytes = container.get_component("Class.cap")
        method_component_bytes = container.get_component("Method.cap")
        static_field_bytes = container.get_component("StaticField.cap")
        reference_location_bytes = container.get_component("RefLocation.cap")

        descriptor_bytes = container.get_component("Descriptor.cap")

        header = HeaderComponent.parse_from_bytes(header_bytes)
        directory = DirectoryComponent.parse_from_bytes(directory_bytes, header.cap_version)
        applet = AppletComponent.parse_from_bytes(applet_bytes, header.cap_version)
        import_componet = ImportComponent.parse_from_bytes(import_component_bytes, header.cap_version)
        constant_pool = ConstantPoolComponent.parse_from_bytes(constant_pool_bytes, header.cap_version)
        class_component = ClassComponent.parse_from_bytes(class_component_bytes, header.cap_version)
        method_component = MethodComponent.parse_from_bytes(method_component_bytes, header.cap_version)
        static_field = StaticFieldComponent.parse_from_bytes(static_field_bytes, header.cap_version)
        reference_location = ReferenceLocationComponent.parse_from_bytes(reference_location_bytes, header.cap_version)

        descriptor = DescriptorComponent.parse_from_bytes(descriptor_bytes, header.cap_version)

        cap_file = CAPFile(
            header=header,
            directory=directory,
            applet=applet,
            import_componet=import_componet,
            constant_pool=constant_pool,
            class_component=class_component,
            method_component=method_component,
            static_field=static_field,
            reference_location=reference_location,
            descriptor=descriptor
        )

        cap_file.validate()
        cap_file.link()
        
        return cap_file
