# cap_parser/container/main.py

# файл для отладки разработки
from container.cap_container import *
from container.zip_reader import *

from components.header import *
from components.directory import *
from components.applet import *
from components.import_component import *
from components.constant_pool import *
from components.class_component import *

from model.cap_file import *

def main():
    container = CAPContainer(Path("transaction_test_305.cap"))
    container.load()

    print(container.list_components())
    container.print_components()
    
    cap_parsing = CAPFileBuilder.build(container)
    print(cap_parsing.header, "\n")
    print(cap_parsing.directory, "\n")
    print(cap_parsing.applet, "\n")
    print(cap_parsing.import_componet, "\n")
    print(cap_parsing.constant_pool, "\n")
    print(cap_parsing.class_component, "\n")
    print(cap_parsing.method_component, "\n")
    print(cap_parsing.static_field, "\n")
    print(cap_parsing.reference_location, "\n")
    print(cap_parsing.descriptor, "\n")

    methods = cap_parsing.to_model()
    for m in methods:
        for ins in m.instructions:
            print(ins)

if __name__ == '__main__':
    main()