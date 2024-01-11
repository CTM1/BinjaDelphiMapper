import binaryninja
from binaryninja import PluginCommand, BinaryView, interaction

def rename_fn(bv: BinaryView):
    map_importer_plugin(bv, False)

def create_and_rename_fn(bv: BinaryView):
    map_importer_plugin(bv, True)

def rename_functions(bv: BinaryView, map_file_path: str, create: bool):
    with open(map_file_path, 'r') as file:
        for line in file:
            try:
                new_name, addr = parse_line(line)

                fn = bv.get_function_at(addr)

                # Avoid renames unless they add context to 'sub_', e.g.
                # System.user32.LoadStringW adds no context to LoadStringW
                # Classes.TComponent.sub_10023AF8 adds context to sub_10023AF8

                if fn and (not fn.name in new_name or "sub_" in new_name):
                    fn.name = new_name
                elif (create):
                    fn = bv.create_user_function(addr, bv.platform)
                    if not fn.name in new_name or "sub_" in new_name:
                        fn.name = new_name
                else:
                    print(f"function {new_name} at {hex(addr)} not found, not creating")
            except:
                continue  # Ignore lines that don't match the expected format

def map_importer_plugin(bv: BinaryView, create: bool):
    map_file_path = interaction.get_open_filename_input("Select a map file", "*.map")
    if map_file_path:
        rename_functions(bv, map_file_path, create)
    else:
        print("No file selected.")

# Valid lines look like
# 0001:000944B0 Forms.TApplication.InvokeHelp_100954B0
# 0001:00097590 _Unit44.sub_10093590_10093590
# 0001:00099254 TestBinary.sub_1009A254_1009A254
def parse_line(line: str):
    line_parts = line.split()
    parts = line_parts[1].split('_')

    addr = int(parts[-1], 16)
    new_name = ''.join(parts[:-1])

    return new_name, addr

PluginCommand.register("Delphi Mapper\\0. Import .map, create and rename functions", "Imports names from a .map file and create function objects where possible", create_and_rename_fn)
PluginCommand.register("Delphi Mapper\\1. Import .map and only rename existing functions", "Imports names from a .map file and rename existing functions", rename_fn)
