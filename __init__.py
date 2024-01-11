import binaryninja
from binaryninja import PluginCommand, BinaryView, interaction

def rename_functions(bv: BinaryView, map_file_path: str, create: bool):
    with open(map_file_path, 'r') as file:
        for line in file:
            if line.count('_') >= 1:
                try:
                    parts = line.split()[1].split('_')
                    new_name = parts[0]
                    addr = int(parts[1], 16)

                    fn = bv.get_function_at(addr)

                    if fn and not fn.name in new_name:
                        fn.name = new_name
                    elif (create):
                        fn = bv.create_user_function(addr, bv.platform)
                        if not fn.name in new_name:
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

def rename_fn(bv: BinaryView):
    map_importer_plugin(bv, False)

def create_and_rename_fn(bv: BinaryView):
    map_importer_plugin(bv, True)

PluginCommand.register("Delphi Mapper\\0. Import .map, create and rename functions", "Imports names from a .map file and create function objects where possible", create_and_rename_fn)
PluginCommand.register("Delphi Mapper\\1. Import .map and only rename existing functions", "Imports names from a .map file and rename existing functions", rename_fn)
