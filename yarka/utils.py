from datetime import datetime
from typing import Generator

import idaapi
import idautils
import ida_bytes
import ida_funcs
import ida_ida
import ida_nalt
import idc


def get_file_md5():
    return ida_nalt.retrieve_input_file_md5().hex()


def get_file_sha256():
    return ida_nalt.retrieve_input_file_sha256().hex()


def get_file_name():
    return ida_nalt.get_root_filename()


def get_current_time(format: str = '%Y-%m-%d'):
    return datetime.now().strftime(format)


def get_selection():
    start = idc.read_selection_start()
    end = idc.read_selection_end()
    if idaapi.BADADDR in (start, end):
        ea = idc.here()
        start = idaapi.get_item_head(ea)
        end = idaapi.get_item_end(ea)
    return start, end


def resolve_ptr(ptr: int):
    if ida_ida.inf_is_64bit():
        return idaapi.get_qword(ptr)

    return idaapi.get_dword(ptr)


def resolve_ptr_until_data(ptr: int, max_depth: int = 3):
    current = ptr
    for _ in range(max_depth):
        if not idc.is_off0(ida_bytes.get_full_flags(current)):
            break
        current = resolve_ptr(current)

    return current


def get_custom_functions(
        min_size: int = 40,
        prefix: str = '',
        skip_lumina_functions: bool = False
    ) -> Generator[ida_funcs.func_t, None, None]:

    for ea in idautils.Functions():
        function = idaapi.get_func(ea)

        if function.flags & (idaapi.FUNC_LIB | idaapi.FUNC_THUNK):
            continue

        if skip_lumina_functions and function.flags & idaapi.FUNC_LUMINA:
            continue

        size = function.end_ea - function.start_ea
        if size < min_size:
            continue

        if prefix:
            name = idaapi.get_func_name(ea)
            if not name.startswith(prefix):
                continue
        
        yield function
