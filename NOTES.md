Random collection of notes. `zeek-spy` uses `ptrace` to read memory
from the process - this is all really low level.

# Position independent executables

Addresses of `main()` - found via gdb:

    0x5565196d73e0
    0x55bd59da73e0

Addresses of `call_stack` - found via gdb:

    0x55b47f2d6170
    0x556519c59170
    0x55bd5a329170

Oha, things have changed - we are running PIE executables. Oh joy.

Workaround: Use `/proc/<pid>/maps` to find the loading address of the
executable and add the offset we find in through the symbol table
using `readelf` / `debug/elf` with `/proc/<pid>/exe`.


# std::vector memory layout for GCC

Now that we have the address of `call_stack`, figure out where the actual
`CallInfo` objects are stored:

`call_stack` is a std:vector of `CallInfo`, objects. GCC uses the following
layout (bits/stl_vector.h):

    _M_start
    _M_finish
    _M_end_of_storage


The `CallInfo` struct is easy, just 3 pointers. `(_M_finish_ - _M_start_) / 24`
gives the number of `CallInfo` entries to expect inside the vector.


# Offset of name in Func:

`Func` is a `BroObj`.

Using dwarfdump and grepping, we find the following entry:

    < 2><0x000d0f72>      DW_TAG_member
        DW_AT_name                  name
        DW_AT_decl_file             0x00000002 /home/awelzel/projects/zeek/src/Func.h
        DW_AT_decl_line             0x00000058
        DW_AT_decl_column           0x00000009
        DW_AT_type                  <0x0000256e>
        DW_AT_data_member_location  72
        DW_AT_accessibility         DW_ACCESS_protected


# std::string memory layout for GCC

`Func.name` is a `std::string`. Fortunately the first element is a pointer
to a NULL terminated C-string, so we can just read the memory until we hit
the NULL byte.

This will probably not work for `clang` which uses short string optimization.

# Location

Every `BroObj` object has a `location` member at offset 8 (right after the `vtable`).

The `Location` objects have a `filename`, `first_line` and `last_line` after
the `vtable`.

    0:  vtable
    8:  filename    // just a NULL terminated c-string
    16: first_line  // int, 4 bytes
    20: lastt_line  // int, 4 bytes

# g_frame_stack when len(call_stack) == 1

When `call_stack` has size 1, we do not have a `call` object in `CallInfo`
to find out where we are. This is the case if we are executing a event handler.
The `Func` in `CallInfo` for this case points to the `bif`, but we would like
to know where the actual event handler code lives.

To workaround this, we read the first Frame on `g_frame_stack` and fetch
its `next_stmt` which has a location to the "right" location that is currently
executing.

Frame class (from dwarfdump):

    < 2><0x000431bc>      DW_TAG_member
        DW_AT_name                  next_stmt
        DW_AT_decl_file             0x000000ac /home/awelzel/projects/zeek/src/Frame.h
        DW_AT_decl_line             0x00000108
        DW_AT_decl_column           0x00000008
        DW_AT_type                  <0x0003c98f>
        DW_AT_data_member_location  144 (-112)

Because `Stmt` is a `BroObj` and has a `Location`, we do the same dance as
for the `Func` before.
