# Process API

The Process API is the main interface for dynamic analysis with Pyda. It provides methods for hooking execution, intercepting system calls, and manipulating process state.

::: pyda.Process
    options:
      show_root_heading: false
      show_source: false
      members:
        - __init__
        - hook
        - unhook
        - hook_after_call
        - syscall_pre
        - syscall_post
        - set_thread_entry
        - on_module_load
        - read
        - write
        - run
        - run_until
        - run_from_to
        - callable
        - backtrace
        - backtrace_cpp
        - tid

## Memory and Register Interfaces

::: pyda.proc.ProcessRegisters
    options:
      show_root_heading: true
      show_source: false
      members:
        - __init__
        - __getitem__
        - __setitem__
        - has_reg

::: pyda.proc.ProcessMemory
    options:
      show_root_heading: true
      show_source: false
      members:
        - __init__
        - __getitem__

::: pyda.proc.ProcessMaps
    options:
      show_root_heading: true
      show_source: false
      members:
        - __init__
        - __getitem__

::: pyda.proc.Map
    options:
      show_root_heading: true
      show_source: false
      members:
        - base
        - start
        - end
        - executable
        - writable
        - readable 
