# Attaching to a running process

`pyda-attach` allows you to attach to an already running process.

!!! info
    `pyda-attach` is currently only supported on Linux.

```bash
pyda-attach <script_path> <pid>
```

!!! warning
    pyda-attach needs permission to attach to the target process via ptrace.

!!! warning
    Due to some internal details of DynamoRIO, `pyda-attach` writes to a temporary file in your $HOME directory.
    **This file must be accessible to the process you are attaching to (even if that process may be running as a different user).**
    
    You may be inclined to run as `sudo` (to ensure the ptrace attach will succeed) but your $HOME may not be accessible
    by the target process when running under `sudo`. In this case, set the $HOME manually to some directory that the target
    can access.

