# Exceptions

Pyda defines several custom exceptions for different error conditions:

- **MemoryError**: Raised when memory operations fail
- **ThreadExitError**: Raised when a thread exits while waiting for I/O
- **InvalidStateError**: Raised when operations are performed in invalid states
- **FatalSignalError**: Raised when the target process receives a fatal signal

These exceptions are imported from the `pyda_core` module and provide detailed information about error conditions during analysis. 
