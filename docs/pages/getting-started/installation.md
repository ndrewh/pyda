# Installation

## Docker (Recommended)

The easiest way to get started with Pyda is using Docker.

### Pull the latest release

```bash
docker pull ghcr.io/ndrewh/pyda
```

### Or build it yourself

```bash
docker build -t pyda .
```

!!! note
    The Pyda image is currently based on `ubuntu:22.04` and we leave the default entrypoint as `/bin/bash`

## Experimental pip install (macOS and Linux)

!!! warning
    macOS support is extremely experimental and may not work.

Installation with pip may take ~1-2 minutes to complete, as it builds everything from source.

**Pyda currently only supports CPython 3.10.**

```bash
pip install pyda-dbi
```

## Supported Platforms

- **Operating System**: Linux, macOS
- **Architecture**: X86_64, ARM64
- **Python**: CPython 3.10

## Verification

Once installed, you can verify your installation works by running a simple example:

```bash
# Using Docker
docker run -it ghcr.io/ndrewh/pyda pyda examples/ltrace.py -- ls -al

# Using pip install
pyda examples/ltrace.py -- ls -al
```

If the installation is successful, you should see ltrace-style output showing library function calls made by the `ls` command.

## Next Steps

Once you have Pyda installed, head over to the [Quick Start](quickstart.md) guide to learn how to write your first analysis tool. 