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
    macOS support is extremely experimental and may not work. See "a note on macOS" below.

Installation with pip may take ~1-2 minutes to complete, as it builds everything from source.

**Pyda currently only supports CPython 3.10.**

```bash
pip install pyda-dbi
```

## Supported Platforms

- **Operating System**: Linux, macOS (experimental)
- **Architecture**: X86_64, ARM64
- **Python**: CPython 3.10

## First use

Once installed, you can verify your installation works by running a simple example:

```bash
# If you used Docker...
docker run -it ghcr.io/ndrewh/pyda pyda examples/ltrace.py -- ls -al

# If you used pip install...
pyda examples/ltrace.py -- ls -al
```

If the installation is successful, you should see ltrace-style output showing library function calls made by the `ls` command.

### A note on macOS

On macOS, certain security mechanisms interfere with Pyda. Pyda (and any other DynamoRIO-based tool) will **silently fail to attach to many code-signed processes**.

- If you just want to try Pyda, try it on something you compiled on your own machine or (if you know what you're doing) resign your target with the `codesign` utility.
- If you want to run system / App Store applications under Pyda, consider disabling SIP. This is completely untested, though.

## Next Steps

Once you have Pyda installed, head over to the [Quick Start](quickstart.md) guide to learn how to write your first analysis tool. 
