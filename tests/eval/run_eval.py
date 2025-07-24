import subprocess
from dataclasses import dataclass, replace
from typing import Optional, Callable
from pathlib import Path
from tempfile import TemporaryDirectory
import os
import time
from argparse import ArgumentParser

@dataclass
class ExpectedResult:
    retcode: Optional[int] = None

    # checker(stdout, stderr) -> bool
    checkers: list[Callable[[bytes, bytes], bool]] = list

@dataclass
class RunOpts:
    no_pty: bool = False

def output_checker(stdout: bytes, stderr: bytes) -> bool:
    try:
        if stdout:
            stdout.decode()

        if stderr:
            stderr.decode()
    except:
        return False

    return True

def no_warnings_or_errors(stdout: bytes, stderr: bytes) -> bool:
    return b"[Pyda]" not in stderr and b"WARNING:" not in stderr

TESTS = [
    ("test_malloc_1", "malloc1.c", "malloccount_pyda.py", "malloccount_libdebug.py", "malloccount_frida.js", "libhook_instruction.so", RunOpts(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"pass\n") == 1,
        ]
    )),
    ("test_malloc_1000", "malloc1000.c", "malloccount_pyda.py", "malloccount_libdebug.py", "malloccount_frida.js", "libhook_instruction.so", RunOpts(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"pass\n") == 1,
        ]
    )),
    ("test_malloc_100000", "malloc100000.c", "malloccount_pyda.py", "malloccount_libdebug.py", "malloccount_frida.js", "libhook_instruction.so", RunOpts(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"pass\n") == 1,
        ]
    )),
    ("test_malloc_10000000", "malloc10000000.c", "malloccount_pyda.py", "malloccount_libdebug.py", "malloccount_frida.js", "libhook_instruction.so", RunOpts(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"pass\n") == 1,
        ]
    )),
    ("test_malloc_10000000_inline", "malloc10000000.c", "malloccount_pyda_inline.py", "malloccount_libdebug.py", "malloccount_frida.js", "libhook_instruction.so", RunOpts(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"pass\n") == 1,
        ]
    )),
    ][-2:]

def main():
    ap = ArgumentParser()
    ap.add_argument("--test", help="Run a specific test", default=None)
    ap.add_argument("--debug", help="Enable debug output", action="store_true")
    ap.add_argument("--ntrials", default=5, type=int)
    args = ap.parse_args()

    if args.test is None:
        res = True
        for (name, c_file, pyda_file, libdebug_file, frida_file, frida_rust_file, run_opts, expected_result) in TESTS:
            res &= run_test(c_file, pyda_file, libdebug_file, frida_file, frida_rust_file, run_opts, expected_result, name, args.debug, args.ntrials)
    else:
        test = next((t for t in TESTS if t[0] == args.test), None)
        if test is None:
            print(f"Test {args.test} not found")
            exit(1)

        name, c_file, pyda_file, libdebug_file, frida_file, frida_rust_file, run_opts, expected_result = test
        res = run_test(c_file, pyda_file, libdebug_file, frida_file, frida_rust_file, run_opts, expected_result, name, args.debug, args.ntrials)

    if not res:
        exit(1)

def run_pyda(c_exe_path, pyda_script_path, env, expected_result, test_name, debug):
    def run():
        cmd = f"pyda {pyda_script_path.resolve()} -- {c_exe_path.resolve()}"
        return subprocess.run(cmd, env=env, stdin=subprocess.DEVNULL, shell=True, timeout=60, capture_output=True)

    return run_tool(run, test_name, expected_result, debug)

def run_libdebug(c_exe_path, libdebug_script_path, env, expected_result, test_name, debug):
    def run():
        return subprocess.run(f"python3 {libdebug_script_path.resolve()} {c_exe_path.resolve()}", env=env, stdin=subprocess.DEVNULL, shell=True, timeout=600, capture_output=True)

    return run_tool(run, test_name, expected_result, debug)

def run_frida(c_exe_path, script_path, env, expected_result, test_name, debug):
    def run():
        return subprocess.run(f"/opt/custom-python-root/bin/frida -l {script_path.resolve()} {c_exe_path.resolve()}", env=env, stdin=subprocess.DEVNULL, shell=True, timeout=60, capture_output=True)

    expected_result = replace(expected_result)
    expected_result.retcode = 1
    return run_tool(run, test_name, expected_result, debug)

def run_frida_rust(c_exe_path, script_path, env, expected_result, test_name, debug):
    def run():
        return subprocess.run(f"LD_PRELOAD={script_path.resolve()} {c_exe_path.resolve()}", env=env, stdin=subprocess.DEVNULL, shell=True, timeout=60, capture_output=True)

    return run_tool(run, test_name, expected_result, debug)

def run_native(c_exe_path, env, expected_result, test_name, debug):
    def run():
        return subprocess.run(f"{c_exe_path.resolve()}", env=env, stdin=subprocess.DEVNULL, shell=True, timeout=60, capture_output=True)

    expected_result = replace(expected_result)
    expected_result.checkers = []
    return run_tool(run, test_name, expected_result, debug)

def run_tool(run_cmd, test_name, expected_result, debug):
    result_str = ""

    t1, t2 = None, None
    try:
        t1 = time.time()
        result = run_cmd()
        t2 = time.time()

        stdout = result.stdout
        stderr = result.stderr
    except subprocess.TimeoutExpired as err:
        result_str += "  Timeout occurred. Did the test hang?\n"

        result = None
        stdout = err.stdout
        stderr = err.stderr


    if result:
        # Check the retcode
        if expected_result.retcode is not None:
            if result.returncode != expected_result.retcode:
                result_str += f"  Expected return code {expected_result.retcode}, got {result.returncode}\n"

    # Unconditionally check the output
    for (i, checker) in enumerate(expected_result.checkers):
        checker_res = False
        try:
            checker_res = checker(stdout, stderr)
        except:
            pass

        if not checker_res:
            result_str += f"  Checker {i} failed\n"

    res_time = None
    if t1 is not None and t2 is not None:
        res_time = t2 - t1

    if len(result_str) > 0:
        print(f"[FAIL] {test_name}")
        print(result_str)
    if debug:
        if stdout:
            print(stdout.decode())
        if stderr:
            print(stderr.decode())

    else:
        print(f"[OK] {test_name}")

    return result_str, res_time


def run_test(c_file, pyda_file, libdebug_file, frida_file, frida_rust_file, run_opts, expected_result, test_name, debug, ntrials):
    # Compile to temporary directory
    with TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        c_path = Path(c_file)
        pyda_path = Path(pyda_file)
        libdebug_path = Path(libdebug_file)
        frida_path = Path(frida_file)
        frida_rust_path = Path(frida_rust_file)

        c_exe = tmpdir / c_path.stem
        compile_res = subprocess.run(['gcc', '-o', c_exe, c_path], capture_output=True)
        if compile_res.returncode != 0:
            print(f"Failed to compile {c_file}")
            print(compile_res.stderr)
            raise RuntimeError("Failed to compile test")

        env = os.environ.copy()
        if run_opts.no_pty:
            env["PYDA_NO_PTY"] = "1"

        for trial in range(ntrials):
            pyda_result, pyda_time = run_pyda(c_exe, pyda_path, env, expected_result, test_name, debug)
            libdebug_result, libdebug_time = run_libdebug(c_exe, libdebug_path, env, expected_result, test_name, debug)
            frida_result, frida_time = run_frida(c_exe, frida_path, env, expected_result, test_name, debug)
            frida_rust_result, frida_rust_time = run_frida_rust(c_exe, frida_rust_path, env, expected_result, test_name, debug)
            native_result, native_time = run_native(c_exe, env, expected_result, test_name, debug)

            print(f"Pyda time: {pyda_time}")
            print(f"libdebug time: {libdebug_time}")
            print(f"frida time: {frida_time}")
            print(f"frida_rust time: {frida_rust_time}")
            print(f"native time: {native_time}")

            # if len(pyda_result) > 0 or len(libdebug_result) > 0:
            #     return False

        return True


if __name__ == '__main__':
    main()
