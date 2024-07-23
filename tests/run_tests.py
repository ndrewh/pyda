import subprocess
from dataclasses import dataclass
from typing import Optional, Callable
from pathlib import Path
from tempfile import TemporaryDirectory

from argparse import ArgumentParser

@dataclass
class ExpectedResult:
    retcode: Optional[int] = None

    # checker(stdout, stderr) -> bool
    checkers: list[Callable[[bytes, bytes], bool]] = list

def output_checker(stdout: bytes, stderr: bytes) -> bool:
    try:
        stdout.decode()
        stderr.decode()
    except:
        return False
    
    return True

def no_warnings_or_errors(stdout: bytes, stderr: bytes) -> bool:
    return b"[Pyda]" not in stderr and b"WARNING:" not in stderr

TESTS = [
    # tests whether we can handle a large number of threads with concurrent hooks
    ("threads_concurrent_hooks", "thread_1000.c", "../examples/ltrace_multithreaded.py", ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"malloc") == 20000,
            lambda o, e: o.count(b"free") == 20000,
            lambda o, e: all((o.count(f"[thread {i}]".encode('utf-8')) == 40 for i in range(2, 1002))),
        ]
    )),

    # tests whether we can handle a large number of threads that do not get waited on
    ("threads_nojoin", "thread_nojoin.c", "../examples/ltrace_multithreaded.py", ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"malloc") > 15000,
            lambda o, e: o.count(b"free") > 15000,
            lambda o, e: all((o.count(f"[thread {i}]".encode('utf-8')) == 40 for i in range(2, 100))),
        ]
    )),

    # hook throws an exception
    ("err_hook_throw", "thread_1000.c", "err_hook.py", ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            lambda o, e: e.count(b"[Pyda] ERROR:") == 1,
        ]
    )),

    # thread entry hook throws an exception
    ("err_thread_entry_throw", "thread_1000.c", "err_thread_entry.py", ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            lambda o, e: e.count(b"[Pyda] ERROR:") == 1,
        ]
    )),

    # tests whether we can handle a simple syscall hook
    ("syscall_hooks", "simple.c", "test_syscall.py", ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"pre syscall") == o.count(b"post syscall") + 1, # (+1 for exit)
            lambda o, e: o.index(b"pre syscall") < o.index(b"post syscall"),
        ]
    )),

    # tests tid is correct in syscall hooks
    ("syscall_hooks_multithread", "thread_10.c", "test_syscall.py", ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: all((o.count(f"[tid {i}]".encode('utf-8')) > 1 for i in range(1, 10))) or print(o),
        ]
    )),

    # user fails to call p.run()
    ("err_norun", "thread_1000.c", "err_norun.py", ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            lambda o, e: e.count(b"[Pyda] ERROR:") == 1,
        ]
    )),

    # test register read/write
    ("test_regs_x86", "simple.c", "test_regs_x86.py", ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"success") == 1,
        ]
    )),

    # test "blocking" I/O
    ("test_io", "test_io.c", "test_io.py", ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"hello") == 0,
            lambda o, e: o.count(b"pass\n") == 1,
        ]
    )),

    # test "blocking" run_until
    ("test_blocking", "simple.c", "test_blocking.py", ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"pass\n") == 1,
        ]
    ))
]

def main():
    ap = ArgumentParser()
    ap.add_argument("--test", help="Run a specific test", default=None)
    ap.add_argument("--debug", help="Enable debug output", action="store_true")
    args = ap.parse_args()

    if args.test is None:
        res = True
        for (name, c_file, python_file, expected_result) in TESTS:
            res &= run_test(c_file, python_file, expected_result, name, args.debug)
    else:
        test = next((t for t in TESTS if t[0] == args.test), None)
        if test is None:
            print(f"Test {args.test} not found")
            exit(1)
        
        name, c_file, python_file, expected_result = test
        res = run_test(c_file, python_file, expected_result, name, args.debug)

    if not res:
        exit(1)

def run_test(c_file, python_file, expected_result, test_name, debug):
    # Compile to temporary directory
    with TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        c_path = Path(c_file)
        p_path = Path(python_file)

        c_exe = tmpdir / c_path.stem
        compile_res = subprocess.run(['gcc', '-o', c_exe, c_path], capture_output=True)
        if compile_res.returncode != 0:
            print(f"Failed to compile {c_file}")
            print(compile_res.stderr)
            raise RuntimeError("Failed to compile test")

        result_str = ""
        try:
            result = subprocess.run(f"pyda {p_path.resolve()} -- {c_exe.resolve()}", shell=True, timeout=10, capture_output=True)
        except subprocess.TimeoutExpired:
            result_str += " Timeout occurred. Did the test hang?\n"
            result = None

        
        if result:
            # Check the results
            if expected_result.retcode is not None:
                if result.returncode != expected_result.retcode:
                    result_str += f"  Expected return code {expected_result.retcode}, got {result.returncode}\n"

            for (i, checker) in enumerate(expected_result.checkers):
                checker_res = False
                try:
                    checker_res = checker(result.stdout, result.stderr)
                except:
                    pass
                
                if not checker_res:
                    result_str += f"  Checker {i} failed\n"


        if len(result_str) > 0:
            print(f"[FAIL] {test_name} ({python_file} {c_file})")
            print(result_str)
            if debug:
                print(result.stdout.decode())
                print(result.stderr.decode())

            return False
        else:
            print(f"[OK] {test_name} ({python_file} {c_file})")
            return True


if __name__ == '__main__':
    main()