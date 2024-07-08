import subprocess
from dataclasses import dataclass
from typing import Optional, Callable
from pathlib import Path
from tempfile import TemporaryDirectory

@dataclass
class ExpectedResult:
    retcode: Optional[int] = None

    # checker(stdout, stderr) -> bool
    checkers: list[Callable[[bytes, bytes], bool]] = list

Res = ExpectedResult

def output_checker(stdout: bytes, stderr: bytes) -> bool:
    try:
        stdout.decode()
        stderr.decode()
    except:
        return False
    
    return True

def main():
    res = True

    # thread_1000.c tests whether we can handle a large number of threads
    # with concurrent hooks
    res &= run_test(
        "thread_1000.c", "../examples/ltrace_multithreaded.py",
        ExpectedResult(
            retcode=0,
            checkers=[
                output_checker,
                lambda o, e: o.count(b"malloc") == 20000,
                lambda o, e: o.count(b"free") == 20000,
                lambda o, e: all((o.count(f"[thread {i}]".encode('utf-8')) == 40 for i in range(2, 1002))),
            ]
        )
    )

    # thread_nojoin.c tests whether we can handle a large number of threads
    # that do not get waited on (i.e. they are not joined). Mostly
    # we just care about the return code and termination here.
    res &= run_test(
        "thread_nojoin.c", "../examples/ltrace_multithreaded.py",
        ExpectedResult(
            retcode=0,
            checkers=[
                output_checker,
            ]
        )
    )

    # err_hook.py tests the case where a hook throws an exception
    # NOTE: Hooks intentionally fail 'gracefully' and do not abort
    res &= run_test(
        "thread_1000.c", "err_hook.py",
        ExpectedResult(
            retcode=0,
            checkers=[
                output_checker,
                lambda o, e: e.count(b"[Pyda] ERROR:") == 1,
            ]
        )
    )

    # err_thread_entry.py tests the case where a hook throws an exception
    # NOTE: Hooks intentionally fail 'gracefully' and do not abort
    res &= run_test(
        "thread_1000.c", "err_thread_entry.py",
        ExpectedResult(
            retcode=0,
            checkers=[
                output_checker,
                lambda o, e: e.count(b"[Pyda] ERROR:") == 1,
            ]
        )
    )

    if not res:
        exit(1)

def run_test(c_file, python_file, expected_result):
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
                if not checker(result.stdout, result.stderr):
                    result_str += f"  Checker {i} failed\n"


        if len(result_str) > 0:
            print(f"[FAIL] {c_file} {python_file}")
            print(result_str)
            return False
        else:
            print(f"[OK] {c_file} {python_file}")
            return True


if __name__ == '__main__':
    main()