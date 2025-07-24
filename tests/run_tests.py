import subprocess
from dataclasses import dataclass
from typing import Optional, Callable
from pathlib import Path
from tempfile import TemporaryDirectory
import os, time, platform

from argparse import ArgumentParser
from dataclasses import field
@dataclass
class ExpectedResult:
    retcode: Optional[int] = None

    # checker(stdout, stderr) -> bool
    checkers: list[Callable[[bytes, bytes], bool]] = list

    hang: bool = False

@dataclass
class RunOpts:
    no_pty: bool = False
    attach: bool = False
    supported_arches: list[str] = field(default_factory=lambda: ["AMD64", "x86_64", "aarch64", "arm64"])
    supported_platforms: list[str] = field(default_factory=lambda: ["Linux"])
    ci: bool = True

    def no_arm64(self):
        self.supported_arches.remove("aarch64")
        self.supported_arches.remove("arm64")
        return self

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
    # tests whether we can handle a large number of threads with concurrent hooks
    ("threads_concurrent_hooks", "thread_1000.c", "../examples/ltrace_multithreaded.py", RunOpts().no_arm64(), ExpectedResult(
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
    ("threads_nojoin", "thread_nojoin.c", "../examples/ltrace_multithreaded.py", RunOpts().no_arm64(), ExpectedResult(
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
    ("err_hook_throw", "thread_1000.c", "err_hook.py", RunOpts().no_arm64(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            lambda o, e: e.count(b"[Pyda] ERROR:") == 1,
        ]
    )),

    # thread entry hook throws an exception
    ("err_thread_entry_throw", "thread_10.c", "err_thread_entry.py", RunOpts(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            lambda o, e: e.count(b"[Pyda] ERROR:") == 1,
        ]
    )),

    # XXX: This is broken in the actions runner for some reason, can't repro locally (#xxx)
    ("err_thread_entry_throw_1000", "thread_1000.c", "err_thread_entry.py", RunOpts(ci=False).no_arm64(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            lambda o, e: e.count(b"[Pyda] ERROR:") == 1,
        ]
    )),

    # tests whether we can handle a simple syscall hook
    ("syscall_hooks", "simple.c", "test_syscall.py", RunOpts(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"pre syscall") == o.count(b"post syscall") + 1, # (+1 for exit)
            lambda o, e: o.index(b"pre syscall") < o.index(b"post syscall"),
        ]
    )),

    # tests tid is correct in syscall hooks
    ("syscall_hooks_multithread", "thread_10.c", "test_syscall.py", RunOpts(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: all((o.count(f"[tid {i}]".encode('utf-8')) > 1 for i in range(1, 10))) or print(o),
        ]
    )),

    # user fails to call p.run()
    ("err_norun", "thread_10.c", "err_norun.py", RunOpts(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            lambda o, e: e.count(b"[Pyda] ERROR:") == 1,
        ]
    )),

    ("err_norun_1000", "thread_1000.c", "err_norun.py", RunOpts(ci=False).no_arm64(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            lambda o, e: e.count(b"[Pyda] ERROR:") == 1,
        ]
    )),

    # test register read/write
    ("test_regs_x86", "simple.c", "test_regs_x86.py", RunOpts().no_arm64(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"success") == 1,
        ]
    )),

    # test "blocking" I/O
    ("test_io1", "test_io.c", "test_io1.py", RunOpts(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"hello") == 0,
            lambda o, e: o.count(b"pass\n") == 1,
        ]
    )),

    # test "blocking" I/O
    ("test_io2", "test_io.c", "test_io2.py", RunOpts(), ExpectedResult(
        checkers=[
            output_checker,
            lambda o, e: e.count(b"[Pyda] ERROR:") == 1,
            lambda o, e: e.count(b"RuntimeError: I/O must be explicitly captured using process(io=True)") == 1,
            lambda o, e: o.count(b"hello there") == 1,
            lambda o, e: o.count(b"goodbye") == 1,
        ]
    )),

    # test "blocking" run_until
    ("test_blocking1", "simple.c", "test_blocking1.py", RunOpts(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"pass\n") == 1,
        ]
    )),

    ("test_blocking2", "simple.c", "test_blocking2.py", RunOpts(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"pass\n") == 1,
        ]
    )),

    ("test_blocking3", "simple.c", "test_blocking3.py", RunOpts(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            lambda o, e: e.count(b"[Pyda] ERROR: Did you forget to call p.run()?") == 1,
        ]
    )),

    ("test_blocking4", "simple.c", "test_blocking4.py", RunOpts(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            lambda o, e: e.count(b"[Pyda] ERROR:") == 1,
            lambda o, e: e.count(b"Hook call failed") == 1,
            lambda o, e: e.count(b"InvalidStateError") == 1,
        ]
    )),

    # test "blocking" i/o with a giant write
    ("test_hugeio", "test_hugeio.c", "test_hugeio.py", RunOpts(no_pty=True, ci=False), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"pass\n") == 1,
        ]
    )),

    ("test_call", "test_call.c", "test_call.py", RunOpts(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"pass\n") == 1,
        ]
    )),

    ("test_thread_blocking", "thread_10.c", "test_thread_blocking.py", RunOpts(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: all((o.count(f"[thread {i}]".encode('utf-8')) == 20 for i in range(2, 12))),
            lambda o, e: o.count(b"pass\n") == 1,
        ]
    )),

    ("test_segv", "test_segv.c", "test_segv.py", RunOpts().no_arm64(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"test_segv") == 8,
            lambda o, e: o.count(b"] main") == 3,
            lambda o, e: o.count(b"] segfault") == 4,
            lambda o, e: o.count(b"pass\n") == 1,
        ]
    )),

    ("test_python_threading", "simple.c", "test_python_threading.py", RunOpts(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"pass\n") == 1,
            lambda o, e: o.count(b"thread start\n") == 1,
            lambda o, e: o.count(b"thread end\n") == 1,
        ]
    )),

    ("err_invalidhook", "simple.c", "err_invalidhook.py", RunOpts(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            lambda o, e: e.count(b"RuntimeError: Hooked PC 1337133713371337 is invalid;") == 1,
        ]
    )),

    ("test_pwntools", "simple.c", "test_pwntools.py", RunOpts(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"pass\n") == 1,
        ]
    )),

    ("test_fork", "test_fork.c", "../examples/ltrace_multithreaded.py", RunOpts(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"child status 0") == 1,
        ]
    )),

    ("test_attach", "test_longrunning.c", "../examples/ltrace_multithreaded.py", RunOpts(attach=True), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"[thread 1] sleep") in range(5, 12),
        ]
    )),

    ("test_attach_multithread", "test_longrunning_multithread.c", "../examples/ltrace_multithreaded.py", RunOpts(attach=True), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: o.count(b"pthread_join") in [9, 10], # first call may happen before attach
            lambda o, e: o.count(b"snprintf") == 10,
            lambda o, e: all((o.count(f"[thread {i}] gettimeofday".encode('utf-8')) in range(5, 12) for i in range(2, 12))),
            lambda o, e: all((o.count(f"thread_entry for {i}".encode('utf-8')) == 1 for i in range(2, 12))),
        ]
    )),

    # test inline instrumentation compiler
    ("test_compiler1", "simple2.c", "builder1.py", RunOpts(), ExpectedResult(
        retcode=0,
        checkers=[
            output_checker,
            no_warnings_or_errors,
            lambda o, e: all(o.count(f"hello {i}".encode('utf-8')) == 1 for i in range(1337, 1347)),
        ]
    )),
]

def main():
    ap = ArgumentParser()
    ap.add_argument("--test", help="Run a specific test", default=None)
    ap.add_argument("--debug", help="Enable debug output", action="store_true")
    ap.add_argument("--ntrials", default=5, type=int)
    ap.add_argument("--ci", help="Run in CI mode", action="store_true")
    args = ap.parse_args()

    if args.test is None:
        res = True
        for (name, c_file, python_file, run_opts, expected_result) in TESTS:
            if run_opts.supported_arches is not None and platform.machine() not in run_opts.supported_arches:
                print(f"Skipping test {name} because it is not supported on {platform.machine()}")
            elif run_opts.supported_platforms is not None and platform.system() not in run_opts.supported_platforms:
                print(f"Skipping test {name} because it is not supported on {platform.system()}")
            elif not run_opts.ci and args.ci:
                print(f"Skipping test {name} because it is not supported in CI")
            else:
                res &= run_test(c_file, python_file, run_opts, expected_result, name, args.debug, args.ntrials)
    else:
        test = next((t for t in TESTS if t[0] == args.test), None)
        if test is None:
            print(f"Test {args.test} not found")
            exit(1)
        
        name, c_file, python_file, run_opts, expected_result = test
        res = run_test(c_file, python_file, run_opts, expected_result, name, args.debug, args.ntrials)

    if not res:
        exit(1)

TIMEOUT = 30
def run_test(c_file, python_file, run_opts, expected_result, test_name, debug, ntrials):
    # Compile to temporary directory
    with TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        c_path = Path(c_file)
        p_path = Path(python_file)

        c_exe = tmpdir / c_path.stem
        compile_res = subprocess.run(['gcc', '-o', c_exe, c_path, '-lpthread'], capture_output=True)
        if compile_res.returncode != 0:
            print(f"Failed to compile {c_file}")
            print(compile_res.stderr)
            raise RuntimeError("Failed to compile test")

        env = os.environ.copy()
        if run_opts.no_pty:
            env["PYDA_NO_PTY"] = "1"

        env["TERM"] = "linux"

        for trial in range(ntrials):
            result_str = ""
            try:
                if not run_opts.attach:
                    result = subprocess.Popen(f"pyda {p_path.resolve()} -- {c_exe.resolve()}", env=env, stdin=subprocess.DEVNULL, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = result.communicate(timeout=TIMEOUT)
                else:
                    # Attach mode: Launch the process and then attach to it
                    proc = subprocess.Popen([c_exe.resolve()], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    time.sleep(2)
                    result = subprocess.Popen(f"pyda-attach {p_path.resolve()} {proc.pid}", env=env, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)

                    stdout, stderr = proc.communicate(timeout=TIMEOUT)
                    result.wait(timeout=TIMEOUT)

                if expected_result.hang:
                    result_str += "  Expected test to hang, but it did not\n"
            except subprocess.TimeoutExpired as err:
                if not expected_result.hang:
                    result_str += "  Timeout occurred. Did the test hang?\n"

                result.kill()
                if run_opts.attach:
                    proc.kill()
            
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


            if len(result_str) > 0:
                print(f"[FAIL] {test_name} ({python_file} {c_file})")
                print(result_str)
                if debug:
                    if stdout:
                        print(stdout.decode())
                    if stderr:
                        print(stderr.decode())

                return False
            else:
                print(f"[OK] {test_name} ({python_file} {c_file})")

        return True


if __name__ == '__main__':
    main()
