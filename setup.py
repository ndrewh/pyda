# translated from Dockerfile courtesy of Claude
import os
import sys
import subprocess
import shutil
import tempfile
from setuptools import setup, Extension, Command
from setuptools.command.install import install
from setuptools.command.develop import develop
from setuptools.command.install_scripts import install_scripts
from setuptools.command.build_ext import build_ext
import multiprocessing
import platform
import site

def dynamorio_tag_and_patch():
    if "macOS" in platform.platform():
        return ("11ee87b68bcb9834a52f42fe764d1a05d3c4f6b7", "patches/dynamorio-11ee87b68-macos.patch")
    else:
        return ("release_11.2.0", "patches/dynamorio-11.2.patch")

# Utility functions
def run_command(command, cwd=None, env=None):
    print(f"Running: {' '.join(command)}")
    subprocess.check_call(command, cwd=cwd, env=env)

def download_and_extract(url, extract_dir):
    import urllib.request
    import tarfile

    filename = url.split('/')[-1]
    urllib.request.urlretrieve(url, filename)

    with tarfile.open(filename) as tar:
        tar.extractall(path=extract_dir)

    os.remove(filename)

class CustomBuildCommand(Command):
    description = "Build Pyda"
    user_options = []
    
    def initialize_options(self):
        self.build_temp = None
        self.build_lib = None
    
    def finalize_options(self):
        self.set_undefined_options('build',
                                  ('build_temp', 'build_temp'),
                                  ('build_lib', 'build_lib'))
    
    def run(self):
        # Create temporary build directory
        build_temp_dir = tempfile.TemporaryDirectory()
        build_temp = build_temp_dir.name
        # build_temp = os.path.join(self.build_lib, "pyda_install")
        # os.makedirs(build_temp, exist_ok=True)
        try:
            # Set up paths
            dynamorio_install_dir = os.path.join(self.build_temp, 'dynamorio_install')
            libunwind_install_dir = os.path.join(self.build_temp, 'libunwind_install')

            os.makedirs(dynamorio_install_dir, exist_ok=True)
            os.makedirs(libunwind_install_dir, exist_ok=True)

            # Build libunwind
            if "Linux" in platform.platform():
                libunwind_dir = os.path.join(build_temp, 'libunwind')
                os.makedirs(libunwind_dir, exist_ok=True)
                download_and_extract(
                    'https://github.com/libunwind/libunwind/releases/download/v1.6.2/libunwind-1.6.2.tar.gz',
                    libunwind_dir
                )
                libunwind_build_dir = os.path.join(libunwind_dir, 'libunwind-1.6.2')
                run_command(['./configure', f'--prefix={os.path.abspath(libunwind_install_dir)}'], cwd=libunwind_build_dir)
                run_command(['make', f'-j{multiprocessing.cpu_count()}'], cwd=libunwind_build_dir)
                run_command(['make', 'install'], cwd=libunwind_build_dir)

            # Build DynamoRIO
            dynamorio_dir = os.path.join(build_temp, 'dynamorio')
            run_command([
                'git', 'clone', '--recurse-submodules', '-j4',
                'https://github.com/DynamoRIO/dynamorio.git',
                dynamorio_dir
            ])

            dyn_tag, dyn_patch = dynamorio_tag_and_patch()
            run_command(['git', 'checkout', dyn_tag], cwd=dynamorio_dir)

            # Apply DynamoRIO patch if it exists
            patch_path = os.path.abspath(dyn_patch)
            if os.path.exists(patch_path):
                run_command(['git', 'apply', patch_path], cwd=dynamorio_dir)

            run_command(["bash", "-c", "wget https://github.com/DynamoRIO/dynamorio/commit/f1b67a4b0cf0a13314d500dd3aaefe9869597021.patch && git apply f1b67a4b0cf0a13314d500dd3aaefe9869597021.patch && rm f1b67a4b0cf0a13314d500dd3aaefe9869597021.patch && git submodule update --init"], cwd=dynamorio_dir)
            run_command(["bash", "-c", "wget https://github.com/DynamoRIO/dynamorio/commit/c46d736f308e6e734bd0477f7b8a2dcbefb155d3.patch && git apply c46d736f308e6e734bd0477f7b8a2dcbefb155d3.patch && rm c46d736f308e6e734bd0477f7b8a2dcbefb155d3.patch"], cwd=dynamorio_dir)

            # Build DynamoRIO
            dynamorio_build_dir = os.path.join(dynamorio_dir, 'build')
            os.makedirs(dynamorio_build_dir, exist_ok=True)

            debug_mode = os.environ.get('PYDA_DEBUG', '0') == '1'
            cmake_debug = 'ON' if debug_mode else 'OFF'
            build_type = 'Debug' if debug_mode else 'Release'

            run_command([
                'cmake',
                f'-DDEBUG={cmake_debug}',
                '-DBUILD_TESTS=OFF',
                '-DBUILD_SAMPLES=OFF',
                '-DBUILD_CLIENTS=OFF',
                '-DBUILD_DOCS=OFF',
                f'-DCMAKE_INSTALL_PREFIX={os.path.abspath(dynamorio_install_dir)}',
                '..'
            ], cwd=dynamorio_build_dir)
            run_command(['make', f'-j{multiprocessing.cpu_count()}'], cwd=dynamorio_build_dir)
            run_command(['make', 'install'], cwd=dynamorio_build_dir)

            # Set environment variables for the final build
            build_env = os.environ.copy()
            build_env.update({
                'DYNAMORIO_HOME': os.path.abspath(dynamorio_install_dir),
                # 'PYTHONHOME': os.path.abspath(python_install_dir),
                # 'PYTHONPATH': f"{os.path.abspath(os.path.join(python_install_dir, 'lib', 'python3.10'))}:{os.path.join(os.getcwd(), 'lib')}"
            })

            # Build the main project
            project_build_dir = os.path.join(self.build_temp, 'build')
            os.makedirs(project_build_dir, exist_ok=True)

            src_dir = os.path.dirname(os.path.abspath(__file__))

            python_home = build_env.get("VIRTUAL_ENV", None)

            cmake_args = [
                'cmake',
                f'-DCMAKE_BUILD_TYPE={build_type}',
                f'-DDynamoRIO_DIR={os.path.abspath(os.path.join(dynamorio_install_dir, "cmake"))}',
                f'-DPython3_EXECUTABLE={sys.executable}',
            ] + ([f'-DPython3_ROOT_DIR={python_home}'] if python_home is not None else []) + ([
                    f'-DLIBUNWIND_INCLUDE_DIRS={os.path.abspath(os.path.join(libunwind_install_dir, "include"))}',
                    f'-DLIBUNWIND_LIBRARY_DIRS={os.path.abspath(os.path.join(libunwind_install_dir, "lib"))}',
                ] if "Linux" in platform.platform() else []) + [
                src_dir
            ]
            run_command(cmake_args, cwd=project_build_dir, env=build_env)

            run_command(['make', f'-j{multiprocessing.cpu_count()}'], cwd=project_build_dir)
            run_command(['rm', '-rf', ''], cwd=dynamorio_build_dir)

            prepend_env = f"""
export DYNAMORIO_HOME={os.path.abspath(dynamorio_install_dir)}/
"""
#export PYTHONPATH={':'.join(site.getsitepackages())}

            if "macOS" in platform.platform():
                pyda_tool_path = os.path.abspath(os.path.join(project_build_dir, 'pyda_core', 'libtool.dylib'))
            else:
                pyda_tool_path = os.path.abspath(os.path.join(project_build_dir, 'pyda_core', 'libtool.so'))

            prepend_env += f"export PYDA_TOOL_PATH={pyda_tool_path}\n"
            
            # Copy and modify the bin scripts to the appropriate location
            bin_dir = os.path.join(self.build_lib, 'bin')
            os.makedirs(bin_dir, exist_ok=True)
            
            # Copy and modify pyda script
            with open(os.path.join(src_dir, 'bin', 'pyda'), 'r') as f:
                pyda_content = f.read()
            
            # Insert the environment variables after the shebang line
            pyda_lines = pyda_content.splitlines()
            modified_pyda = pyda_lines[0] + '\n\n' + prepend_env + '\n'.join(pyda_lines[1:])
            
            with open(os.path.join(src_dir, 'bin', 'pyda'), 'w') as f:
                f.write(modified_pyda)
            
            # Copy and modify pyda-attach script
            with open(os.path.join(src_dir, 'bin', 'pyda-attach'), 'r') as f:
                pyda_attach_content = f.read()
            
            # Insert the environment variables after the shebang line
            pyda_attach_lines = pyda_attach_content.splitlines()
            modified_pyda_attach = pyda_attach_lines[0] + '\n\n' + prepend_env + '\n'.join(pyda_attach_lines[1:])
            
            with open(os.path.join(src_dir, 'bin', 'pyda-attach'), 'w') as f:
                f.write(modified_pyda_attach)

            # you don't want to know why this is here
            with open(os.path.join(dynamorio_install_dir, "CMakeCache.txt"), 'w') as f:
                pass

        finally:
            build_temp_dir.cleanup()
            pass

# Custom install command that runs our build command first
class CustomInstallCommand(install):
    def run(self):
        self.run_command('build_pyda')
        install.run(self)

# Custom develop command that runs our build command first
class CustomDevelopCommand(develop):
    def run(self):
        self.run_command('build_pyda')
        develop.run(self)

class CustomInstallScriptsCommand(install_scripts):
    def run(self):
        install_scripts.run(self)

        src_dir = os.path.dirname(os.path.abspath(__file__))

        for script in ['pyda', 'pyda-attach']:
            with open(os.path.join(src_dir, 'bin', script), 'r') as f:
                script_content = f.read()

            self.write_script(script, script_content)


setup(
    name='pyda-dbi',
    description='Pyda is a Python library for writing dynamic analysis tools',
    author='Andrew Haberlandt',
    author_email='your.email@example.com',
    cmdclass={
        'build_pyda': CustomBuildCommand,
        'install': CustomInstallCommand,
        'develop': CustomDevelopCommand,
        'install_scripts': CustomInstallScriptsCommand,
    },
    package_dir={"pyda": "lib/pyda"},
    packages=["pyda"],
    python_requires='>=3.0',
    install_requires=[
        # Add your Python package dependencies here
    ],
    scripts=[],
)
