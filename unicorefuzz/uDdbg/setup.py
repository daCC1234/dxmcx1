# python安装脚本
#!/usr/bin/env python3
import setuptools

# 秒睡文件
with open("README.md", "r") as fh:
    # long_description 中保存描述
    long_description = fh.read()

# 修复setup_tools
def fix_setuptools():
    """
    Work around bugs in setuptools.
        处理 setuptools 的 bug
    Some versions of setuptools are broken and raise SandboxViolation for normal
        一些版本的
    operations in a virtualenv. We therefore disable the sandbox to avoid these
        在虚拟环境中操作，所以禁用沙箱
    issues.
    """
    try:
        # setuptools.sandbox 中引入 DirectorySandbox，目录沙箱？
        from setuptools.sandbox import DirectorySandbox

        # 违反
        def violation(operation, *args, **_):
            print("SandboxViolation: %s" % (args,))
        # 设置，应该是一个回调函数？
        DirectorySandbox._violation = violation
    except ImportError:
        pass


# Fix bugs in setuptools.
# 首先调用fix_setuptools修复setbugs中的洞
fix_setuptools()

setuptools.setup(
    name="udbg",
    version="0.0.1",
    author="Giovanni Rocca and Vincenzo Greco",
    description="GDB-like debugger for Unicorn Engine",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/iGio90/uDdbg",
    # 寻找包，定位包的地址
    packages=setuptools.find_packages(),
    # 入口
    entry_points={'console_scripts':
        [
            'uddbg = udbg.udbg:main',
        ]},
    # 分类器？
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent"
    ],
    # 依赖库
    install_requires=[
        'inquirer',
        'termcolor',
        'tabulate',
        'prompt-toolkit',
        'wcwidth',
        'hexdump',
        'keystone-engine',
        'capstone',
        'unicorn'
    ]
)
