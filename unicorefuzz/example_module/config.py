# unicorefuzz的配置文件

# This is the main config file of Unicorefuzz.
# It should be adapted for each fuzzing run.
import os
import struct

from unicorn import Uc
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RDX, UC_X86_REG_RDI
from unicorefuzz.unicorefuzz import Unicorefuzz

# A place to put scratch memory to. Non-kernelspace address should be fine.
# 把scratch memory（不知道什么东西） 移动到这个地址，非内核地址页也行？
SCRATCH_ADDR = 0x80000
# How much scratch to add. We don't ask for much. Default should be fine.
# 大小
SCRATCH_SIZE = 0x1000

# The page size used by the emulator. Optional.
PAGE_SIZE = 0x1000

# Set a supported architecture
ARCH = "x64"

# The gdb port to connect to
GDB_HOST = "localhost"
GDB_PORT = 1234

# Either set this to load the module from the VM and break at module + offset...
# 断在这个模块上，并且在OFFSET位置下断
MODULE = "procfs1"
BREAK_OFFSET = 0x10

# Or this to break at a fixed offset.
# 准确地址
BREAK_ADDR = None
# You cannot set MODULE and BREAKOFFSET at the same time

# Additional exits here.
# The Exit at entry + LENGTH will be added automatically.
# 退出点
EXITS = []
# Exits realtive to the initial rip (entrypoint + addr)
# 相对退出点
ENTRY_RELATIVE_EXITS = []

# The location used to store data and logs
# 存储数据和日志的目录
WORKDIR = os.path.join(os.getcwd(), "unicore_workdir")

# Where AFL input should be read from
# AFL_INPUTS 和 AFL_OUTPUTS
AFL_INPUTS = os.path.join(os.getcwd(), "afl_inputs")
# Where AFL output should be placed at
AFL_OUTPUTS = os.path.join(os.getcwd(), "afl_outputs")

# Optional AFL dictionary
AFL_DICT = None


def init_func(uc):
    """
    An init function called before forking.
    This function may be used to set additional unicorn hooks and things.
        用来设置额外的unicorn hook和其他东西
    If you uc.run_emu here, you will trigger the forkserver. Try not to/do that in place_input. :)
        不要在这里uc.run_emu，这个玩意会触发forkserver
    """
    pass


# This function gets the current input and places it in the memory.
    # 获得当前输入并且在内存里取代它
# It will be called for each execution, so keep it lightweight.
    # 每次执行都会调用
# This can be compared to a testcase in libfuzzer.
    # 可以类比libfuzzer里的测试案例
# if you want to ignore an input, you can os._exit(0) here (anything else is a lot slower)
    # 如果想忽略输入，os._exit(0)
def place_input_skb(ucf: Unicorefuzz, uc: Uc, input: bytes) -> None:
    """
    Places the input in memory and alters the input.
    This is an example for sk_buff in openvsswitch
    """

    if len(input) > 1500:
        import os

        os._exit(0)  # too big!

    # read input to the correct position at param rdx here:
    rdx = uc.reg_read(UC_X86_REG_RDX)
    rdi = uc.reg_read(UC_X86_REG_RDI)
    ucf.map_page(uc, rdx)  # ensure sk_buf is mapped
    bufferPtr = struct.unpack("<Q", uc.mem_read(rdx + 0xD8, 8))[0]
    ucf.map_page(uc, bufferPtr)  # ensure the buffer is mapped
    uc.mem_write(rdi, input)  # insert afl input
    uc.mem_write(rdx + 0xC4, b"\xdc\x05")  # fix tail


def place_input(ucf: Unicorefuzz, uc: Uc, input: bytes) -> None:
    rax = uc.reg_read(UC_X86_REG_RAX)
    # make sure the parameter memory is mapped
    ucf.map_page(uc, rax)
    uc.mem_write(rax, input)  # insert afl input
