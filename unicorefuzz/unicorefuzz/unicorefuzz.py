
#ucf的核心
"""
The heart of all ucf actions.
Defines most functionality used by the harnesses.
"""
import os
import signal
import time
from typing import List, Dict, Optional

# unicornafl avatar2 unicorefuzz
from avatar2 import X86_64, ARM_CORTEX_M3, ARMV7M, ARMBE
from avatar2.archs import Architecture
from avatar2.archs.arm import ARM
from avatar2.archs.x86 import X86
from capstone import Cs
from unicornafl import (
    UC_ERR_READ_UNMAPPED,
    UC_ERR_READ_PROT,
    UC_ERR_READ_UNALIGNED,
    UC_ERR_WRITE_UNMAPPED,
    UC_ERR_WRITE_PROT,
    UC_ERR_WRITE_UNALIGNED,
    UC_ERR_FETCH_UNMAPPED,
    UC_ERR_FETCH_PROT,
    UC_ERR_FETCH_UNALIGNED,
    UC_ERR_INSN_INVALID,
    UC_ARCH_X86,
    UC_MODE_32,
    UC_MODE_64,
    arm_const,
    x86_const,
    Uc,
    UcError,
)

from unicorefuzz import x64utils, configspec

# unicornafl 是用的AFL++里的unicorn mode
AFL_PATH = "AFLplusplus"
UNICORN_IN_AFL = os.path.join("unicorn_mode", "unicorn")

# 默认页大小， 探测封装等待时间
DEFAULT_PAGE_SIZE = 0x1000
PROBE_WRAPPER_WAIT_SECS = 0.5

X64 = X86_64  # type: Architecture
REQUEST_FOLDER = "requests"
STATE_FOLDER = "state"
REJECTED_ENDING = ".rejected"

# 对avatar2的一些修补
# X86估计是一个结构体之类的， 没有初始化就可以赋值？
# TODO:
# Fix avatar2 x86 mode upstream
# (ARM already contains unicorn_* and pc_name)
X86.pc_name = "eip"
X86.unicorn_arch = UC_ARCH_X86
X86.unicorn_mode = UC_MODE_32
X64.pc_name = "rip"
# unicorn_arch is the same/inherited from X86
X64.unicorn_mode = UC_MODE_64

ARM.unicorn_consts = arm_const
X86.unicorn_consts = x86_const

ARM.unicorn_reg_tag = "UC_ARM_REG_"
ARM.ignored_regs = []
ARM.insn_nop = b"\x00\x00\x00\x00"
X86.unicorn_reg_tag = "UC_X86_REG_"
X86.ignored_regs = ["cr0"]  # CR0 unicorn crash
X86.insn_nop = b"\x90"
X64.ignored_regs = X86.ignored_regs + ["fs", "gs"]  # crashes unicorn too

# base_base = X86.unicorn_consts.UC_X86_REG_MXCSR
# x86_const.UC_X86_REG_GS_BASE = base_base + 1
# x86_const.UC_X86_REG_FS_BASE = base_base + 2

# 支持的架构： X86，X86_64， ...
# TODO: Add mips? ARM64? More archs?
archs = {
    "x86": X86,
    "x86_64": X64,
    "x64": X64,
    "arm": ARM,
    "arm_cortex_m3": ARM_CORTEX_M3,
    "arm_v7m": ARMV7M,
    "armbe": ARMBE,
}


# 从@begin模拟到@until
# emulate from @begin, and stop when reaching address @until
# def uc_forkserver_start(uc: Uc, exits: List[int]) -> None:
# import ctypes
# from unicornafl import unicorn

# exit_count = len(exits)
# unicorn._uc.uc_afl_forkserver_start(
#    uc._uch, ctypes.c_size_t(exit_count), (ctypes.c_uint64 * exit_count)(*exits)
# )


# 获取所有的架构所支持的寄存器
def regs_from_unicorn(arch: Architecture) -> List[str]:
    """
    Get all (supported) registers of an arch from Unicorn constants
    """
    # noinspection PyUnresolvedReferences
    consts = arch.unicorn_consts

    # 大的for循环配合上一些split过滤
    regs = [
        k.split("_REG_")[1].lower()
        # 学一下这个东西
        for k, v in consts.__dict__.items()
        if not k.startswith("__") and "_REG_" in k and "INVALID" not in k
    ]

    # if arch == X64:
    # These two are not directly supported by unicorn.
    # x64的unicorn不支持gs和fs寄存器
    # regs += ["gs_base", "fs_base"]
    return regs


# 从所有的Unicorn consts架构当中读取寄存器名字
# for: 分架构名字
#     regs_from_unicorn()
def _init_all_reg_names():
    """
    Read all register names for an arch from Unicorn consts
    """
    for arch in archs.values():
        # noinspection PyTypeChecker
        arch.reg_names = regs_from_unicorn(arch)


_init_all_reg_names()


def uc_reg_const(arch: Architecture, reg_name: str) -> int:
    """
    Returns an unicorn register constant to address the register by name.
    i.e.:
    `uc_reg_const("x64", "rip") #-> UC_X86_REG_RIP`
    """
    # noinspection PyUnresolvedReferences
    # arch.unicorn_consts里有属性，根据参数返回一个字符串
    return getattr(arch.unicorn_consts, arch.unicorn_reg_tag + reg_name.upper())


# 返回架构实例
'''
    archs = {
        "x86": X86,
        "x86_64": X64,
        "x64": X64,
        "arm": ARM,
        "arm_cortex_m3": ARM_CORTEX_M3,
        "arm_v7m": ARMV7M,
        "armbe": ARMBE,
    }
'''
def get_arch(archname: str) -> Architecture:
    """
    Look up Avatar architecture, add Ucf extras and return it
    """
    return archs[archname.lower()]


# Unicorefuzz 大类
class Unicorefuzz:
    def __init__(self, config: [str, "configspec"]) -> None:
        # 根据config加载配置
        if isinstance(config, str):
            from unicorefuzz.configspec import load_config

            config = load_config(config)
        # 配置
        self.config = config  # type: configspec
        # 获取架构
        self.arch = get_arch(config.ARCH)  # type: Architecture

        # 缓存映射的页，字典：地址 -> 内存
        self._mapped_page_cache = {}  # type: Dict[int, bytes]

        # capstone实例， 用来反汇编等等
        self.cs = Cs(self.arch.capstone_arch, self.arch.capstone_mode)  # type: Cs

        # 状态地址
        self.statedir = os.path.join(config.WORKDIR, "state")  # type: str

        # 请求地址（文件名就是请求数据的地址）
        self.requestdir = os.path.join(config.WORKDIR, "requests")  # type: str

        # 退出地址
        self.exits = None  # type: Optional[List[int]]
        # fore some things like the fuzz child we want to disable logging, In this case, we set should_log to False.
        
        # 是否日志
        self.should_log = True  # type: bool

    # 阻塞到请求目录是可达的
    def wait_for_probe_wrapper(self) -> None:
        """
        Blocks until the request folder gets available
        """
        while not os.path.exists(self.requestdir):
            print("[*] Waiting for probewrapper to be available...")
            print("    ^-> UCF workdir is {}".format(self.config.WORKDIR))
            time.sleep(PROBE_WRAPPER_WAIT_SECS)

    # 计算退出地址
    # 配置里的退出地址（config.EXITS）+ （entry + 相对偏移（config.ENTRY_RELATIVE_EXITS））
    def calculate_exits(self, entry: int) -> List[int]:
        config = self.config
        # add MODULE_EXITS to EXITS
        exits = config.EXITS + [x + entry for x in config.ENTRY_RELATIVE_EXITS]
        return exits

    # 根据地址返回对应的文件名字
    def path_for_page(self, address: int) -> str:
        """
        Return the filename for a page
        """
        base_address = self.get_base(address)
        return os.path.join(
            self.config.WORKDIR, "state", "{:016x}".format(base_address)
        )

    #退出
    def exit(self, exitcode: int = 1) -> None:
        """
        Exit it
        :param exitcode:
        """
        os._exit(exitcode)

    # 强制退出
    # 调用os.kill()
    def force_crash(self, uc_error: UcError) -> None:
        """
        This function should be called to indicate to AFL that a crash occurred during emulation.
        Pass in the exception received from Uc.emu_start()
        :param uc_error: The unicorn Error
        """
        #内存错误
        mem_errors = [
            UC_ERR_READ_UNMAPPED,
            UC_ERR_READ_PROT,
            UC_ERR_READ_UNALIGNED,
            UC_ERR_WRITE_UNMAPPED,
            UC_ERR_WRITE_PROT,
            UC_ERR_WRITE_UNALIGNED,
            UC_ERR_FETCH_UNMAPPED,
            UC_ERR_FETCH_PROT,
            UC_ERR_FETCH_UNALIGNED,
        ]
        if uc_error.errno in mem_errors:
            # 内存错误，直接段错误
            # Memory error - throw SIGSEGV
            os.kill(os.getpid(), signal.SIGSEGV)
        elif uc_error.errno == UC_ERR_INSN_INVALID:
            # 指令错误
            # Invalid instruction - throw SIGILL
            os.kill(os.getpid(), signal.SIGILL)
        else:
            # 其他错误
            # Not sure what happened - throw SIGABRT
            os.kill(os.getpid(), signal.SIGABRT)

    # 序列化spec（不知道啥玩意）
    def serialize_spec(self) -> str:
        """
        Serializes the config spec.
        :return: The spec
        """
        return configspec.serialize_spec(self.config)

    def print_spec(self) -> None:
        """
        Prints the config spec
        """
        print(self.serialize_spec())

    # 映射内存
    # 请求 probe_wrapper
    def map_page(self, uc: Uc, addr: int) -> None:
        """
        Maps a page at addr in the harness, asking probe_wrapper.
        :param uc: The unicore
        :param addr: The address
        """
        # 页大小
        page_size = self.config.PAGE_SIZE
        # 基地址
        base_address = self.get_base(addr)
        # 如果不在缓存里
        if base_address not in self._mapped_page_cache.keys():
            # 获得输入文件名和dump文件名
            '''
                requestdir
                statedir?
                outdir?
            '''
            input_file_name = os.path.join(self.requestdir, "{:016x}".format(addr))
            dump_file_name = os.path.join(self.statedir, "{:016x}".format(base_address))
            # 如果 dump_file_name + ".rejected" 存在，直接kill
            if os.path.isfile(dump_file_name + REJECTED_ENDING): # ".rejected"
                print("CAN I HAZ EXPLOIT?")
                os.kill(os.getpid(), signal.SIGSEGV)
            # dump的文件不存在，创建
            if not os.path.isfile(dump_file_name):
                open(input_file_name, "a").close()
            # 打印日志
            if self.should_log:
                print("mapping {}".format(hex(base_address)))
            
            # forever loop
            while 1:
                try:
                    if os.path.isfile(dump_file_name + REJECTED_ENDING):
                        print("CAN I HAZ EXPLOIT?")
                        os.kill(os.getpid(), signal.SIGSEGV)
                    with open(dump_file_name, "rb") as f:
                        content = f.read()
                        # 必须读满 page_size的大小
                        if len(content) < page_size:
                            time.sleep(0.001)
                            continue
                        self._mapped_page_cache[base_address] = content
                        # uc的mem_map方法映射内存
                        #     mem_write方法写入内存
                        uc.mem_map(base_address, len(content))
                        uc.mem_write(base_address, content)
                        return
                except IOError:
                    pass
                except UcError as ex:
                    return
                except Exception as ex:  # todo this should never happen if we don't map like idiots
                    print(
                        "map_page failed: base address=0x{:016x} ({})".format(
                            base_address, ex
                        )
                    )
                    # exit(1)

    # AFL的地址
    @property
    def afl_path(self) -> str:
        """
        Calculate afl++ path
        :return: The folder AFLplusplus lives in
        """
        return os.path.abspath(os.path.join(self.config.UNICORE_PATH, AFL_PATH))

    @property
    def libunicorn_path(self) -> str:
        """
        Calculate the libunicorn path
        :return Whereever unicorn.so resides lives in the system
        """
        return os.path.abspath(os.path.join(self.afl_path, UNICORN_IN_AFL))

    # 获取基地址
    def get_base(self, addr: int) -> int:
        """
        Calculates the base address (aligned to PAGE_SIZE) to an address, using default configured page size
        All you base are belong to us.
        :param addr: the address to get the base for
        :return: base addr
        """
        page_size = self.config.PAGE_SIZE
        return addr - addr % page_size
