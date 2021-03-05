
#!/usr/bin/env python
"""
Main (Unicorn-)Harness, used alongside AFL.
"""
import argparse
import gc
import os
import sys
import time
from typing import Optional, Tuple, Dict, List
# 引入capstone
from capstone import Cs
from unicornafl import *

from unicorefuzz import x64utils
from unicorefuzz.unicorefuzz import (
    Unicorefuzz,
    REJECTED_ENDING,
    X64,
    uc_reg_const,
)

# no need to print if we're muted
CHILD_SHOULD_PRINT = os.getenv("AFL_DEBUG_CHILD_OUTPUT")


# 调试输出指令
def unicorn_debug_instruction(
    uc: Uc, address: int, size: int, user_data: "Unicorefuzz"
) -> None:
    cs = user_data.cs  # type: Cs
    try:
        # 读内存
        mem = uc.mem_read(address, size)
        # 调用cs disasm_lite方法反编译
        for (cs_address, cs_size, cs_mnemonic, cs_opstr) in cs.disasm_lite(
            bytes(mem), size
        ):
            if CHILD_SHOULD_PRINT:
                print(
                    "    Instr: {:#016x}:\t{}\t{}".format(
                        address, cs_mnemonic, cs_opstr
                    )
                )
    except Exception as e:
        print(hex(address))
        print("e: {}".format(e))
        print("size={}".format(size))
        for (cs_address, cs_size, cs_mnemonic, cs_opstr) in cs.disasm_lite(
            bytes(uc.mem_read(address, 30)), 30
        ):
            print("    Instr: {:#016x}:\t{}\t{}".format(address, cs_mnemonic, cs_opstr))


# block调试输出
def unicorn_debug_block(uc: Uc, address: int, size: int, user_data: None) -> None:
    print("Basic Block: addr=0x{:016x}, size=0x{:016x}".format(address, size))

# 内存访问调试信息
def unicorn_debug_mem_access(
    uc: Uc, access: int, address: int, size: int, value: int, user_data: None
) -> None:
    if access == UC_MEM_WRITE:
        print(
            "        >>> Write: addr=0x{:016x} size={} data=0x{:016x}".format(
                address, size, value
            )
        )
    else:
        print("        >>> Read: addr=0x{:016x} size={}".format(address, size))


# 内存无效访问
def unicorn_debug_mem_invalid_access(
    uc: Uc, access: int, address: int, size: int, value: int, user_data: "Harness"
):
    harness = user_data  # type Unicorefuzz
    if CHILD_SHOULD_PRINT:
        print(
            "unicorn_debug_mem_invalid_access(uc={}, access={}, addr=0x{:016x}, size={}, value={}, ud={}, afl_child={})".format(
                uc, access, address, size, value, user_data, user_data.is_afl_child
            )
        )
    # 无效的写
    if access == UC_MEM_WRITE_UNMAPPED:
        if CHILD_SHOULD_PRINT:
            print(
                "        >>> INVALID Write: addr=0x{:016x} size={} data=0x{:016x}".format(
                    address, size, value
                )
            )
    else:
    # 无效的读
        if CHILD_SHOULD_PRINT:
            print(
                "        >>> INVALID Read: addr=0x{:016x} size={}".format(address, size)
            )
    try:
        # 映射内存
        harness.map_page(uc, address)
    except KeyboardInterrupt:
        uc.emu_stop()
        return False
    return True

# Harness大类
# 从probe wrapper中接收内存并在unicorn中运行
class Harness(Unicorefuzz):
    """
    The default harness, receiving memory from probe wrapper and running it in unicorn.
    """

    def __init__(self, config) -> None:
        super().__init__(config)
        # 两个不知道做什么用的
        # 获取的寄存器
        self.fetched_regs = None  # type: Optional[Dict[str, int]]
        # Will be set to true if we are a afl-forkser child.
        # 是否是afl的孩子
        self.is_afl_child = False  # type: bool
    # 默认的harness
    def harness(self, input_file: str, wait: bool, debug: bool, trace: bool) -> None:
        """
        The default harness, receiving memory from probe wrapper and running it in unicorn.
        :param input_file: the file to read
            读取的文件
        :param wait: if we want to wait
            是否等待
        :param debug: if we should enable unicorn debugger
            是否开启unicorn调试
        :param trace: trace or not
            是否追踪
        """

        # Exit without clean python vm shutdown:
        # "The os._exit() function can be used if it is absolutely positively necessary to exit immediately"
            #os._exit()退出的更彻底？
        # Many times faster!
        # noinspection PyProtectedMember
        # 如果没有设置UCF_DEBUG_CLEAN_SHUTDOWN就os._exit，否则exit
        exit_func = os._exit if not os.getenv("UCF_DEBUG_CLEAN_SHUTDOWN") else exit

        # In case we need an easy way to debug mem loads etc.
            # 调试内存加载？
        init_sleep = os.getenv("UCF_DEBUG_SLEEP_BEFORE_INIT")
        if init_sleep:
            print(
                "[d] Sleeping. Unicorn init will start in {} seconds.".format(
                    init_sleep
                )
            )
            time.sleep(float(init_sleep))

        # 设置CHILD_SHOULD_PRINT选项的
        if debug or trace:
            # TODO: Find a nicer way to do this :)
            global CHILD_SHOULD_PRINT
            CHILD_SHOULD_PRINT = True

        # uc_init函数就在下面
        uc, entry, exits = self.uc_init(
            input_file, wait, trace, verbose=(debug or trace)
        )
        if debug:
            # debug的话就直接uc_debug
            self.uc_debug(uc, input_file, exits)
            print("[*] Debugger finished :)")
        else:
            # 否则uc_fuzz目标文件
            if self.uc_fuzz(uc, input_file, exits):
                print("[*] Done fuzzing. Cya.")
            else:
                print("[*] Finished one run (without AFL).")

    def uc_init(
        self, input_file, wait: bool = False, trace: bool = False, verbose: bool = False
    ) -> Tuple[Uc, int, List[int]]:
        """
        Initializes unicorn with the given params
            用参数初始化unicorn
        :param input_file: input file to drop into the emulator with config.init_func
        :param wait: block until state dir becomes available
        :param trace: if we should add trace hooks to unicorn
        :param verbose: enables some more logging
        :return: Tuple of (unicorn, entry_point, exits)
        """
        config = self.config
        # 初始化uc
        uc = Uc(self.arch.unicorn_arch, self.arch.unicorn_mode)

        # 如果设置了trace就hook code、block、内存访问的操作等等
        if trace:
            print("[+] Settings trace hooks")
            uc.hook_add(UC_HOOK_BLOCK, unicorn_debug_block)
            uc.hook_add(UC_HOOK_CODE, unicorn_debug_instruction, self)
            uc.hook_add(
                UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ | UC_HOOK_MEM_FETCH,
                unicorn_debug_mem_access,
            )

        # 如果设置了等待就等待probe_wrapper
        if wait:
            self.wait_for_probe_wrapper()

        # 啰嗦模式 hh
        if verbose:
            print("[*] Reading from file {}".format(input_file))

        # we leave out gs_base and fs_base on x64 since they start the forkserver
        # 加载寄存器
        self.uc_load_registers(uc)

        # let's see if the user wants a change.
        # 初始化函数，和config.py里的初始化函数相同，用户自定义
        config.init_func(self, uc)

        # get pc from unicorn state since init_func may have altered it.
        # config.init_func可能改变寄存器，所以读取寄存器？
        pc = self.uc_read_pc(uc)

        # 映射内存
        self.map_known_mem(uc)

        # 计算所有的退出点
        exits = self.calculate_exits(pc)
        if not exits:
            raise ValueError(
                "No exits founds. Would run forever... Please set an exit address in config.py."
            )

        # On error: map memory, add exits.
        # map错误处理回调函数
        uc.hook_add(UC_HOOK_MEM_UNMAPPED, unicorn_debug_mem_invalid_access, self)

        # 如果设置了调试内存
        if os.getenv("UCF_DEBUG_MEMORY"):
            # pympler库作用未知
            from pympler import muppy, summary

            all_objects = muppy.get_objects()
            sum1 = summary.summarize(all_objects)
            summary.print_(sum1)

        # Last chance to hook before forkserver starts (if running as afl child)
        # 最后一次hook的机会
        fork_sleep = os.getenv("UCF_DEBUG_SLEEP_BEFORE_FORK")
        if fork_sleep:
            print(
                "[d] Sleeping. Forkserver will start in {} seconds.".format(fork_sleep)
            )
            time.sleep(float(fork_sleep))

        return uc, pc, exits

    # uc调试模式
    def uc_debug(self, uc: Uc, input_file: str, exits: List[int]) -> None:
        """
        Start uDdbg debugger for the given unicorn instance
            为unicorn实例启动调试
        :param uc: The unicorn instance
            unicorn实例
        :param input_file: The (afl)input file to read
            输入文件
        :param exits: List of exits that end fuzzing
            退出点
        """
        print("[*] Loading debugger...")
        # noinspection PyUnresolvedReferences
        # udbg实例
        from udbg import UnicornDbg

        udbg = UnicornDbg()

        # The afl_forkserver_start() method sets the exits correctly.
            # afl_forkserver_start正确的设置退出点
        # We don't want to actually fork, though, so make sure that return is False.
        if uc.afl_forkserver_start(exits) != uc.UC_AFL_RET_NO_AFL:
            raise Exception(
                "Debugger cannot run in AFL! Did you mean -t instead of -d?"
            )

        with open(input_file, "rb") as f:  # load AFL's input
        # 加载输入文件
            input = f.read()
        try:
            # 替换输入
            self.config.place_input(self, uc, input)
        except Exception as ex:
            raise Exception(
                "[!] Error setting testcase for input {}: {}".format(input, ex)
            )
        # 入口点
        entry_point = self.uc_read_pc(uc)
        # 退出点
        # 改了一下，这个位置不知道是不是作者写错了
        #exit_point = self.exits[0]
        exit_point = exits[0]

        # uddbg wants to know some mappings, read the current stat from unicorn to have $something...
        # TODO: Handle mappings differently? Update them at some point? + Proper exit after run?
        '''
            map表
        '''
        mappings = [
            (hex(start), start, (end - start + 1))
            for (start, end, perms) in uc.mem_regions()
        ]

        # 初始化
        udbg.initialize(
            emu_instance=uc,
            entry_point=entry_point,
            exit_point=exit_point,
            hide_binary_loader=True,
            mappings=mappings,
        )

        def dbg_except(x, y):
            raise Exception(y)

        os.kill = dbg_except

        # 开始
        udbg.start()
        # TODO will never reach done, probably.
        print("[*] Done.")

    #
    def uc_fuzz(self, uc: Uc, input_file: str, exits: List[int]) -> bool:
        """
        Run initialized unicorn
            运行初始化的unicorn
        :param uc: the Unicorn instance  to work on
        :param input_file: The afl input file
        :param exits: List of exit addresses to end fuzzing at

        :returns: True, if we're in the parent after fuzzing, False otherwise.
        """

        # 替换入口点位置
        def input_callback(uc: Uc, input: bytes, persistent_round: int, data: Harness):
            # We need to reset the entry point for persistence mode.
            self.config.place_input(data, uc, input)

        # def crash_callback(
        #    uc: Uc, uc_ret: UcError, input: bytes, persistent_round: int, data: Harness
        # ):
        #   print("input", uc, uc_ret, input, persistent_round, data)
        #   print("crashing", args)

        try:
            # 启动fuzz
            return uc.afl_fuzz(
                input_file=input_file,
                place_input_callback=input_callback,
                exits=exits,
                validate_crash_callback=None,  # TODO: self.crash_callback,
                persistent_iters=1,  # TODO: Still needs some sort of reset between runs!
                data=self,
            )
        except UcError as e:
            print(
                "[!] Execution failed with error: {} at address {:x}".format(
                    e, self.uc_read_pc(uc)
                )
            )

    # 映射内存
    def map_known_mem(self, uc: Uc):
        """
        Maps all memory known
        :param uc:
        :return:
        """
        # 映射statedir中的文件
        for filename in os.listdir(self.statedir):
            if (
                not filename.endswith(REJECTED_ENDING)
                and filename not in self.fetched_regs
            ):
                try:
                    address = int(filename, 16)
                    self.map_page(uc, address)
                except Exception:
                    pass

    # 如果reject，报错
    def _raise_if_reject(self, base_address: int, dump_file_name: str) -> None:
        """
        If dump_file_name + REJECTED_ENDING exists, raises exception
            如果dump_file_name + REJECTED_ENDING这个文件存在，触发异常
        :param base_address: the base addr we're currently working with
            基地址：工作的基地址
        :param dump_file_name: the dump filename
            dump的文件名字
        """
        # 如果这个文件存在
        if os.path.isfile(dump_file_name + REJECTED_ENDING):
            # 大佬这话文明考吗
            with open(dump_file_name + REJECTED_ENDING, "r") as f:
                # 错误信息
                err = "".join(f.readlines()).strip()
                # TODO: Exception class?
                raise Exception(
                    "Page at 0x{:016x} was rejected by target: {}".format(
                        base_address, err
                    )
                )

    # 获取页块
    def fetch_page_blocking(self, address: int) -> Tuple[int, bytes]:
        """
        Fetches a page at addr in the harness, asking probe wrapper, if necessary.
        returns base_address, content
        """
        # 基地址
        base_address = self.get_base(address)
        # 输入文件名
        input_file_name = os.path.join(self.requestdir, "{0:016x}".format(address))
        # dump文件名
        dump_file_name = os.path.join(self.statedir, "{0:016x}".format(base_address))
        # 如果base_address在缓存当中
        if base_address in self._mapped_page_cache.keys():
            # 返回
            return base_address, self._mapped_page_cache[base_address]
        else:
            self._raise_if_reject(base_address, dump_file_name)
            # Creating the input file == request
            # 不存在输入文件，创建
            if not os.path.isfile(dump_file_name):
                open(input_file_name, "a").close()
            if self.should_log:
                print(
                    "Requesting page 0x{:016x} from `ucf attach`".format(base_address)
                )
            while 1:
                self._raise_if_reject(base_address, dump_file_name)
                try:
                    # 打开
                    with open(dump_file_name, "rb") as f:
                        content = f.read()
                        # 必须读够一个页的大小
                        if len(content) < self.config.PAGE_SIZE:
                            time.sleep(0.001)
                            continue
                        缓存
                        self._mapped_page_cache[base_address] = content
                        return base_address, content
                except IOError:
                    pass

    # 获取寄存器
    def _fetch_register(self, name: str) -> int:
        """
        Loads the value of a register from the dumped state.
        Used internally: later, rely on `ucf.regs[regname]`.
        :param name The name
        :returns the content of the register
        """
            # statedir目录下面有各个寄存器
        with open(os.path.join(self.statedir, name), "r") as f:
            return int(f.read())

    # 加载所有寄存器
    def uc_load_registers(self, uc: Uc) -> None:
        """
        Loads all registers to unicorn, called in the harness.
        """
        regs = self.fetch_all_regs()
        for key, value in regs.items():
            # 如果是被忽略的，直接返回
            if key in self.arch.ignored_regs:
                # print("[d] Ignoring reg: {} (Ignored)".format(key))
                continue
            try:
                # 写入寄存器的值
                uc.reg_write(uc_reg_const(self.arch, key), value)
            except Exception as ex:
                print("[d] Faild to load reg: {} ({})".format(key, ex))
                pass

    def uc_reg_const(self, reg_name: str) -> int:
        """
        Gets the reg const for the current arch
        :param reg_name: the reg name
        :return: UC_ const for the register of this name
        """
        return uc_reg_const(self.arch, reg_name)

    # 读取寄存器
    def uc_reg_read(self, uc: Uc, reg_name: str) -> int:
        """
        Reads a register by name, resolving the UC const for the current architecture.
        Handles potential special cases like base registers
        :param uc: the unicorn instance to read the register from
        :param reg_name: the register name
        :return: register content
        """
        reg_name = reg_name.lower()
        # if reg_name == "fs_base":
        #    return x64utils.get_fs_base(uc, self.config.SCRATCH_ADDR)
        # if reg_name == "gs_base":
        #    return x64utils.get_gs_base(uc, self.config.SCRATCH_ADDR)
        # else:
        return uc.reg_read(self.uc_reg_const(reg_name))

    # 寄存器写
    def uc_reg_write(self, uc: Uc, reg_name: str, val: int) -> int:
        """
        Reads a register by name, resolving the UC const for the current architecture.
        Handles potential special cases like base registers
        :param uc: the unicorn instance to read the register from
        :param reg_name: the register name
        :param val: the register content
        """
        reg_name = reg_name.lower()
        # if reg_name == "fs_base":
        #    return x64utils.get_fs_base(uc, self.config.SCRATCH_ADDR)
        # if reg_name == "gs_base":
        #    return x64utils.get_gs_base(uc, self.config.SCRATCH_ADDR)
        # else:
        return uc.reg_write(self.uc_reg_const(reg_name), val)

    # 读取内存页
    def uc_read_page(self, uc: Uc, addr: int) -> Tuple[int, bytes]:
        """
        Reads a page at the given addr from unicorn.
        Resolves the base addr automatically.
        :param uc: The unicorn instance
        :param addr: An address inside the page to read
        :return: Tuple of (base_addr, content)
        """
        base_addr = self.get_base(addr)
        # 调用mem_read读取内存
        return base_addr, uc.mem_read(base_addr, self.config.PAGE_SIZE)

    # 读取所有寄存器
    def fetch_all_regs(self, refetch: bool = False) -> Dict[str, int]:
        """
        Fetches all registers from state folder
        :param refetch: reload them from disk (defaults to False)
        :return: regname to content mapping
        """
        # 如果refetch为真并且fetched_regs为空
        if refetch or self.fetched_regs is None:
            self.fetched_regs = {}
            for reg_name in self.arch.reg_names:
                try:
                    # 获取寄存器的值
                    self.fetched_regs[reg_name] = self._fetch_register(reg_name)
                except Exception as ex:
                    # print("Failed to retrieve register {}: {}".format(reg_name, ex))
                    pass
        return self.fetched_regs

    # 获取pc
    def uc_read_pc(self, uc) -> int:
        """
        Gets the current pc from unicorn for this arch
        :param uc: the unicorn instance
        :return: value of the pc
        """
        # noinspection PyUnresolvedReferences
        return uc.reg_read(uc_reg_const(self.arch, self.arch.pc_name))

    # 改变pc的值
    def uc_write_pc(self, uc, val) -> int:
        """
        Sets the program counter of a unicorn instance
        :param uc: Unicorn instance
        :param arch: the architecture to use
        :param val: the value to write
        """
        return uc.reg_write(uc_reg_const(self.arch, self.arch.pc_name), val)
