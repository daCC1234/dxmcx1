#############################################################################
#
#    Copyright (C) 2020
#    Giovanni -iGio90- Rocca, Vincenzo -rEDSAMK- Greco
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>
#
#############################################################################
#
# Unicorn DOPE Debugger
#
# Runtime bridge for unicorn emulator providing additional api to play with
# Enjoy, have fun and contribute
#
# Github: https://github.com/iGio90/uDdbg
# Twitter: https://twitter.com/iGio90
#
#############################################################################

from typing import List, Tuple

# 从 prompt_toolkit 中引入 FormattedText
from prompt_toolkit.formatted_text import FormattedText

# 模块？
from udbg.modules.core_module import CoreModule
from udbg.modules import binary_loader, memory, module_test, registers, mappings, patches, asm, configs, executors, \
    find, stepover

# 引入了 prompt_toolkit 中的很多库
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.shortcuts import prompt

# termcolor 颜色
from termcolor import colored
from unicorn import *
from unicorn import unicorn_const

import sys
import udbg.utils as utils
import copy
from udbg.arch import *

# 提示符
MENU_APPENDIX = '$>'

# 不知道啥，和显示有关
MENU_APIX = '[' + colored('*', 'cyan', attrs=['bold', 'dark']) + ']'


# UnicornDbg 核心类，所有的函数，功能和执行流
class UnicornDbgFunctions(object):
    """
    The core class of the UnicornDbg. With this we manage all the functions, functionality and execution flow
    """

    
    def __init__(self, unicorndbg_instance):
        # in context_map we keep a list of loaded modules associated with their instances.
        # We will use them in exec_command

        # context_map保存所有加载的模块和它们的实例，将在exec_command
        self.context_map = {
            "self": self,
        }

        # in commands_map we keep a list of loaded commands from all the modules
        # commands_map 中保存一个从所有模块中加载的命令列表
        self.commands_map = {}

        # 调试实例
        self.unicorndbg_instance = unicorndbg_instance

        
        # load modules
        try:
            # 调用加载核心模块
            self.load_core_modules()
        except Exception as e:
            print(e)
            self.quit()
    # 加载核心模块
    def load_core_modules(self):
        '''
            加载的模块
            CoreModule
            mappings.Mappings
            memory.Memory
            registers.Registers
            patches.Patches
            asm.ASM
            configs.Configs
            executors.Executors
            find.Find
            stepover.StepOver
        '''
        # 创建核心模块实例 CoreModule()
        core_module_instance = CoreModule(self)
        # 添加模块
        self.add_module(core_module_instance)

        # 映射的模块
        mappings_module = mappings.Mappings(self)
        # 添加模块
        self.add_module(mappings_module)


        memory_module = memory.Memory(self)
        self.add_module(memory_module)

        registers_module = registers.Registers(self)
        self.add_module(registers_module)

        patches_module = patches.Patches(self)
        self.add_module(patches_module)

        asm_module = asm.ASM(self)
        self.add_module(asm_module)

        configs_module = configs.Configs(self)
        self.add_module(configs_module)

        executors_module = executors.Executors(self)
        self.add_module(executors_module)

        find_module = find.Find(self)
        self.add_module(find_module)

        stepover_module = stepover.StepOver(self)
        self.add_module(stepover_module)

    def exec_command(self, command, args):
        # 执行命令
        """
        the core method of commands exec, it tries to fetch the requested command,
            执行命令核心方法，提取请求的命令
        bind to the right context and call the associated function
            绑定到正确的上下文中，调用相应的函数

        TODO:
        :param command: requested command
        :param args: arguments array
        :return:
        """

        # save the found command and sub_command array
        # complete_command_array 保存找到的命令和子命令的数组
        complete_command_array = [command]
        try:
            # 如果是空命令直接返回
            if command == '':
                return
            
            # 如果命令位于 commands_map
            if command in self.commands_map:
                
                # if we found the command but has the "ref" property,
                    # 如果找到了命令但是有 ref（指向）属性
                # so we need to reference to another object. Ex. short command q --references--> quit
                    # 需要引用另一个实例，比如命令简称
                if 'ref' in self.commands_map[command]:
                    # 新com指向ref指向的命令
                    com = self.commands_map[self.commands_map[command]['ref']]
                else:
                    # 否则命令就是它自己内部保存的命令
                    com = self.commands_map[command]


                # if we have no arguments no sub_command exist, else save the first argument
                
                last_function = False
                if len(args) > 0:
                    # 没有子命令，子命令就是 第一个选项 args[0]，可能的子命令？
                    possible_sub_command = args[0]
                else:
                    possible_sub_command = None

                # now iterate while we have a valid sub_command,
                    # 当有子命令的时候遍历
                # when we don't find a valid sub_command exit and the new command will be the sub_command
                    # 当没有找到有效的子命令，退出，新的命令是sub_command
                # save the sub_command parent
                    # 保存子命令的母命令
                prev_command = com

                while last_function is False:
                    # if the sub command is a ref, catch the right command
                        # 如果子命令中有引用，com保存它正确命令
                    if 'ref' in com:
                        com = prev_command['sub_commands'][com['ref']]
                    if 'sub_commands' in com and possible_sub_command:
                        # 如果possible_sub_command存在，com中有sub_commands项
                        if possible_sub_command in com['sub_commands']:
                            
                            prev_command = com
                            # com用它里边的子命令possible_sub_command答题
                            com = com['sub_commands'][possible_sub_command]
                            # pop the found sub_command so we can iterate on the remanings arguments
                            # 完成命令数组加入 args.pop(0)
                            complete_command_array.append(args.pop(0))
                            # 命令是possible_sub_command
                            command = possible_sub_command
                            # if there are arguments left
                            if len(args) > 0:
                                # take the first args (the next sub_command)
                                possible_sub_command = args[0]
                            else:
                                last_function = True
                        else:
                            last_function = True
                    else:
                        last_function = True

                # if the sub_command is a reference to another associated sub_command
                # 如果 sub_command是另一个相关子命令的引用
                if 'ref' in com:
                    com = prev_command['sub_commands'][com['ref']]

                # if we have a function field just fetch the context and the function name,
                    # 如果有函数域，提取它和函数名字
                # bind them and call the function passing the arguments
                    # 绑定他们，调用函数，传递参数
                
                if 'function' in com:
                    if 'args' in com['function']:
                        # 检查参数
                        args_check, args_error = utils.check_args(com['function']['args'], args)
                        if args_check is False:
                            # 检查失败
                            raise Exception(args_error)

                    # 函数上下文，根据context_map
                    context = self.context_map[com["function"]["context"]]
                    # 函数
                    funct = com["function"]["f"]
                    # 调用方法，直接getattr
                    call_method = getattr(context, funct)
                    # we pass the command name (could be useful for the called function)
                    # and possible arguments to the function
                    # 直接调用这个函数
                    call_method(command, *args)
                else:
                    # if we have no method implementation of the command
                    # print the help of the command
                    # passing all the arguments list to help function (including the command) in a unique array
                    # 如果没有实现这个函数，打印帮助信息
                    self.exec_command('help', complete_command_array)

            else:
                # 没有找到这个命令
                print("command '" + command + "' not found")
        except Exception as e:
            if isinstance(e, UcError):
                print(utils.titlify('uc error'))
                print(str(e))
            else:
                print(utils.error_format('exec_command', str(e)))
                self.exec_command('help', complete_command_array)

    # 获取调试实例
    def get_dbg_instance(self):
        """ expose dbg instance """
        return self.unicorndbg_instance

    # 获取模拟实例
    def get_emu_instance(self):
        """ expose emu instance """
        return self.unicorndbg_instance.get_emu_instance()

    # 获取capstone实例
    def get_cs_instance(self):
        """ expose capstone instance """
        return self.unicorndbg_instance.get_cs_instance()

    # 获取模块
    def get_module(self, module_key):
        return self.context_map[module_key]

    # 添加模块
    def add_module(self, module):
        """
        add a module to the core.

        :param module: class instance of the module
        :return:
        """
        # 获取实例名
        context_name = module.get_context_name()
        # 获取命令名
        command_map = module.get_command_map()

        try:
            # get the context_name (or module name) and the command_map from the module.
                # 从模块中获得实例名命令map
            # These 2 functions are ensured by class inheritance of UnicornDbgModule
            # check if is all valid and if we have not already loaded it
                # 检查是否都有效，是否我们还没有加载它
            if context_name not in self.commands_map and context_name not in self.context_map and len(command_map) \
                    is not 0 and len(context_name) is not 0:

                # add the module to the context_map and push new commands on the commands_map
                # check if command already exist in the command map, if yes trigger error for the module load
                for com in command_map:
                    if com in self.commands_map:
                        raise Exception('command "' + com + '" already exist')

                # 更新 commands_map
                self.commands_map.update(copy.deepcopy(command_map))
                self.context_map[context_name] = module


                print(MENU_APIX + " Module " + colored(context_name, 'white', attrs=['underline', 'bold']) + " loaded")
                # call the module init function
                # 初始化模块
                module.init()
            else:
                raise Exception("module already loaded")
        except Exception as e:
            raise Exception("Error in adding '" + context_name + "' module.\nErr: " + str(e))

    # 批量执行
    def batch_execute(self, commands_arr):
        """
        batch execute a list of commands
        :param commands_arr: array with commands
        :return:
        """
        try:
            # 大小
            l = len(commands_arr)
            if l > 0:
                for com in commands_arr:
                    #解析命令
                    self.parse_command(com)
                print('executed ' + utils.green_bold(str(l) + ' commands') + '.')
            else:
                raise Exception
        except Exception as e:
            print(MENU_APIX + " " + colored("FAILED", 'red', attrs=['underline', 'bold']) + " " + colored(
                "batch execution of " + str(len(commands_arr)) + " commands", 'white', attrs=['underline', 'bold']))

    # 解析命令
    def parse_command(self, text):
        """
        parse command section, here we will make first filters and checks
        TODO: i think we can filter here args (like -w) from sub commands
        """
        try:
            # 分割
            command_arr = text.split(' ')

            # 取命令
            command = command_arr[0]
            
            # 参数
            args = command_arr[1:]
            
            # 执行
            self.exec_command(command, args)

        except AttributeError as e:
            print('error in parsing command')

    # 退出
    def quit(self):
        """
        exit function, here goes all the handles in order to clean quit the system
        # 退出前的清理工作
        :param args:
        :return:
        """

        # for every loaded module call the delete method for safe close
        for module in self.context_map:
            if module is not "self":
                # 清理
                self.context_map[module].delete()
        sys.exit(0)


# UnicornDbg类
class UnicornDbg(object):
    @staticmethod
    def boldify(x):
        # 加颜色
        return colored(x, attrs=['bold'])

    # 初始化
    def __init__(self, module_arr=None):
        self.arch = None # 架构
        self.mode = None # 模式
        self.is_thumb = False # 是否是thumb模式
        self.cs_arch = None # cs架构
        self.cs_mode = None # cs模式
        self.emu_instance = None  # type: Uc 模拟实例
        self.cs = None # cs实例？
        self.entry_point = None # 入口地址
        self.exit_point = None # 退出点
        self.current_address = 0x0 # 当前地址
        self.last_mem_invalid_size = 0x0 # 上一个内存无效的大小
        self.entry_context = {} # 入口上下文
        self.trace_instructions = 0x0 # 追踪指令
        self.skip_bp_count = 0x0 # 越过断点计数

        self.history = InMemoryHistory() # prompt_toolkit里的方法，不知道干啥的

        # create UnicornDbgFunctions instance
        # 创建 UnicornDbgFunctions 实例
        self.functions_instance = UnicornDbgFunctions(self)

        # if we pass an array with modules, just load them
        # remember: we can load modules both on the UnicornDbg creation and after with the
        #           add_module method

        if module_arr:
            for module in module_arr:
                # 添加模块
                self.add_module(module(self.functions_instance))

        # hold some modules
        # 保存模块
        self.core_module = self.get_module('core_module')
            # 核心模块
        self.register_module = self.get_module('registers_module')
            # 注册模块
        self.asm_module = self.get_module('asm_module')
            # 汇编模块
        # last breakpoint
            # 上一个断点
        self.last_bp = 0x0
        self.soft_bp = False # 软断点?
        self.has_soft_bp = False # 有软断点？
        self.breakpoint_count = 0x0 # 断点计数
        # mem access
        self.mem_access_result = None # 内存访问
        self.hook_mem_access = False # hook内存访问
        # hold last command
        self.last_command = None # 保存上一个命令

    # hook代码
    def dbg_hook_code(self, uc, address, size, user_data):
        """
        Unicorn instructions hook
        """
        try:
            # 设置当前地址
            self.current_address = address
            # 命中软断点
            hit_soft_bp = False
            # 打印指令？
            should_print_instruction = self.trace_instructions > 0

            # 如果软断点
            if self.soft_bp:
                # 内存访问hook
                self.hook_mem_access = True
                # 软断点
                self.soft_bp = False
                # 命中软断点置位
                hit_soft_bp = True

            # 地址不是上一个断点 and (地址在断点列表中 or 有软断点)
            if address != self.last_bp and \
                    (address in self.core_module.get_breakpoints_list() or
                     self.has_soft_bp):
                # 略过断点
                if self.skip_bp_count > 0:
                    self.skip_bp_count -= 1
                
                else:
                    # 断点数加一
                    self.breakpoint_count += 1
                    # 应该打印指令
                    should_print_instruction = False
                    # 模拟停止
                    uc.emu_stop()

                    # 上一个断点
                    self.last_bp = address

                    # 打印一些东西
                    print(utils.titlify('breakpoint'))
                    print('[' + utils.white_bold(str(self.breakpoint_count)) +
                          ']' + ' hit ' + utils.red_bold('breakpoint') +
                          ' at: ' + utils.green_bold(hex(address)))
                    self._print_context(uc, address)
            
            # 地址是上一个断点
            elif address == self.last_bp:
                self.last_bp = 0
            
            # 有软断点
            self.has_soft_bp = hit_soft_bp
            if self.current_address + size == self.exit_point:
                # 到达退出点
                should_print_instruction = False
                self._print_context(uc, address)
                print(utils.white_bold("emulation") + " finished with " + utils.green_bold("success"))
            if should_print_instruction:
                # 反汇编
                self.asm_module.internal_disassemble(uc.mem_read(address, size), address)
        except KeyboardInterrupt as ex:
            # If stuck in an endless loop, we can exit here :). TODO: does that mean ctrl+c never works for targets?
            print(utils.titlify('paused'))
            self._print_context(uc, address)
            uc.emu_stop()

    # hook内存访问
    def dbg_hook_mem_access(self, uc, access, address, size, value, user_data):
        if self.hook_mem_access:
            self.hook_mem_access = False
            # store to ensure a print after disasm
            self.mem_access_result = [address, value]

    # 无效内存hook
    def dbg_hook_mem_invalid(self, uc: Uc, access, address, size, value, userdata):
        """
        Unicorn mem invalid hook
        """
        if size < 2:
            size = self.last_mem_invalid_size
        self.last_mem_invalid_size = size
        self.register_module.registers('mem_invalid')
        # 调用utils.titlify， 作用未知
        print(utils.titlify('disasm'))
        start = max(0, self.pc - 0x16)
        self.asm_module.internal_disassemble(uc.mem_read(start, 0x32), start, address)

    # 打印上下文
    def _print_context(self, uc, pc):
        self.register_module.registers('mem_invalid')
        print(utils.titlify('disasm'))
        self.asm_module.internal_disassemble(uc.mem_read(pc - 0x16, 0x32), pc - 0x16, pc)
        if self.mem_access_result is not None:
            val = utils.red_bold("\t0x%x" % self.mem_access_result[1])
            ad = utils.green_bold("\t> 0x%x" % self.mem_access_result[0])
            print(utils.titlify("memory access"))
            print(utils.white_bold("WRITE") + val + ad)
            self.hook_mem_access = None
            self.mem_access_result = None

    # 添加模块
    def add_module(self, module):
        """
        add modules to UnicornDbg core
        just an interface to call add_module in UnicornDbgFunctions
        """
        # 调用functions_instance中的add_module方法
        self.functions_instance.add_module(module)

    # 初始化
    def initialize(self, emu_instance: Uc = None, arch=None, mode=None, hide_binary_loader=False,
                   entry_point=None, exit_point=None, mappings: List[Tuple[str, int, int]] = None) -> Uc:
        """
        Initializes the emulator with all needed hooks. 
            用所有的hook初始化模拟器
        Will return the unicorn emu_instance ready to go. 
            返回的是unicorn模拟实例
        This method can be called from external scripts to to embed udbg.
            这个方法可以被外部脚本调用
        To kick off emulation, run start().
            调用start方法开始模拟
        :param entry_point: Entrypoint 入口点
        :param exit_opint: Exitpoint (where to stop emulation) 出口点
        :param emu_instance: Optional Unicorn instance to initialize this debugger with 模拟实例
        :param hide_binary_loader: if True, binary loader submenus will be hidden (good if embedding udbg in a target uc script)
            # 隐藏二进制加载器
        :param arch: unicorn arch int costant
            unicorn 架构 int常量
        :param mode: unicorn mode int costant
            unicorn 模式 
        :param mappings: list of mappings as tuple: [(name, offset, size),...]
            内存映射
        :return: Fully initialzied Uc instance.
        """
        # 二进制加载模块
        binary_loader_module = binary_loader.BinaryLoader(self)
        # 添加模块
        self.add_module(binary_loader_module)

        if emu_instance:
            self.emu_instance = emu_instance

        self.current_address = self.entry_point = entry_point
        self.exit_point = exit_point

        # if no arch or mode are sets in param, prompt for them
        if not arch:
            if emu_instance:
                arch = emu_instance._arch
            else:
                arch = utils.prompt_arch()
        if not mode:
            if emu_instance:
                mode = emu_instance._mode
            else:
                mode = utils.prompt_mode()

        if isinstance(arch, str):
            self.arch = getattr(unicorn_const, arch)
        else:
            self.arch = arch

        if isinstance(mode, str):
            self.mode = getattr(unicorn_const, mode)
        else:
            self.mode = mode

        if not self.emu_instance:
            self.emu_instance = Uc(self.arch, self.mode)

        if self.mode == UC_MODE_THUMB:
            self.is_thumb = True

        if mappings:
            [self.get_module('mappings_module').internal_add(*mapping[1:], path=mapping[0]) for mapping in mappings]

        # add hooks
        # 添加hook
        self.emu_instance.hook_add(UC_HOOK_CODE, self.dbg_hook_code)
        self.emu_instance.hook_add(UC_HOOK_MEM_WRITE, self.dbg_hook_mem_access)
        self.emu_instance.hook_add(UC_HOOK_MEM_INVALID, self.dbg_hook_mem_invalid)

        return self.emu_instance

    # 获取当前的pc
    @property
    def pc(self):
        reg = getPCCode(getArchString(self.arch, self.mode))
        return self.emu_instance.reg_read(reg)

    def start(self):
        # 开始函数： 命令获取和unicorn实例创建
        """
        main start function, here we handle the command get loop and unicorn istance creation
       :return:
        """

        # 创建实例
        if not self.emu_instance:
            self.initialize()

        # 清空屏幕
        utils.clear_terminal()
        print(utils.get_banner())
        print('\n\n\t' + utils.white_bold('Contribute ') + 'https://github.com/iGio90/uDdbg\n')
        print('\t' + 'Type ' + utils.white_bold_underline('help') + ' to begin.\n')

        print()
        while True:
            # prompt方法
            text = prompt(FormattedText([('ansired bold', MENU_APPENDIX + ' ')]), history=self.history, auto_suggest=AutoSuggestFromHistory())

            # only grant the use of empty command to replicate the last command while in cli. No executors
            if len(text) == 0 and self.last_command is not None:
                # 解析命令
                self.functions_instance.parse_command(self.last_command)
                continue

            self.last_command = text

            # send command to the parser
            # 解析命令
            self.functions_instance.parse_command(text)

    # 继续模拟
    def resume_emulation(self, address=None, skip_bp=0):
        # 从这个地方开始？
        if address is not None:
            self.current_address = address

        # 跳过bp
        self.skip_bp_count = skip_bp

        # 退出点
        if self.exit_point is not None:
            print(utils.white_bold("emulation") + " started at " + utils.green_bold(hex(self.current_address)))

            if len(self.entry_context) == 0:
                # store the initial memory context for the restart
                # 重新启动， 入口上下文
                self.entry_context = {
                    'memory': {},
                    'regs': {}
                }

                # 映射表
                map_list = self.get_module('mappings_module').get_mappings()
                for map in map_list:
                    map_address = int(map[1], 16)
                    map_len = map[2]
                    # 读取内存
                    self.entry_context['memory'][map_address] = bytes(self.emu_instance.mem_read(map_address, map_len))
                # registers
                # 寄存器
                const = utils.get_arch_consts(self.arch)
                regs = [k for k, v in const.__dict__.items() if
                        not k.startswith("__") and "_REG_" in k and not "INVALID" in k]
                
                for r in regs:
                    try:
                        # 读取寄存器
                        self.entry_context['regs'][r] = self.emu_instance.reg_read(getattr(const, r))
                    except Exception as ex:
                        pass
                        # print("Ignoring reg: {} ({})".format(r, ex)) -> Ignored UC_X86_REG_MSR

            # 开始地址
            start_addr = self.current_address
            if self.is_thumb:
                start_addr = start_addr | 1
            # 开始执行
            self.emu_instance.emu_start(start_addr, self.exit_point)
        else:
            print('please use \'set exit_point *offset\' to define an exit point')

    # 存储
    def restore(self):
        # 目前的地址
        self.current_address = self.entry_point
        # 写入内存
        for addr in self.entry_context['memory']:
            m = self.entry_context['memory'][addr]
            self.emu_instance.mem_write(addr, m)
        print('restored ' + str(len(self.entry_context['memory'])) + ' memory regions.')
        # 架构相关
        const = utils.get_arch_consts(self.arch)
        # 写入寄存器
        for r in self.entry_context['regs']:
            self.emu_instance.reg_write(getattr(const, r), self.entry_context['regs'][r])
        print('restored ' + str(len(self.entry_context['regs'])) + ' registers.')
        print('emulator at ' + utils.green_bold(hex(self.current_address)))

    # 停止模拟
    def stop_emulation(self):
        self.emu_instance.emu_stop()

    # 获取模拟实例
    def get_emu_instance(self):
        """ expose emu instance """
        return self.emu_instance

    # 获取capstone实例
    def get_cs_instance(self):
        """ expose capstone instance """
        if self.cs is None:
            if self.arch is not None or self.mode is not None:
                # 获取架构名称
                archstring = getArchString(self.arch, self.mode)
                # 启动Capstone
                self.cs_arch, self.cs_mode = getCapstoneSetup(archstring)

            # 储存配置
            self.functions_instance.get_module('configs_module').push_config('cs_mode', self.cs_mode)

            # 启动实例
            self.cs = Cs(self.cs_arch, self.cs_mode)
        return self.cs
    
    # 设置cs架构
    def set_cs_arch(self, arch):
        self.cs_arch = arch
        if self.cs_mode is not None:
            self.cs = Cs(self.cs_arch, self.cs_mode)

    # 设置cs模式
    def set_cs_mode(self, mode):
        self.cs_mode = mode
        if self.cs_arch is not None:
            self.cs = Cs(self.cs_arch, self.cs_mode)
    
    # 设置入口点
    def set_entry_point(self, entry_point):
        self.entry_point = entry_point

    # 设置退出点
    def set_exit_point(self, exit_point):
        self.exit_point = exit_point
    # 获取架构
    def get_arch(self):
        return self.arch
    # 获取模式
    def get_mode(self):
        return self.mode
    # 获取cs架构
    def get_cs_arch(self):
        return self.cs_arch

    def get_cs_mode(self):
        return self.cs_mode

    def get_current_address(self):
        return self.current_address

    def get_entry_point(self):
        return self.entry_point

    def get_exit_point(self):
        return self.exit_point

    def get_module(self, module_key):
        return self.functions_instance.get_module(module_key)

    # 批量执行
    def batch_execute(self, commands):
        self.functions_instance.batch_execute(commands)

    def exec_command(self, command):
        self.functions_instance.exec_command(command)


def main():
    udbg = UnicornDbg()
    t = module_test.MyModule(udbg)
    udbg.add_module(t)

    udbg.start()


if __name__ == "__main__":
    main()
