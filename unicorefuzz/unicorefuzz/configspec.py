# 读取和验证配置
# spec：规格
"""
This thing reads and validates the config.
The actual spec can be found a few lines below.
Lots of Required and Optional things.
"""
import collections
import inspect
import os

# 类型的各种库，第一次见hh
from types import ModuleType
from typing import (
    List,
    Union,
    Any,
    Callable,
    TypeVar,
)  # other types are not supported, sorry...

from avatar2 import Avatar, Target, X86

# from sh import which
from unicorn import unicorn

import unicorefuzz.unicorefuzz
from unicorefuzz.unicorefuzz import Unicorefuzz
from unicorefuzz.unicorefuzz import archs

# collections的namedtuple方法，命名的元组
Required = collections.namedtuple("Required", "key type description param_names")
Required.__new__.__defaults__ = ("*args",)
Optional = collections.namedtuple(
    "Optional", "key type default description param_names"
)
Optional.__new__.__defaults__ = ("*args",)

DEFAULT_PAGE_SIZE = 0x1000


def nop_func(*args, **kwargs) -> None:
    pass


# 初始化avatar目标结构，理解avatar的重要函数
# 在gdb_probe_wrap中单单调用Avatar，不知道他是怎么连接端口等等的。。
def init_avatar_target(ucf: Unicorefuzz, avatar: Avatar) -> Target:
    """
        初始化probe wrapper使用的target
    Init the target used by the probe wrapper.
        probe_wrapper会设置断点，导向寄存器和内存
    The probe_wrapper will set the breakpoint and forward regs and mem using this target.

    :param ucf: Unicorefuzz instance, access config using ucf.config.
    :param avatar: Initialized Avatar to add target to.
        返回一个初始化后的target
    :return: An initialized target, added to Avatar.
    """
    from avatar2 import GDBTarget

    # 调用avatar的add_target方法
    target = avatar.add_target(
        GDBTarget,
        gdb_ip=ucf.config.GDB_HOST, # gdb ip
        gdb_port=ucf.config.GDB_PORT, # gdb 端口
        gdb_executable=ucf.config.GDB_PATH, # gdb执行路径
    )

    # 初始化
    target.init()

    # 返回
    return target


# 自动完成？？ ipython的特性吗？？
# Just for autocompletion
ARCH = X86  # type Architecture
PAGE_SIZE = (
    SCRATCH_ADDR
) = SCRATCH_SIZE = GDB_PORT = BREAKADDR = BREAKOFFSET = -1  # type int
GDB_HOST = (
    MODULE
) = WORKDIR = GDB_PATH = UNICORE_PATH = AFL_OUTPUT = AFL_DICT = ""  # type str
init_func = place_input = nop_func  # type Callable

# 好像也是用来解析一些东西的，在后面提供给config
# The spec the config.py needs to abide by.
UNICOREFUZZ_SPEC = [
    Required("ARCH", list(archs.keys()), "What architecture to emulate"),
    Optional(
        "PAGE_SIZE",
        int,
        DEFAULT_PAGE_SIZE,
        "The page size used when fetching and mapping memory",
    ),
    Required(
        "SCRATCH_ADDR", int, "Location of free Scratch Memory, not used by the target"
    ),
    Optional(
        "SCRATCH_SIZE",
        int,
        lambda config: config.PAGE_SIZE,
        "Size of the mapped scratch memory",
    ),
    Optional("GDB_HOST", str, "localhost", "The GDB Host to connect to"),
    Required("GDB_PORT", int, "The GDB port to connect to"),
    Optional("BREAK_ADDR", Union[int, None], None, "The absolute address to break at"),
    Optional(
        "MODULE",
        Union[str, None],
        None,
        "A linux kernel module to break in (cannot be combined with BREAKADDR)",
    ),
    Optional(
        "BREAK_OFFSET",
        Union[int, None],
        None,
        "Relative location in the MODULE to break in",
    ),
    Optional(
        "EXITS", List[int], [], "Absolute addresses at which Ucf should stop fuzzing"
    ),
    Optional(
        "ENTRY_RELATIVE_EXITS",
        List[int],
        [],
        "EXITS relative to initial PC at uc.emu_start (entrypoint + addr)",
    ),
    Optional(
        "WORKDIR",
        str,
        lambda config: os.path.join(config.folder, "unicore_workdir"),
        "Path to UCF workdir to store state etc.",
    ),
    Optional(
        "GDB_PATH", str, "gdb", "The path GDB lives at"
    ),  # which("gdb"), "The path GDB lives at"),
    Optional(
        "UNICORE_PATH",
        str,
        os.path.dirname(os.path.dirname(os.path.abspath(unicorefuzz.__file__))),
        "Custom path of Unicore installation",
    ),
    Optional(
        "AFL_INPUTS",
        Union[str, None],
        lambda config: os.path.join(config.folder, "afl_inputs"),
        "The seed directory to use for fuzzing",
    ),
    Optional(
        "AFL_OUTPUTS",
        Union[str, None],
        lambda config: os.path.join(config.folder, "afl_outputs"),
        "AFL output directory to use for fuzzing (default will be at location of config.py)",
    ),
    Optional("AFL_DICT", Union[str, None], None, "AFL dictionary to use for fuzzing"),
    Optional(
        "init_func",
        Callable[[Unicorefuzz, unicorn.Uc], None],
        lambda config: nop_func,
        """An init function called before forking.
        Will receive handle to ucf and unicorn as parameters.
        This function may be used to set additional unicorn hooks and things.
        Use ucf.map_page(addr) if you need to access/alter memory that may not be available.
        Set the program counter here if you want to fuzz somewhere else.
        If you uc.run_emu here, you will start the forkserver! Try not to/do that in place_input. :)
        Does not return anything.
        :param ucf: unicorefuzz instance
        :param uc: fully initialized unicorn instance""",
        "ucf, uc",
    ),
    Required(
        "place_input",
        Callable[[Unicorefuzz, unicorn.Uc, bytes], None],
        """Function placing input to the unicorn state. It receives ucf, unicorn and input as parameters.
        The function will be called for each execution, so keep it lightweight.
        Think testcase in libfuzzer.
        If you want to ignore an input, you can ucf.exit(exitcode) here.
        This will call through to os._exit(0). Anything else is a lot slower.
        :param ucf: unicorefuzz instance
        :param uc: fully initialized unicorn instance
        :param input: the input""",
        "ucf, uc, input",
    ),
    Optional(
        "init_avatar_target",
        Callable[[Unicorefuzz, Avatar], Target],
        lambda config: init_avatar_target,
        init_avatar_target.__doc__,
        "ucf, avatar",
    ),
]  # type: List[Union[Required, Optional]]


# 是否是可调用类型
def is_callable_type(typevar: Union[Callable, callable, TypeVar]) -> bool:
    """
    Returns True if typevar is callable or Callable
    """
    # 如果是以下两种情况返回真，表明是可调用的
    if typevar == callable or typevar == Callable:
        return True

    # 冷静pycharms的静态分析？？
    # This return is split in 2 parts to calm down pycharms static analyzer.
    if hasattr(typevar, "__origin__"):
        # noinspection PyUnresolvedReferences
        return typevar.__origin__ == Callable.__origin__
    return False


# 接受一个函数或者一个lambda表达式的源
def clean_source(func: Callable[[Any], Any]) -> str:
    """
    Receives the source of a function or lambda
    :param func: The function to serialize
    :return: The included source code
    """
    # 调用inspect的getsource方法，返回的应该是一个字符串，然后处理之
    source = inspect.getsource(func).split(":", 1)[1].strip()
    # 如果以","结尾
    if source.endswith(","):
        # special case for lambdas
        return source[:-1]
    return source


# 字符串化规格spec
def stringify_spec_entry(entry: Union[Optional, Required]) -> str:
    """Make a nice string out of it."""
    # 获得entrytype
    entrytype = entry.type
    if isinstance(entrytype, type):
        entrytype = entrytype.__name__
    # ugly hack: We don't want a list to be ['like', 'this'] but ["with", "json", "quotes"]...
    
    # 单引号变双引号
    entrytype = "{}".format(entrytype).replace("'", '"')

    # 如果是Required，并且是函数类型（callable）
    if isinstance(entry, Required):
        if is_callable_type(entry.type):
            return '''def {}({}):
    #  type: {}
    """
    {}
    """
    TODO
    '''.format(
                entry.key, entry.param_names, entrytype, entry.description
            )
    # 否则返回一个注释。 interesting
        return '"""{}"""\n{} = TODO #  type {}'.format(
            entry.description, entry.key, entrytype
        )
    if isinstance(entry, Optional):
        # If it's a func, we only want the print the content.
        default = entry.default
        # 如果可调用
        # callable和is_callable_type不重复吗？ 不懂
        if callable(entry.default):
        # clean_source它
            default = clean_source(default)
        if is_callable_type(entry.type):
            default = clean_source(eval(default))
            return '''def {}({}):
    #  type: {}
    """[Optional]
    {}
    """
    {}
    '''.format(
                entry.key, entry.param_names, entrytype, entry.description, default
            )
        return '"""[Optional] {}"""\n{} = {} #  type {}'.format(
            entry.description, entry.key, default, entrytype
        )
    raise ValueError(
        "Could not stringify unknown entry type {}: {}".format(type(entry), entry)
    )


# 序列化规格，打印字符串
def serialize_spec(spec: List[Union[Optional, Required]]) -> str:
    """
    Prints a checker spec in a readable format, close to python.
    :param spec: a spec
    :return: formatted string
    """
    return "\n\n".join(
        [
            "# Config options for unicorefuzz\n"
            "# Values tagged as [Optional] are autofilled by ucf if not set explicitly."
        ]
        + [stringify_spec_entry(x) for x in spec]
    )


# 类型匹配
def type_matches(val: Any, expected_type: Union[List, TypeVar, None]) -> bool:
    """
        返回是否类型和期望相等
    Returns if the type equals the expectation
    :param val: The value
    :param expected_type: The type or a list of allowed values
    :return: True if the type is correct, False otherwise
    """
    # 如果是列表类型
    if isinstance(expected_type, list):
        # A list of allowed values is given, not an actual type
        return val in expected_type
    # 如果期望类型是Any，直接返回True
    elif expected_type == Any:
        return True
    # 期望类型为空，返回val也是空
    elif expected_type is None:
        return val is None
    # 再不行就判断__origin__属性了，__origin__不了解
    elif hasattr(expected_type, "__origin__"):
        # Something from the typing module
        if expected_type.__origin__ == Union:
            for union_member in expected_type.__args__:
                if type_matches(val, union_member):
                    return True
        elif is_callable_type(expected_type):
            return callable(val)
        elif expected_type.__origin__ == dict:
            if not isinstance(val, dict):
                return False
            for key in val.keys():
                if not type_matches(key, expected_type.__args__[0]):
                    return False
            for value in val.values():
                if not type_matches(value, expected_type.__args__[1]):
                    return False
            return True
        elif expected_type.__origin__ == list:
            if not isinstance(val, list):
                return False
            for el in val:
                if not type_matches(el, expected_type.__args__[0]):
                    return False
            return True
    # TypeVar 太复杂，直接略过了
    elif isinstance(expected_type, TypeVar):
        # too complex to check if TypeVars (List[TypeVar]) are alright... Treat like Any
        return True
    elif isinstance(val, expected_type):
        return True
    return False


# 检查类型
def check_type(name: str, val: str, expected_type: Union[List, TypeVar, None]) -> None:
    """
    returns and converts if necessary
    :param name: the name of the value
    :param val: the value to check
    :param expected_type: the expected type
    """
    if not type_matches(val, expected_type):
        raise ValueError(
            "{} should be '{}' but is {} of type '{}'.".format(
                name, expected_type.__name__, val, type(val).__name__
            )
        )


# 通过路径引入一个python模块
def import_py(mod_name: str, mod_path: str, silent: bool = False) -> ModuleType:
    """
    Imports a python module by path
        模块名字
    :param mod_name: the name the module should be imported by
        模块路径
    :param mod_path: the path to load the module from
        安静模式
    :param silent: If True, nothing will be printed
    :return: the module, as reference
    """
    # Python 3.5+, see https://stackoverflow.com/questions/67631/how-to-import-a-module-given-the-full-path for others.
    # 如果不存在这个文件
    if not os.path.isfile(mod_path):
        raise IOError(
            "Could not open config at {} as file. Make sure it exists.".format(
                os.path.abspath(mod_path)
            )
        )
    else:
    # 如果存在，就打印debug信息
        if not silent:
            print("[+] Reading config from {}".format(os.path.abspath(mod_path)))
    try:
        # python3.5+
        # 引入importlib.util库
        import importlib.util
        # 调用spec_from_file_location
        # spec规格，不懂
        spec = importlib.util.spec_from_file_location(mod_name, mod_path)
        if not spec:
            raise EnvironmentError(
                "Could not load {} from {}".format(mod_name, mod_path)
            )
        # 从spec规格当中提取出模块
        mod = importlib.util.module_from_spec(spec)
        # 返回执行模块(loader方法？)
        return unicorefuzz.__loader__.exec_module(mod)
    except EnvironmentError:
        raise
    except:
        try:
            # python 3.3-3.4 (untested)
            from importlib.machinery import SourceFileLoader

            return SourceFileLoader(mod_name, mod_path).load_module()
        except Exception as ex:
            raise EnvironmentError(
                "Could not load {} from {}: {}".format(mod_name, mod_path, ex)
            )


# 加载配置
def load_config(path: str, silent: bool = False) -> ModuleType:
    """
    :param path: path to config.py (including filename)
    :param silent: If True, nothing will be printed
    :return: Loaded config (or ValueError)
    """
    # 获得绝对地址
    path = os.path.abspath(path)
    config = import_py("unicoreconfig", path, silent=silent)
    # path of the actual config file
    config.path = os.path.abspath(path)  # type: str
    config.filename = os.path.basename(config.path)  # type: str
    # config.folder is the folder containing the config
    config.folder = os.path.dirname(config.path)  # type: str
    # 应用spec，实现就在限免
    apply_spec(config, UNICOREFUZZ_SPEC, silent=silent)
    return config


def apply_spec(
    module: Any, spec: List[Union[Optional, Required]], silent: bool = False
) -> None:
    """
        检查config是否实现了spec，部分spec是否丢失
    Checks if config implements the spec or parts are missing.
        填充可选值和其他各个默认值
    Fills in Optional() values with their respective default values.
        如果Optional defaults是可调用的，他们将被调用，目前的module将作为参数
    If Optional defaults are callable, they will be called with the current module as parameter.
        spec是顺序可迭代的
    The spec is iterated in order - make sure optional values only depends on previous values.

    In case the spec fails, errors out with ValueError.
    :param module: the element to verify the spec against
    :param spec: the spec
    :param silent: If False, will print info about replaced defaults
    """
    errors = []
    # 根据silent设置print_maybe函数
    if silent:

        def print_maybe(*args):
            pass

    else:

        def print_maybe(*args):
            print(*args)

    for entry in spec:
        # 如果module没有这个entry
        if not hasattr(module, entry.key):
            # Entry not found.
            if isinstance(entry, Optional):
                default = entry.default
                printable = default
                if callable(default):
                    printable = clean_source(default)
                    default = entry.default(module)
                print_maybe(
                    "[*] Optional setting {} not set. Using default value: {}.\n\tDescription: {}".format(
                        entry.key, printable, entry.description
                    )
                )
                # 设置属性
                setattr(module, entry.key, default)
            else:
                print_maybe(
                    "[-] Error: Required option {} not set! Please add it to config.py.\n\tDescription: {}".format(
                        entry.key, entry.description
                    )
                )
                errors.append(entry)
        else:
            # Value found. Check.
            # 找到了值
            val = getattr(module, entry.key)
            try:
                # 检查类型
                check_type(entry.key, val, entry.type)
            except ValueError as ex:
                print_maybe(
                    "[-] Error: Required option {} has wrong type! {}\nPlease fix in config.py.\n\tDescription: {}".format(
                        entry.key, ex, entry.description
                    )
                )
                errors.append(entry)
    if errors:
        raise ValueError(
            "Could not load required values from config.py: \n{}".format(
                "\n".join([stringify_spec_entry(x) for x in errors])
            )
        )
