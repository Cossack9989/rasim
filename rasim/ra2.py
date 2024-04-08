import os
import r2pipe

from copy import deepcopy
from loguru import logger
from joblib import load, dump
from urllib.parse import quote
from binascii import unhexlify
from typing import Literal, Union, Dict
from Crypto.Util.number import bytes_to_long, long_to_bytes


class Engine:

    sig_list: list = []

    def __init__(self, bin_path: str, feature_db_root_path: str,
                 platform: Literal["OpenBMC", "MegaRAC", "UEFI", "Debian", "Ubuntu", "Android"],
                 debug=True):
        self.bin_path = bin_path
        self.feature_db_root_path = feature_db_root_path
        self.feature_db_platform_path = os.path.join(feature_db_root_path, platform)
        os.makedirs(self.feature_db_platform_path, exist_ok=True)
        self.platform = platform
        self.debug = debug
        if self.debug:
            logger.debug(f"ini pipe for {self.bin_path}")
        self.pipe = r2pipe.open(bin_path)
        self.pipe.cmd("aaa")

    def gen_sig(self):
        self.pipe.cmd("zg")
        raw_sig_list = self.pipe.cmdj("zj")
        for sig in raw_sig_list:
            if sig["graph"]["nbbs"] <= 2 and sig["graph"]["bbsum"] < 16:
                continue
            sig["fuzzy"] = long_to_bytes(bytes_to_long(unhexlify(sig["bytes"])) & bytes_to_long(unhexlify(sig["mask"])))
            self.sig_list.append(sig)

    def __del__(self):
        if self.debug:
            logger.debug(f"del pipe for {self.bin_path}")
        self.pipe.quit()


class Engine4Store(Engine):

    def __init__(self, bin_path: str, feature_db_root_path: str,
                 platform: Literal["OpenBMC", "MegaRAC", "UEFI", "Debian", "Ubuntu", "Android"],
                 project: str, version: str, name: str,
                 debug=True):
        """
        :param bin_path: the binary to be analyzed and recorded, it should be a **realpath**
        :param feature_db_root_path: the directory to store zignatures, it should be a **realpath**
        :param platform: Literal["OpenBMC", "MegaRAC", "UEFI", "Debian", "Ubuntu", "Android"]
        :param project: the project name, such as phosphor-ipmi-net, NO DOT DOT !
        :param version: the project version, such as 1.0+git, NO DOT DOT !
        :param name: .e.g "/usr/bin/netipmid" (will be quoted to %2Fusr%2Fbin%2Fnetipmid), NO DOT DOT !
        """
        super().__init__(bin_path, feature_db_root_path, platform, debug)
        self.feature_db_base_path = os.path.join(self.feature_db_platform_path, project, version)
        os.makedirs(self.feature_db_base_path, exist_ok=True)
        self.feature_db_path = os.path.join(self.feature_db_base_path, f"{quote(name, safe='')}.db")

    def store_sig(self):
        self.gen_sig()
        dump(self.sig_list, self.feature_db_path)


class Engine4Query(Engine):

    def __init__(self, bin_path: str, feature_db_root_path: str,
                 platform: Literal["OpenBMC", "MegaRAC", "UEFI", "Debian", "Ubuntu", "Android"],
                 db_in_memory: Union[None, Dict] = None,
                 debug=True):
        super().__init__(bin_path, feature_db_root_path, platform, debug)
        if not db_in_memory:
            self.db_in_memory = {}
        else:
            self.db_in_memory = deepcopy(db_in_memory)

    def query_sig(self):
        self.gen_sig()
        self.update_db_in_memory()

    def query_sig_by_func(self, func: Dict):
        return

    def update_db_in_memory(self):
        for root, _, filename_list in os.walk(self.feature_db_platform_path):
            for filename in filename_list:
                filepath = os.path.join(root, filename)
                if filepath not in self.db_in_memory.keys():
                    try:
                        data = load(filepath)
                        self.db_in_memory[filepath] = data
                    except Exception as e:
                        logger.error(e)
                        continue

