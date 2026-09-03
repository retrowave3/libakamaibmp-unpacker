from emulite import AndroidEmulator64
import logging
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("libakamaibmp.unpacker")

class AkamaiBmpUnpacker():
    def __init__(self):
        self.emu = AndroidEmulator64()
        self.ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

    def load(self, library_path: str):
        logger.info("Loading module")
        self.lib = self.emu.load_library(library_path)
        self.lib.call_jni_onload()

        logger.info("Mapping code segments")
        self.code_segments = []
        for segment in self.lib.segments:
            if segment.permissions & segment.permissions.EXEC:
                self.code_segments.append((segment.start, segment.size))

        logger.info("Scanning for proxy & resolver functions")

        self.proxy_address = self.lib.scan_pattern_first("FD 7B BB A9 FD 03 00 91 E0 07 01 A9 E2 0F 02 A9")     # Proxy function
        if self.proxy_address is None:
            raise Exception('failed to find proxy function')
        
        self.resolver_address = self._find_resolver_address(self.proxy_address)  # Resolver function
        if self.resolver_address is None:
            raise Exception('failed to find resolver function')

        logger.info("Library has been loaded")

    def resolve_proxy_destination(self, caller_rva: int):
        caller_address = self.lib.base + caller_rva
        key = (self.proxy_address - caller_address - 4) & 0xFFFFFFFFFFFFFFFF
        output = self.emu.allocate_bytes(8)  # malloc(8)
        self.emu.call(self.resolver_address, key, self.proxy_address, output)
        destination = self.emu.mem.read_u64(output)
        self.emu.free(output)

        return destination - self.lib.base

    def unpack(self, remove_proxy_calls: bool = True, remove_proxy_shims: bool = True, remove_fake_calls: bool = True, remove_nop_b: bool = True):
        if remove_proxy_calls:
            self._unpack_proxy_calls(remove_proxy_shims)

        if remove_fake_calls:
            self._remove_fake_calls(remove_nop_b)

        return self.lib.dump()

    def _find_resolver_address(self, proxy_address: int):
        address = proxy_address
        visited = set()

        while address not in visited:
            visited.add(address)
            instruction = self.emu.disassemble(address)[0]

            if instruction.mnemonic == "bl":
                return instruction.operands[0].imm

            if instruction.mnemonic == "b":
                address = instruction.operands[0].imm
                continue

            if instruction.mnemonic in ("br", "ret"):
                break

            address += instruction.size

        return None

    def _ins_branch_target(self, address: int, instruction: int):
        offset = instruction & 0x03FFFFFF
        if offset & 0x02000000:
            offset -= 0x04000000
        return address + (offset << 2)

    def _find_callers(self):
        callers = {}
        for start, size in self.code_segments:
            code = self.emu.mem.read(start, size)
            for offset in range(0, len(code) - 3, 4):
                instruction = int.from_bytes(code[offset : offset + 4], "little")
                address = start + offset
                if (instruction & 0xFC000000) == 0x94000000:
                    target = self._ins_branch_target(address, instruction)
                    callers.setdefault(target, []).append(address)
        return callers

    def _find_branches(self):
        branches = {}
        names = {"b", "bl", "cbz", "cbnz", "tbz", "tbnz"}

        for start, size in self.code_segments:
            code = self.emu.mem.read(start, size)
            for offset in range(0, len(code) - 3, 4):
                address = start + offset
                instruction = self.emu.disassembler.one(code[offset : offset + 4], address)
                if instruction is None:
                    continue

                if instruction.mnemonic not in names and not instruction.mnemonic.startswith("b."):
                    continue

                destination = instruction.operands[-1].imm
                branches.setdefault(destination, []).append(address)

        return branches

    def _assemble_branch(self, address: int, destination: int):
        instruction = self.emu.disassemble(address)[0]
        operands = instruction.op_str.rsplit(",", 1)

        if len(operands) == 1:
            code = f"{instruction.mnemonic} {destination:#x}"
        else:
            code = f"{instruction.mnemonic} {operands[0]}, {destination:#x}"

        return bytes(self.ks.asm(code, addr=address)[0])

    def _unpack_proxy_calls(self, remove_proxy_shims: bool):
        logger.info("Scanning for proxy calls")
        callers = self._find_callers().get(self.proxy_address, [])
        logger.info("Found %d proxy calls", len(callers))

        branches = []
        for caller in callers:
            destination = self.lib.base + self.resolve_proxy_destination(caller - self.lib.base)
            branches.append((caller, destination))

        for caller, destination in branches:
            branch = bytes(self.ks.asm(f"bl {destination:#x}", addr=caller)[0])
            self.emu.mem.write(caller, branch)

        logger.info("Patched %d proxy calls", len(callers))

        if not remove_proxy_shims:
            return

        shim_addresses = set()

        for last_byte in range(0x14, 0x18):
            shim_addresses.update(self.lib.scan_pattern(f"FD 7B C5 A8 ?? ?? ?? {last_byte:02X}"))

        shim_addresses = sorted(shim_addresses)
        logger.info("Found %d shim functions", len(shim_addresses))

        patched_shim_callers = 0
        callers = self._find_callers()
        for shim in shim_addresses:
            shim_callers = callers.get(shim, [])
            instruction = self.emu.mem.read_u32(shim + 4)

            if (instruction & 0xFC000000) != 0x14000000:
                raise ValueError(f"unexpected shim at {shim:#x}")

            destination = self._ins_branch_target(shim + 4, instruction)
            for caller in shim_callers:
                branch = bytes(self.ks.asm(f"bl {destination:#x}", addr=caller)[0])
                self.emu.mem.write(caller, branch)
                patched_shim_callers += 1

            # overwrite shim with garbage for better analysis
            self.emu.mem.write(shim, b"\xff" * 8)

        logger.info("Patched %d callers for %d shim functions", patched_shim_callers, len(shim_addresses))        

    def _remove_fake_calls(self, remove_nop_b: bool):
        callers = self._find_callers()    # update callers
        cf_bl_lr = set()
        cf_bl_lr.update(self.lib.scan_pattern(f"FD 7B C1 A8"))   # LDP X29, X30, [SP],#0x10
        logger.info("Found %d fake call functions", len(cf_bl_lr))

        patched_calls = 0
        nop = b"\x1f\x20\x03\xd5"
        nop_b = {}

        for destination in cf_bl_lr:
            target = destination + 4

            for caller in callers.get(destination, []):
                instruction = self.emu.mem.read_u32(caller)
                if self.emu.mem.read_u32(caller - 4) == 0xA9BF7BFD:
                    self.emu.mem.write(caller - 4, nop)
                    branch = bytes(self.ks.asm(f"b {target:#x}", addr=caller)[0])
                    nop_b[caller - 4] = target
                else:
                    branch = (instruction & 0x7FFFFFFF).to_bytes(4, "little")

                self.emu.mem.write(caller, branch)
                patched_calls += 1

        logger.info("Patched %d fake calls", patched_calls)

        if not remove_nop_b:
            return
        
        branches = self._find_branches()
        patched_branches = 0
        removed_blocks = 0

        for loc, destination in nop_b.items():
            loc_branches = branches.get(loc, []) + branches.get(loc + 4, [])
            if not loc_branches:
                continue

            for caller in loc_branches:
                branch = self._assemble_branch(caller, destination)
                self.emu.mem.write(caller, branch)
                patched_branches += 1

            self.emu.mem.write(loc, b"\xff" * 8)
            removed_blocks += 1

        logger.info("Forwarded %d branches through %d NOP B blocks", patched_branches, removed_blocks)


if __name__ == "__main__":
    unpacker = AkamaiBmpUnpacker()
    unpacker.load("libakamaibmp.so")
    result = unpacker.unpack(
        remove_proxy_calls=True,   # Resolve the proxified calls
        remove_proxy_shims=True,   # Makes the resolved proxified calls direct (remove_proxy_calls required) 
        remove_fake_calls=True,    # Resolve fake BL's which never returns
        remove_nop_b=True,         # Make the fake calls direct (remove_fake_calls required)
    )

    with open('libakamaibmp.unpacked.so', 'wb') as fw:
        fw.write(result)

    ### Resolve proxy destinations:
    #   destination = unpacker.resolve_proxy_destination(caller_rva=0x12345)
