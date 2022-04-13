from dataclasses import dataclass
import logging
import binascii
import codecs
from capstone import (
    CS_ARCH_ARM,
    CS_ARCH_ARM64,
    Cs,
    CsInsn,
    CS_OPT_SYNTAX_INTEL,
    CS_ARCH_X86,
    CS_MODE_32,
)
from capstone.arm_const import ARM_INS_B, ARM_INS_BX, ARM_INS_BL, ARM_INS_BLX
from capstone.arm64_const import (
    ARM64_INS_B,
    ARM64_INS_BFM,
    ARM64_INS_BIC,
    ARM64_INS_BIF,
    ARM64_INS_BIT,
    ARM64_INS_BL,
    ARM64_INS_BLR,
    ARM64_INS_BR,
    ARM64_INS_BRK,
    ARM64_INS_BSL,
)
from .yararule import YaraRule, StringType
from datetime import datetime
from typing import List, Tuple

import coloredlogs


YARA_AUTHOR = "Nick Anderson"
YARA_EMAIL = "thor@fb.com"
YARA_VERSION = "1.0"


IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_I386 = 0x014C

ARM_JUMPS = [ARM_INS_B, ARM_INS_BX, ARM_INS_BL, ARM_INS_BLX]
ARM64_JUMPS = [
    ARM64_INS_B,
    ARM64_INS_BFM,
    ARM64_INS_BIC,
    ARM64_INS_BIF,
    ARM64_INS_BIT,
    ARM64_INS_BL,
    ARM64_INS_BLR,
    ARM64_INS_BR,
    ARM64_INS_BRK,
    ARM64_INS_BSL,
]

LOGGING_LEVEL = logging.INFO
coloredlogs.install(level=LOGGING_LEVEL, datefmt="%Y-%m-%dT%H:%M:%S%z")
log = logging.getLogger("yara-generator")
log.setLevel(LOGGING_LEVEL)


@dataclass
class DataChunk(object):
    data: bytes
    length: int
    is_data: bool


class YaraGenerator(object):
    def __init__(
        self,
        sig_mode,
        instruction_set,
        instruction_mode,
        rule_name="generated_rule",
        do_comment=True,
    ):
        self.instruction_set = instruction_set
        self.instruction_mode = instruction_mode
        self.do_comment_sig = do_comment
        self.sig_mode = sig_mode
        self.rule_name = rule_name
        self.yr_rule = YaraRule()
        self._signature = ""
        self._chunks = []

    def add_chunk(self, data: bytes, length: int = 0, is_data: bool = False) -> None:
        self._chunks.append(DataChunk(data=data, length=length, is_data=is_data))

    def _hex_opcode(self, opcode_list):
        """Returns a HEX string representation of the Capstone opcode list"""
        return " ".join(format(x, "02x").upper() for x in opcode_list if x != 0)

    def _get_opcode_size(self, opcode_list):
        """Count the number of opcodes in the Capstone opcode list"""
        result = 0
        for bt in opcode_list:
            if bt != 0:
                result += 1
        return result

    def _wilcard_bytes(self, data: List[str], offset: int, length: int):
        for i in range(offset, offset + length):
            data[i] = "?"
        return data

    def _process_instruction(self, ins: CsInsn) -> Tuple[str, str]:
        """Process an instruction of the binary, generating a pattern/signature for it"""
        ins_str = "{} {}".format(ins.mnemonic, ins.op_str)

        imm_offs = None
        imm_size = None
        disp_offs = None
        disp_size = None
        if self.instruction_set not in [CS_ARCH_ARM, CS_ARCH_ARM64]:
            opcode_hex_str = self._hex_opcode(ins.opcode)
            opcode_size = self._get_opcode_size(ins.opcode)
            operand_total_size = len(ins.bytes) - opcode_size

            log.debug("Opc. size:\t {}".format(opcode_size))
            log.debug("Opcode:\t\t {}, {}".format(opcode_hex_str, str(ins.opcode)))
            log.debug("rex:\t {}".format(hex(ins.rex)))

            imm_offs = ins.imm_offset
            imm_size = ins.imm_size
            disp_offs = ins.disp_offset
            disp_size = ins.disp_size
        else:
            # Instruction width is fixed on ARM.
            imm_offs = 2
            imm_size = 2
            disp_offs = 2
            disp_size = 2

        ins_hex = binascii.hexlify(ins.bytes).upper()
        ins_hex = ins_hex.decode("ascii")

        log.debug("Hex:\t\t {}".format(ins_hex))
        log.debug("Ins:\t\t {}".format(ins_str))

        # TODO: Unsure if we A.) Want this, B.) If it's even correct for ARM
        ins_comment = "{}".format(ins_hex)
        ins_comment = ins_comment.ljust(15)
        ins_comment += ins_str
        ins_comment = " * {} {}".format(hex(ins.address), ins_comment)

        ins_hex_list = list(ins_hex)

        if self.should_wildcard_imm_operand(ins):
            ins_hex_list = self._wilcard_bytes(ins_hex_list, imm_offs * 2, imm_size * 2)
        if self.should_wildcard_disp_operand(ins):
            ins_hex_list = self._wilcard_bytes(
                ins_hex_list, disp_offs * 2, disp_size * 2
            )

        signature = "".join(ins_hex_list)
        return signature, ins_comment

    def is_jmp_or_call(self, ins):
        """
        For arm?
        if i.id in (ARM_INS_BL, ARM_INS_CMP):
        """
        if self.instruction_set == CS_ARCH_ARM64:
            return ins.id in ARM64_JUMPS

        if self.instruction_set == CS_ARCH_ARM:
            return ins.id in ARM_JUMPS

        # This doesn't work for ARM. Does it even work for x64?
        for group in ins.groups:
            group_name = ins.group_name(group)
            if group_name in ["jump", "call"]:
                return True
        return False

    def should_wildcard_disp_operand(self, ins):
        if self.sig_mode in ["loose", "normal"]:
            return True
        else:
            return self.is_jmp_or_call(ins)

    def should_wildcard_imm_operand(self, ins):
        if self.sig_mode in ["loose"]:
            return True
        else:
            return self.is_jmp_or_call(ins)

    def format_hex(self, data):
        n = 2
        return " ".join([data[i : i + n] for i in range(0, len(data), n)])

    def generate_rule(self) -> YaraRule:
        """Generate Yara rule. Return a YaraRule object"""

        self.yr_rule.rule_name = self.rule_name
        self.yr_rule.metas["generated_by"] = f'"{YARA_AUTHOR}"'
        self.yr_rule.metas["date"] = '"{}"'.format(
            datetime.now().strftime("%Y-%m-%d %H:%M")
        )
        self.yr_rule.metas["version"] = f'"{YARA_VERSION}"'
        self.yr_rule.metas["email"] = f'"{YARA_EMAIL}"'

        if self.instruction_set is None or self.instruction_mode is None:
            log.error("[-] The architecture appears to not be supported.")
            return

        md = Cs(self.instruction_set, self.instruction_mode)
        md.detail = True
        md.syntax = CS_OPT_SYNTAX_INTEL
        chunk_nr = 0
        for chunk in self._chunks:
            chunk_nr += 1
            chunk_id = "$chunk_{}".format(chunk_nr)
            chunk_signature = ""
            chunk_comment = ""
            if chunk.is_data is False:
                disasm = md.disasm(chunk.data, chunk.length)
                for ins in disasm:
                    rule_part, comment = self._process_instruction(ins)
                    rule_part = self.format_hex(rule_part)
                    chunk_signature += rule_part + "\n"
                    chunk_comment += comment + "\n"
                self.yr_rule.add_string(chunk_id, chunk_signature, StringType.HEX)
                if self.do_comment_sig:
                    self.yr_rule.comments.append(chunk_comment)
            else:
                rule_part = self.format_hex(chunk.data.encode("hex"))
                self.yr_rule.add_string(chunk_id, rule_part, StringType.HEX)

        self.yr_rule.condition = "any of them"
        return self.yr_rule
