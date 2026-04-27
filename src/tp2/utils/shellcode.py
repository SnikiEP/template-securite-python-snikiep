import os
import re
import string

try:
    import pylibemu
except ImportError:
    pylibemu = None

from openai import OpenAI
from capstone import CS_ARCH_X86, CS_MODE_32, Cs


def parse_shellcode(raw: str) -> bytes:
    hex_bytes = re.findall(r"\\[xX]([0-9a-fA-F]{2})", raw)
    return bytes(int(h, 16) for h in hex_bytes)


def get_shellcode_strings(shellcode: bytes) -> str:
    result = []
    current = []
    for b in shellcode:
        c = chr(b)
        if c in string.printable and c not in string.whitespace:
            current.append(c)
        else:
            if len(current) >= 4:
                result.append("".join(current))
            current = []
    if len(current) >= 4:
        result.append("".join(current))
    return "\n".join(result)


def get_capstone_analysis(shellcode: bytes) -> str:
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    lines = []
    for i in md.disasm(shellcode, 0x1000):
        lines.append(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
    return "\n".join(lines)


def get_pylibemu_analysis(shellcode: bytes) -> str:
    if pylibemu is None:
        return "pylibemu not available on this platform"
    emulator = pylibemu.Emulator()
    offset = emulator.shellcode_getpc_test(shellcode)
    emulator.prepare(shellcode, offset)
    emulator.test()
    return str(emulator.emu_profile_output)


def get_llm_analysis(shellcode: bytes, analysis: str) -> str:
    api_key = os.getenv("OPENAI_KEY")
    if not api_key:
        return "No OPENAI_KEY"

    prompt = (
        f"Analyse ce shellcode et explique ce qu'il fait en français.\n\n"
        f"Analyse technique:\n{analysis}\n\n"
        f"Shellcode (hex): {shellcode.hex()}"
    )

    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content
