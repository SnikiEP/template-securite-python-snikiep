import argparse

from tp2.utils.config import logger
from tp2.utils.shellcode import (
    get_capstone_analysis,
    get_llm_analysis,
    get_pylibemu_analysis,
    get_shellcode_strings,
    parse_shellcode,
)


def main():
    parser = argparse.ArgumentParser(description="Shellcode analyser")
    parser.add_argument("-f", "--file", required=True, help="Shellcode file path")
    args = parser.parse_args()

    with open(args.file, "r") as f:
        raw = f.read()

    shellcode = parse_shellcode(raw)
    logger.info(f"Testing shellcode of size {len(shellcode)}B")

    strings = get_shellcode_strings(shellcode)
    logger.info(f"Strings found:\n{strings}")

    emu_output = get_pylibemu_analysis(shellcode)
    logger.info(f"Pylibemu analysis:\n{emu_output}")

    asm_output = get_capstone_analysis(shellcode)
    logger.info(f"Capstone disassembly:\n{asm_output}")

    llm = get_llm_analysis(shellcode, emu_output + "\n" + asm_output)
    logger.info(f"Explication LLM: {llm}")

    logger.info("Shellcode analysed!")


if __name__ == "__main__":
    main()
