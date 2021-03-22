#! /usr/bin/python

import os
import argparse

MAX_BIP39_WORD_LEN = 8


def main(path: str, declaration: str, definition: str):
    raw_dict = bytearray()

    with open(path, mode='r') as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            if len(line) > MAX_BIP39_WORD_LEN:
                raise RuntimeError("invalid word length")

            raw_dict += line.strip().encode('utf-8').ljust(8, b'\0')

    if len(raw_dict) % 4 != 0:
        raise RuntimeError("raw dictionary data is not aligned")

    generated_definition = "const uint32_t BIP39[] = {"

    i = 0
    while i < len(raw_dict):
        number = 0
        for j in range(4):
            number += raw_dict[i + (3 - j)] << (j * 8)

        if i != 0:
            generated_definition += ','

        generated_definition += "\n    " if i % 9 == 0 else ' '
        generated_definition += f"0x{number:08x}"

        i += 4

    generated_definition += "};"

    os.makedirs(os.path.dirname(declaration), exist_ok=True)
    with open(declaration, 'w') as f:
        generated_declaration = "#pragma once\n\nextern uint32_t BIP39[];\n"
        f.write(generated_declaration)
        print(f"Generated declaration in {declaration}")

    os.makedirs(os.path.dirname(definition), exist_ok=True)
    with open(definition, 'w') as f:
        f.write(generated_definition)
        print(f"Generated definition in {definition}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BIP39 binary dictionary generator")
    parser.add_argument("path", metavar="PATH", type=str, help="The raw dictionary path")
    parser.add_argument("declaration", metavar="DECLARATION", type=str, help="Path to the output .h file")
    parser.add_argument("definition", metavar="DEFINITION", type=str, help="Path to the output .cpp file")
    args = parser.parse_args()
    main(args.path, args.declaration, args.definition)
