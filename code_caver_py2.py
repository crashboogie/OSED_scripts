# Built-in imports
import sys
import argparse

# Third party libraries
import pykd


PROTECTION_FLAGS = {
    0x01: "PAGE_NOACCESS",
    0x02: "PAGE_READONLY",
    0x04: "PAGE_READWRITE",
    0x08: "PAGE_WRITECOPY",
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE",
    0x80: "PAGE_EXECUTE_WRITECOPY",
    0x100: "PAGE_GUARD",
    0x200: "PAGE_NOCACHE",
    0x400: "PAGE_WRITECOMBINE",
}

# Protection constants indicating executable memory
EXEC_PROTECTION_FLAGS = [
    0x10,  # PAGE_EXECUTE
    0x20,  # PAGE_EXECUTE_READ
    0x40,  # PAGE_EXECUTE_READWRITE
    0x80,  # PAGE_EXECUTE_WRITECOPY
]

def print_welcome_message():
    pykd.dprintln(
        """
==================================================
            Code Cave Scanner by nop
==================================================
        -> https://nop-blog.tech/
        -> https://github.com/nop-tech/
        -> https://twitter.com/thenopcode
==================================================
"""
    )

def run(cmd):
    try:
        return pykd.dbgCommand(cmd)
    except Exception as e:
        pykd.dprintln("[!] Error executing '%s': %s" % (cmd, e))
        return ""

def get_module_range(module_name):
    pykd.dprintln("[*] Searching for module '%s' range" % module_name)
    output = run("lm m %s" % module_name)
    if "start" in output and "end" in output:
        try:
            lines = output.splitlines()
            for line in lines:
                if module_name in line:
                    parts = line.split()
                    start, end = int(parts[0], 16), int(parts[1], 16)
                    pykd.dprintln("|-> From %s to %s" % (hex(start), hex(end)))
                    return start, end
        except (IndexError, ValueError):
            pykd.dprintln("[!] Failed to parse module address range.")
    else:
        pykd.dprintln("[!] Module '%s' not found." % module_name)
    return None, None

def analyze_cave(start_addr):
    counter = 0
    while True:
        output = run("dd (%s + 4 * 0n%d) L4" % (start_addr, counter))
        counter += 1
        if "00000000 00000000 00000000 00000000" not in output:
            output = run("dd (%s + 4 * 0n%d) L4" % (start_addr, counter - 1))
            end_address = int(output.split()[0], 16)
            break
    code_cave_size = (counter + 1) * 4
    pykd.dprintln("|-> %d bytes" % code_cave_size)
    return end_address

def get_protection(addr):
    output = run("!vprot %s" % addr)
    if "Protect:" not in output:
        pykd.dprintln("[!] Failed to determine protection for %s" % addr)
        return 0
    try:
        protection_hex = output.split("Protect:           ")[1].split()[0]
        return int(protection_hex, 16)
    except (IndexError, ValueError) as e:
        pykd.dprintln("[!] Error parsing protection for %s: %s" % (addr, e))
        return 0

def analyze_memory_chunk(output, current_address):
    for line in output.splitlines():
        if "00000000 00000000 00000000 00000000" in line:
            addr = line.split()[0]
            protection = get_protection(addr)
            if protection in EXEC_PROTECTION_FLAGS:
                pykd.dprintln("\n[+] 0x%s - %s (%s)" % (
                    addr, PROTECTION_FLAGS.get(protection), hex(protection))
                )
                current_address = analyze_cave(start_addr=addr)
    return current_address

def scan_memory_range(start, end, current_address=0):
    for address in range(start, end, 0xA):
        if current_address:
            return scan_memory_range(current_address, end)
        current_address = analyze_memory_chunk(
            output=run("dd %s L100" % hex(address)), current_address=current_address
        )
    return current_address

def main():
    parser = argparse.ArgumentParser(
        prog="code_caver",
        add_help=True,
        description="Code Cave Scanner in loaded modules/binary",
    )
    parser.add_argument(
        "module_or_start",
        metavar="module_or_start",
        type=str,
        help="Enter module name or start address",
    )
    parser.add_argument(
        "end",
        metavar="endvalue",
        type=str,
        nargs="?",
        help="End address (if start is specified)",
    )
    args = parser.parse_args()
    print_welcome_message()
    start = end = None
    if args.end is None:
        start, end = get_module_range(args.module_or_start)
    else:
        try:
            start = int(args.module_or_start, 16)
            end = int(args.end, 16)
        except ValueError:
            pykd.dprintln("[!] Invalid address format.")
            sys.exit(0)
    if start is None or end is None:
        pykd.dprintln("[!] Could not determine memory range to scan.")
        sys.exit(0)
    pykd.dprintln("[*] Scanning for code caves within address range: %s - %s" % (hex(start), hex(end)))
    scan_memory_range(start, end)
    pykd.dprintln("\n[+] Done")

if __name__ == "__main__":
    main()
