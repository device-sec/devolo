#!/usr/bin/env python3

import argparse
import re
import string
import urllib.parse


def repl(m):
    lookup = string.digits + string.ascii_uppercase
    val = int(m.group(1), 16)
    alt = "%" + lookup[(val >> 4) + 15] + lookup[(val & 15) + 16]
    return alt


def main(p):
    encoded = urllib.parse.quote_plus(p)
    alt = re.sub("%([0-9a-fA-F]{2})", repl, encoded)
    print("default encoding:     {}".format(encoded))
    print("alternative encoding: {}".format(alt))


if __name__ == "__main__":
    argparser = argparse.ArgumentParser(add_help=False)
    argparser.add_argument("-p", "--parameter",  nargs=1,
                           dest="parameter", required=True, help="parameter")
    args = argparser.parse_args()
    main(args.parameter[0])
