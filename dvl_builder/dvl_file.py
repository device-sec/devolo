#!/usr/bin/env python3

import argparse
import crcmod
import os
import pickle
import struct
import sys


class DvlChunk:
    def __init__(self, data, offset):
        self.__type = None
        self.__data = None
        self.__isencrypted = True
        fmt_chunkheader = ">I4s"
        datalen = struct.calcsize(fmt_chunkheader)
        chunkheader = struct.unpack(
            fmt_chunkheader, data[offset:offset + datalen])
        offset += datalen
        self.__type = chunkheader[1]
        self.__data = bytearray(data[offset:offset + chunkheader[0]])
        offset += chunkheader[0]
        fmt_crc = ">I"
        datalen = struct.calcsize(fmt_crc)
        crc = struct.unpack(fmt_crc, data[offset:offset + datalen])[0]
        if DvlFile.dvlmagic and self.__calc_crc() != crc:
            print("error calculating crc type {}".format(
                self.__type.decode("utf-8")))

    def write(self, dvlfile):
        fmt_chunkheader = ">I4s"
        data = struct.pack(fmt_chunkheader, len(self.__data), self.__type)
        dvlfile.write(data)
        crc = self.__calc_crc()
        self.__encrypt()
        dvlfile.write(self.__data)
        fmt_crc = ">I"
        data = struct.pack(fmt_crc, crc)
        dvlfile.write(data)

    def __xorcrypt(self, encrypt):
        if self.__isencrypted != encrypt:
            try:
                xorkey = DvlFile.dvlmagic[self.__type]
                for i in range(0, len(self.__data)):
                    # broken implementation. they used the terminating \0
                    # instead of the first keychar
                    if i != 0 and i % len(xorkey) == 0:
                        continue
                    keybyte = xorkey[i % len(xorkey)]
                    # if type == DVCX nullbytes are allowed ...
                    if keybyte == self.__data[i] and self.__type != b"DVCX":
                        continue
                    self.__data[i] ^= keybyte
            except KeyError:
                pass  # no encryption
            self.__isencrypted = encrypt

    def __decrypt(self):
        self.__xorcrypt(False)

    def __encrypt(self):
        self.__xorcrypt(True)

    def set_data(self, data):
        self.__data = bytearray(data)
        self.__isencrypted = False

    def get_data(self):
        self.__decrypt()
        return self.__data

    def get_chunk_size(self):
        return 4 + 4 + 4 + len(self.__data)

    def get_type(self):
        return self.__type

    def __calc_crc(self):
        self.__decrypt()
        crc32 = crcmod.mkCrcFun(0x104c11db7, rev=False, initCrc=0x0)
        crc = crc32(self.__type)
        crc = crc32(self.__data, crc)
        size = len(self.__data) + len(self.__type)
        while size != 0:
            next = bytes([size & 0xff])
            crc = crc32(next, crc)
            size >>= 8
        crc ^= 0xffffffff
        return crc


class DvlFile:
    dvlmagicfile = "dvl_file.keys"
    dvlmagic = {}

    def __init__(self, dvlfile, check=True):
        if not DvlFile.dvlmagic and check:
            self.read_dvl_magic()
        magic = dvlfile[:8]
        if check and magic != DvlFile.dvlmagic["dvlheader"]:
            raise IOError("wrong magic")
        self.__chunks = []
        curroffset = 8
        try:
            while curroffset < len(dvlfile):
                chunk = DvlChunk(dvlfile, curroffset)
                self.__chunks.append(chunk)
                curroffset += chunk.get_chunk_size()
        except struct.error:
            pass  # eof (should not happend)

    def read_dvl_magic(self):
        with open(DvlFile.dvlmagicfile, 'rb') as f:
            DvlFile.dvlmagic = pickle.load(f)

    def write(self, dvlfile):
        dvlfile.write(DvlFile.dvlmagic["dvlheader"])
        for chunk in self.__chunks:
            chunk.write(dvlfile)

    def get_chunks(self):
        return self.__chunks


def main(args):
    if not os.path.isfile(args.dvlfile[0]):
        print("Keyfile \"{}\" is not a file.".format(args.dvlfile[0]), file=sys.stderr)
        return 1

    with open(args.dvlfile[0], "rb") as f:
        try:
            data = f.read()
            dvlfile = DvlFile(data)
        except FileNotFoundError:
            print("Keyfile \"{}\" not found. Run {} first!".format(
                DvlFile.dvlmagicfile, "dvl_keys.py"), file=sys.stderr)
            return 1

    for chunk in dvlfile.get_chunks():
        if chunk.get_type() == b"FSTY":
            print("filesystem: {}".format(chunk.get_data().decode("utf-8")))
        elif chunk.get_type() == b"VRSN":
            print("version: {}".format(chunk.get_data().decode("utf-8")))
        elif chunk.get_type() == b"DVCO":
            print("devicename: {}".format(chunk.get_data().decode("utf-8")))
        elif chunk.get_type() == b"DVCX":
            print("deviceconfig: {}".format(
                chunk.get_data().decode("utf-8")))
        else:
            print("\"{}\": {} bytes".format(
                chunk.get_type().decode("utf-8"), len(chunk.get_data())))
        if chunk.get_type() == b"FLSY" and args.extract:
            filename = "{}.squashfs".format(args.dvlfile[0])
            with open(filename, "wb") as f:
                f.write(chunk.get_data())
        if chunk.get_type() == b"CNFG" and args.extract:
            filename = "{}.xml".format(args.dvlfile[0])
            with open(filename,  "wb") as f:
                f.write(chunk.get_data())

    if args.import_data and args.type:
        for chunk in dvlfile.get_chunks():
            if chunk.get_type().decode("utf-8") == args.type[0]:
                with open(args.import_data[0], "rb") as f:
                    data = f.read()
                    chunk.set_data(data)
        with open(args.dvlfile[0], "wb") as f:
            dvlfile.write(f)

    return 0


if __name__ == "__main__":
    argparser = argparse.ArgumentParser()
    argparser.add_argument("-d", "--dvlfile", nargs=1,
                           dest="dvlfile", required=True, help="dvlfilename")
    argparser.add_argument('-e', "--extract", dest="extract",
                           action='store_true', help="extract rootfs for firmwarefile / xml config for configuration backups")
    argparser.add_argument('-i', "--import", nargs=1,
                           dest="import_data", help="import chunk")
    argparser.add_argument('-t', "--type", nargs=1,
                           dest="type", help="destination chunk type. Set to FLSY for rootfs / CNFG for configuration backups")
    args = argparser.parse_args()
    sys.exit(main(args))
