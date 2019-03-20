#!/usr/bin/env python3

import argparse
import hashlib
import os
import pickle
import shutil
import subprocess
import sys
import tempfile
from dvl_file import DvlFile


hints = {
    "7094d3271bf20d2abf3fc9fa3d36118c": {"offsets": {
        b"FSTY": 45992, b"VRSN": 47124, b"CNFG": 45748, b"DVCX": 44824},
        "device": "dLAN 550 WiFi", "version": "v1.2.0", "url": "https://www.devolo.de/fileadmin/Web-Content/DE/Contentseiten/Downloads/Firmware/550_WiFi/firmware-dLAN_550_WiFi-v1-2-0__1_.dvl"}
}


def build_write_magic(data, offsets):
    magic = {}
    magic["dvlheader"] = data[:8]
    dvlfile = DvlFile(data, False)
    retval = 0
    for chunk in dvlfile.get_chunks():
        if chunk.get_type() == b"FLSY":
            # create tempfile
            handle, squashfsfile = tempfile.mkstemp()
            # writesquashfs into tempfile
            os.write(handle, chunk.get_data())
            os.close(handle)
            # mktempdir
            tempdir = tempfile.mkdtemp()
            root = os.path.join(tempdir, "root")
            chunkbinpath = "usr/sbin/chunk"
            # extract binary into tempdir
            cmd = ["unsquashfs",  "-d", root, squashfsfile, chunkbinpath]
            try:
                print("> {}".format(" ".join(cmd)))
                subprocess.call(cmd)
                chunkbinpath = os.path.join(root, chunkbinpath)
                with open(chunkbinpath, "rb") as f:
                    data = f.read()
                    for k, start in offsets.items():
                        end = data.find(b"\x00", start)
                        magic[k] = data[start:end]
                with open(DvlFile.dvlmagicfile, 'wb') as f:
                    pickle.dump(magic, f)
                for k, v in magic.items():
                    print("key {}, value {}".format(k, v))
            except OSError as e:
                print(e)
                retval = 1
            break
            os.remove(squashfsfile)
            shutil.rmtree(tempdir)
    return retval


def main(args):
    try:
        with open(args.dvlfile[0],  "rb") as f:
            data = f.read()
            md5 = hashlib.md5()
            md5.update(data)
        return build_write_magic(data, hints[md5.hexdigest()]["offsets"])

    except KeyError as f:
        print("wrong file :(", file=sys.stderr)
        print("download one of the following firmwareimages:", file=sys.stderr)
        for md5hash, firmware in hints.items():
            print("{} / {}, url: {} md5sum: {}".format(firmware["device"], firmware["version"], firmware["url"], md5hash), file=sys.stderr)
        return 1


if __name__ == "__main__":
    argparser = argparse.ArgumentParser()
    argparser.add_argument("-d", "--dvlfile", nargs=1,
                           dest="dvlfile", required=True, help="dvlfilename")
    args = argparser.parse_args()
    sys.exit(main(args))
