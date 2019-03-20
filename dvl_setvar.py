#!/usr/bin/env python3

import argparse
import requests as req


def set_DHCI(host, var, value):
    var = var.split(".", 1)
    url = "http://{}:22879/".format(host)
    payload = {"version": "1", "type": "sync",
               "target": var[0],  "key": var[1], "value": value}
    r = req.post(url, data=payload)
    return r.text


def set_web(host, var, value, username=None, password=None):
    url = "http://{}/cgi-bin/htmlmgr".format(host)
    key = ":sys:{}".format(var)
    payload = {key: value}
    if username and password:
        r = req.post(url, data=payload, auth=(username, password))
    else:
        r = req.post(url, data=payload)
    return r.text


def main(args):
    if args.interface[0] == "w":
        res = set_web(args.host[0],  args.config[0], args.value[0], args.username[0]
                      if args.username else None, args.password[0] if args.password else None)
    else:
        res = set_DHCI(args.host[0], args.config[0], args.value[0])
    if not args.quiet:
        print(res)


if __name__ == "__main__":
    argparser = argparse.ArgumentParser(add_help=False)
    argparser.add_argument('--help', action='help', default=argparse.SUPPRESS,
                           help=argparse._('show this help message and exit'))
    argparser.add_argument("-c", "--configvar",  nargs=1,
                           dest="config", required=True, help="name of config var")
    argparser.add_argument("-v", "--value",  nargs=1,
                           dest="value", required=True, help="value for configvar")
    argparser.add_argument("-h", "--host", nargs=1,
                           dest="host", required=True, help="hoastaddr")
    argparser.add_argument('-i', "--interface",  choices=["d", "w"],  dest="interface",
                           required=True,  help="choose interface to use: (w)eb or (d)hci")
    argparser.add_argument("-u", "--user", nargs=1,
                           dest="username", help="username for webinterface")
    argparser.add_argument("-p", "--pass", nargs=1,
                           dest="password", help="password for webinterface")
    argparser.add_argument('-q', "--quiet",  dest="quiet",
                           action='store_true',  help="supress output")

    args = argparser.parse_args()
    main(args)
