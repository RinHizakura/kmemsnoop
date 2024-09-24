#!/usr/bin/env drgn

import argparse

import drgn
from drgn.helpers.common import *
from drgn.helpers.linux import *

import importlib
drgn_utils = importlib.import_module("drgn-utils.subsys_dev")

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pid", type=int, help="pid of the task_struct")
    parser.add_argument("-d", "--device", type=str,
            help="name of the device in the format {dev}@{subsys}")
    parser.add_argument("kexpr")
    args = parser.parse_args()
    return args

def parse_kexpr(obj, kexpr):
    if kexpr[0] == "*":
        print(eval(f"hex(obj.{kexpr[1:]})"))
    else:
        print(eval(f"hex(obj.{kexpr}.address_)"))

def task_kexpr2addr(pid, kexpr):
    task = find_task(pid)
    if not task:
        exit(f"Can find 'struct task_struct' for pid={pid}")

    parse_kexpr(task, kexpr)

def dev_kexpr2addr(device, kexpr):
    tok = device.split("@")
    if len(tok) != 2:
        exit("The name of device should be <dev>@<bus/class>")
    dev_name = tok[0]
    bus = tok[1]
    dev = drgn_utils.get_busdev(prog, bus, dev_name)
    if not dev:
        exit(f"Can find 'struct device' for {device}")

    parse_kexpr(dev, kexpr)

args = get_args()
pid = args.pid
device = args.device
kexpr = args.kexpr

if pid and device:
    exit(1)

if not pid and not device:
    exit(1)

if pid:
    task_kexpr2addr(pid, kexpr)
elif device:
    dev_kexpr2addr(device, kexpr)

