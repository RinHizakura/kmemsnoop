#!/usr/bin/env drgn

import argparse

import drgn
from drgn.helpers.common import *
from drgn.helpers.linux import *

import importlib
drgn_utils = importlib.import_module("drgn-utils.subsys_dev")

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, help="pid of the task_struct")
    parser.add_argument("--pci_dev", type=str, help="name of the pci device")
    parser.add_argument("--usb_dev", type=str, help="name of the usb device")
    parser.add_argument("--plat_dev", type=str, help="name of the platform device")
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

def busdev_kexpr2addr(bus, device, kexpr):
    dev = drgn_utils.get_busdev(prog, bus, device)
    if not dev:
        exit(f"Can find device-specified struct for {device}")

    dev = drgn_utils.to_subsys_dev(bus, dev)
    parse_kexpr(dev, kexpr)

args = get_args()
pid = args.pid
pci_dev = args.pci_dev
usb_dev = args.usb_dev
plat_dev = args.plat_dev
kexpr = args.kexpr


# If multiple kexpr is specified, only one
# of it will be used by order
if pid:
    task_kexpr2addr(pid, kexpr)
elif pci_dev:
    busdev_kexpr2addr("pci", pci_dev, kexpr)
elif usb_dev:
    busdev_kexpr2addr("usb", usb_dev, kexpr)
elif plat_dev:
    busdev_kexpr2addr("platform", plat_dev, kexpr)
else:
    print(f"Invalid arguments {args}")
    exit(1)

