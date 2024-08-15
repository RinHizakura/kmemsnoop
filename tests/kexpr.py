#!/usr/bin/env drgn

import argparse

import drgn
from drgn.helpers.common import *
from drgn.helpers.linux import *

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pid", type=int, help="pid of the task_struct")
    parser.add_argument("kexpr")
    args = parser.parse_args()
    return args

args = get_args()
pid = args.pid
kexpr = args.kexpr

if not pid:
    exit(1)

task = find_task(pid)
if not task:
    exit(f"Can find task_struct for pid={pid}")

if kexpr[0] == "*":
    print(eval(f"hex(task.{kexpr[1:]})"))
else:
    print(eval(f"hex(task.{kexpr}.address_)"))
