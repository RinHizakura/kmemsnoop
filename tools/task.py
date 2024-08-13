#!/usr/bin/env drgn

import argparse

import drgn
from drgn.helpers.common import *
from drgn.helpers.linux import *

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pid", type=int, help="pid of the task_struct")
    args = parser.parse_args()
    return args

pid = get_args().pid

if not pid:
    for task in for_each_task(prog):
        print(f"pid={task.pid.value_()}: {cmdline(task)}")
    exit(0)

task = find_task(pid)
if not task:
    exit(f"Can find task_struct for pid={pid}")

task_addr = hex(task.value_())
print(f"task_struct@{task_addr}: \n{task}")
print(f"sched_entity:\n{task.se}")
