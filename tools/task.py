import argparse

import drgn
from drgn.helpers.common import *
from drgn.helpers.linux import *

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("pid", type=int, help="pid of the task_struct")
    args = parser.parse_args()
    return args

if len(sys.argv) < 2:
    exit(f"usage: {sys.argv[0]} pid")

pid = get_args().pid

task = find_task(pid)
if not task:
    exit(f"Can find task_struct for pid={pid}")

task_addr = hex(task.value_())
print(f"task_struct@{task_addr}: \n{task}")
print(f"sched_entity:\n{task.se}")
