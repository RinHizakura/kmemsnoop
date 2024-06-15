import sys

import drgn
from drgn.helpers.common import *
from drgn.helpers.linux import *

if len(sys.argv) < 2:
    exit(f"usage: {sys.argv[0]} pid")

pid = int(sys.argv[1])

task = find_task(pid)
if not task:
    exit(f"Can find task_struct for pid={pid}")

task_addr = hex(task.value_())
print(f"task_struct@{task_addr}: \n{task}")
print(f"sched_entity:\n{task.se}")
