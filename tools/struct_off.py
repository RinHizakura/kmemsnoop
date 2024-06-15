import argparse

import drgn
from drgn.helpers.common import *
from drgn.helpers.linux import *
from drgn import offsetof


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("struct",
            help="name of the struct(for example: \"struct task_struct\")")
    parser.add_argument("member", help="member in the struct")
    args = parser.parse_args()
    return args

args = get_args()

struct = args.struct
member = args.member
off = offsetof(prog.type(f"{struct}"), member)

print(f"offset of '{member}' in '{struct}' = {off}")
