import argparse

import drgn
from drgn.helpers.common import *
from drgn.helpers.linux import *
from drgn import Object

IRQ_TYPE_EDGE_RISING = 0x00000001
IRQ_TYPE_EDGE_FALLING = 0x00000002
IRQ_TYPE_EDGE_BOTH = (IRQ_TYPE_EDGE_FALLING | IRQ_TYPE_EDGE_RISING)
IRQ_TYPE_LEVEL_HIGH = 0x00000004
IRQ_TYPE_LEVEL_LOW = 0x00000008
IRQ_TYPE_LEVEL_MASK = (IRQ_TYPE_LEVEL_LOW | IRQ_TYPE_LEVEL_HIGH)
IRQ_TYPE_SENSE_MASK = 0x0000000f

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("irq", type=int, help="number of the irq")
    args = parser.parse_args()
    return args

def irq_to_desc(irq):
    addr = radix_tree_lookup(prog["irq_desc_tree"].address_of_(), irq)
    return Object(prog, "struct irq_desc", address=addr).address_of_()

def irq_settings_get_trigger_mask(desc):
    return desc.status_use_accessors & IRQ_TYPE_SENSE_MASK

args = get_args()
irq = args.irq

desc = irq_to_desc(irq)
print(desc)
print("trigger = ", irq_settings_get_trigger_mask(desc))
