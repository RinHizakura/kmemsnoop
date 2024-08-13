#!/usr/bin/env drgn

import os, sys
import argparse

import drgn
from drgn.helpers.common import *
from drgn.helpers.linux import *
from drgn import container_of

def linux_ver():
    v = os.uname().release.split('.')
    main = int(v[0])
    sub = int(v[1])
    return (main, sub)

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("bus", help="bus type for the device",
            choices=["platform", "usb", "pci"])
    parser.add_argument("-d", "--dev", help="name of the specified device")
    args = parser.parse_args()
    return args

def bus_to_subsys(bus):
    for sp in list_for_each_entry(
        "struct subsys_private",
        prog["bus_kset"].list.address_of_(),
        "subsys.kobj.entry",
    ):
        if sp.bus == bus:
            return sp
    return NULL(bus.prog_, "struct subsys_private *")

class ToDriver():
    def to_platform_driver(d):
        return container_of(d, f"struct platform_driver", "driver")

    def to_usb_driver(d):
        # Consider different Linux version, try to get
        # usb_driver in two different way
        if linux_ver() < (6, 8):
            return container_of(d, f"struct usb_driver", "drvwrap.driver")
        else:
            return container_of(d, f"struct usb_driver", "driver")

    def to_pci_driver(d):
        return container_of(d, f"struct pci_driver", "driver")

args = get_args()
bus = args.bus
dev = args.dev

sp = bus_to_subsys(prog[f"{bus}_bus_type"].address_of_())

for priv in list_for_each_entry(
    "struct driver_private", sp.drivers_kset.list.address_of_(), "kobj.entry"
):
    driver = priv.driver
    driver_name = driver.name.string_().decode()
    if dev and driver_name != dev:
        continue
    print(f"=== {driver_name} ===\n{driver}")

    to_driver = getattr(ToDriver, f"to_{bus}_driver")
    inner_driver = to_driver(driver)
    print(inner_driver)
