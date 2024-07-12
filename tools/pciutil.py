from drgn import cast

def pci_get_drvdata(typ, pdev):
    # Cast driver_data to the given type. For example:
    # pci_get_drvdata("struct net_device *", pdev)
    return cast(typ, pdev.dev.driver_data)
