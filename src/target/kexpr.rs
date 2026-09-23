use anyhow::{anyhow, Result};
use drgn_knight::*;

use super::expr::{Expr, Op};
use super::Bus;

impl Expr {
    /// Walk the parsed steps from `root` and read the final value, or its
    /// address when the expression started with `&`.
    pub fn eval(&self, root: &Object) -> Result<u64> {
        let mut cur: Option<Object> = None;
        let mut prev: Option<&str> = None;
        for step in &self.steps {
            let obj = cur.as_ref().unwrap_or(root);
            let next = match step.op {
                Op::Access => obj.member(&step.member),
                Op::Deref => obj.deref_member(&step.member),
            };
            cur = Some(next.ok_or_else(|| match prev {
                Some(prev) => anyhow!("member {:?} not found after {prev:?}", step.member),
                None => anyhow!("member {:?} not found", step.member),
            })?);
            prev = Some(&step.member);
        }

        let cur = cur.expect("Expr::parse never yields an empty expression");
        if self.addr_of {
            cur.address_of()
                .ok_or_else(|| anyhow!("can't take the address of {:?}", prev.unwrap_or("")))?
                .to_num()
        } else {
            cur.to_num()
        }
    }
}

pub fn task(pid: u64, expr: &str) -> Result<usize> {
    let expr = Expr::parse(expr)?;
    let prog = Program::new()?;
    let task = prog.find_task(pid)?;
    Ok(expr.eval(&task)? as usize)
}

fn bus_to_subsys(prog: &Program, bus: &str) -> Result<Object> {
    let bus_kset = prog.find_object_variable("bus_kset")?;
    let bus_kset_list = bus_kset
        .deref_member("list")
        .ok_or(anyhow!("Fail to find member list"))?;
    let subsys_list = List::new(bus_kset_list, "struct subsys_private", "subsys.kobj.entry")?;

    for subsys in subsys_list {
        let Some(bus_type) = subsys.deref_member("bus") else {
            continue;
        };

        let Some(bus_name) = bus_type.deref_member("name") else {
            continue;
        };

        let Ok(name) = bus_name.to_str() else {
            continue;
        };

        if bus == name {
            return Ok(subsys);
        };
    }

    Err(anyhow!(format!("Bus {bus} is not found")))
}

fn find_busdev(prog: &Program, bus: &str, dev_name: &str) -> Result<Object> {
    let sp = bus_to_subsys(prog, bus)?;
    let sp_k_list = sp
        .deref_member("klist_devices")
        .ok_or(anyhow!("Fail to find member klist_devices"))?
        .member("k_list")
        .ok_or(anyhow!("Fail to find member k_list"))?;

    let dev_list = List::new(sp_k_list, "struct device_private", "knode_bus.n_node")?;

    for dev in dev_list {
        let device = dev
            .deref_member("device")
            .ok_or(anyhow!("Fail to find member device"))?;
        let device_name = device
            .deref_member("kobj")
            .ok_or(anyhow!("Fail to find member kobj"))?
            .member("name")
            .ok_or(anyhow!("Fail to find member name"))?
            .to_str()?;

        if device_name == dev_name {
            return Ok(device);
        }
    }

    Err(anyhow!("Fail to find {dev_name} on bus {bus}"))
}

pub fn busdev(bus: Bus, dev_name: &str, expr: &str) -> Result<usize> {
    let expr = Expr::parse(expr)?;
    let (bus_name, dev_struct) = bus.table();
    let prog = Program::new()?;
    let busdev = find_busdev(&prog, bus_name, dev_name)?;
    let dev = busdev
        .container_of(dev_struct, "dev")
        .ok_or(anyhow!("Fail to get data for device {dev_name}"))?;
    Ok(expr.eval(&dev)? as usize)
}
