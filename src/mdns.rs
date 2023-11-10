use mdns_sd::{ServiceDaemon, ServiceInfo};
use std::net::IpAddr;
use std::thread;

use crate::nearby_share;

struct MdnsHandle {
    daemon: ServiceDaemon,
    fullname: String,
}

impl MdnsHandle {
    fn kill(&self) {
        self.daemon.unregister(self.fullname.as_str()).unwrap();
        self.daemon.shutdown().unwrap();
    }
}

fn create_mdns_server(device_name: String, port: u16) -> MdnsHandle {
    // Create a daemon
    let mdns = ServiceDaemon::new().expect("Failed to create daemon");

    // Create a service info.
    let name: String = nearby_share::generate_name();

    let record =
        nearby_share::generate_txt_record(device_name.clone(), nearby_share::DeviceType::LAPTOP);
    let service_type = "_FC9F5ED42C8A._tcp.local.";
    let instance_name = &*name;
    let host_ipv4 = local_ip_address::local_ip().unwrap().to_string();
    let host_name = format!("{}.local.", host_ipv4.clone());
    let port = port;
    let properties = [("n", record)];

    let my_service = ServiceInfo::new(
        service_type,
        instance_name,
        host_name.clone().as_str(),
        host_ipv4.clone(),
        port,
        &properties[..],
    )
    .unwrap()
    .enable_addr_auto();

    let fullname = my_service.get_fullname().to_string();

    // Register with the daemon, which publishes the service.
    mdns.register(my_service)
        .expect("Failed to register our service");

    println!(
        "Started MDNS service at ip {} with device name {}\n",
        host_ipv4, device_name
    );

    MdnsHandle {
        daemon: mdns,
        fullname,
    }
}

pub fn run_mdns_server(device_name: String, port: u16){
    let mut mdns = create_mdns_server(device_name.clone(), port);
    let mut last_v4: Option<IpAddr> = None;
    loop {
        use network_interface::NetworkInterface;
        use network_interface::NetworkInterfaceConfig;
        let network_interfaces = NetworkInterface::show().unwrap();

        let mut current_v4: Option<IpAddr> = None;
        for itf in network_interfaces.iter() {
            let has_ipv4 = itf.addr.iter().any(|addr| addr.ip().is_ipv4());
            let is_loopback = itf.addr.iter().any(|addr| addr.ip().is_loopback());
            if has_ipv4 && !is_loopback {
                current_v4 = Some(
                    itf.addr
                        .iter()
                        .find(|addr| addr.ip().is_ipv4())
                        .unwrap()
                        .ip(),
                );
                if last_v4.is_none() {
                    last_v4 = current_v4;
                }
            }
        }
        // Check if ip changed
        if current_v4.is_some() && current_v4 != last_v4 {
            last_v4 = current_v4;

            println!("IP changed to {}", current_v4.unwrap());

            // Update mdns
            mdns.kill();
            mdns = create_mdns_server(device_name.clone(), port);
        }
        thread::sleep(std::time::Duration::from_secs(1));
    }
}
