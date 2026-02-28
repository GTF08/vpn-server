use std::{str::FromStr, sync::Arc, process};
//use tokio::net::TcpStream;

use server::Server;

use crate::key_management::generate_and_save_keys;

mod messages;
mod diffie_hellman;
mod server;
mod client;
mod key_management;
mod socket_wrapper;
mod bufferpool;

//iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
//sudo iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT
//sudo iptables -A FORWARD -i eth0 -o tun0 -j ACCEPT
//iptables -t nat -A PREROUTING -i $VPN_INTERFACE -p udp --dport 53 -j DNAT --to-destination 8.8.8.8:53
//iptables -t nat -A PREROUTING -i $VPN_INTERFACE -p tcp --dport 53 -j DNAT --to-destination 8.8.8.8:53

//curl ifconfig.me  # Should show your server's IP
//nslookup myip.opendns.com resolver1.opendns.com  # Should show your server's IP
use pprof::ProfilerGuard;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    std::thread::spawn(|| {
        let guard = ProfilerGuard::new(100).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(80));
        if let Ok(report) = guard.report().build() {
            let mut file = std::fs::File::create("flamegraph.svg").unwrap();
            report.flamegraph(&mut file).unwrap();
            println!("Flamegraph saved");
        }
    });

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("USAGE:\n    START VPN LISTEN\n\t{} listen <credentials_filepath> <signing_key_filepath> <listen_port> <tun_ip> <tun_netmask> \n    GENERATE KEYS FOR VPN\n\t{} keygen <private_key_path> <public_key_path>\n", args[0], args[0]);
        process::exit(1);
    }

    match args[1].as_str() {
        "listen" => {
            if args.len() != 7 {
                 eprintln!("USAGE:\n    {} listen <credentials_filepath> <signing_key_filepath> <listen_port> <tun_ip> <tun_netmask>", args[0]);
                process::exit(1);
            } else {
                let credentials_filename = &args[2];
                let signing_key_filepath = &args[3];
                //let listen_addr = &args[4];
                let listen_port = &args[4];
                let tun_address = std::net::Ipv4Addr::from_str(&args[5])?;
                let tun_netmask = std::net::Ipv4Addr::from_str(&args[6])?;

                let server = server::Server::new(
                    credentials_filename,
                    signing_key_filepath,
                    &listen_port, 
                    &tun_address.to_string(), 
                    &tun_netmask.to_string()).await?;
                let server = Arc::new(server);
                Server::run(&server).await?;
            }
        },
        "keygen" => {
            if args.len() != 4 {
                eprintln!("USAGE:\n    {} keygen <private_key_path> <public_key_path>", args[0]);
                process::exit(1);
            } else {
                let private_key_path = &args[2];
                let public_key_path = &args[3];
                generate_and_save_keys(private_key_path, public_key_path)?;
            }
        }
        _ => {
                eprintln!("USAGE:\n    START VPN LISTEN\n\t{} listen <credentials_filepath> <signing_key_filepath> <listen_addr> <listen_port> <tun_ip> <tun_netmask> \n    GENERATE KEYS FOR VPN\n\t{} <keygen private_key_path> <public_key_path>\n", args[0], args[0]);
                process::exit(1);
        }
    }

    

    return Ok(());
}