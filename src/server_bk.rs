use std::os::fd::AsRawFd;
use std::{collections::HashMap, net::{IpAddr, Ipv4Addr, SocketAddr}, path::Path, str::FromStr, sync::Arc, usize};
use crossbeam_queue::ArrayQueue;
use libc::{iovec, mmsghdr, sa_family_t, sockaddr_in, sockaddr_in6, sockaddr_storage, socklen_t};
use packet::ip;
use rand::{rngs::OsRng, Rng};

use tokio::io::unix::AsyncFd;
use tokio::{io::{AsyncBufReadExt}, sync::{mpsc, Mutex}, time::Instant};
use tun_rs::{AsyncDevice, DeviceBuilder, GROTable, IDEAL_BATCH_SIZE, PACKET_INFORMATION_LENGTH, VIRTIO_NET_HDR_LEN};

use tokio::io::{BufReader};
use aes_gcm_siv::{
    aead::{AeadMut, KeyInit}, AeadCore, Aes256GcmSiv, Nonce // Or `Aes128Gcm`
};

use x25519_dalek::PublicKey;
use ed25519_dalek::{ed25519::signature::Signer, SigningKey};

use tokio::fs::File;
use crate::socket_wrapper::CustomUdpSocket;
use crate::{diffie_hellman::generate_keypair, key_management::load_signing_key, messages::{AuthData, CryptoSupported, DHKeyPacket, DHKeyResponsePacket, EncryptedMessage, PacketType, TunnelSettingsPkt}};
use std::thread::available_parallelism;


const HANDSHAKE_TIMEOUT_SECS: u64 = 5;
const MAX_DATAGRAMS : usize = 128;
const USER_CLEANUP_INTERVAL: tokio::time::Duration = tokio::time::Duration::from_secs(5);
const USER_TIMEOUT_DURATION: tokio::time::Duration = tokio::time::Duration::from_secs(10);

async fn read_credentials_file(filename: impl AsRef<Path>) -> Result<HashMap<String, String>, Box<dyn std::error::Error + Send + Sync>> {
    let file = File::open(filename).await?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let mut credentials = HashMap::<String, String>::new();

    while let Some(line) = lines.next_line().await? {
        let words: Vec<&str> = line.split(" ").collect();
        if words.len() != 2 {
            eprintln!("Wrong credentials file format\n
            expected \"username password_hash\"\n
            received \"{line}\"");
        }
        let (username, password_hash) = (words[0], words[1]);

        match credentials.get(username) {
            Some(_) => {
                return Err(format!("Duplicate username password for user {username} in credentials file").into())
            },
            None => {
                credentials.insert(username.to_owned(), password_hash.to_owned());
            },
        }

        
    }

    Ok(credentials)
}



pub struct Server {
    //tun_interface: Arc<Mutex<Framed<AsyncDevice, TunPacketCodec>>>,
    signing_key: SigningKey,
    tun_ip: Ipv4Addr,
    tun_netmask: Ipv4Addr,
    tun_device: Arc<AsyncDevice>,
    credentials: HashMap<String, String>,
    udpsocket_fd: AsyncFd<CustomUdpSocket>,
    available_ip_addresses: ArrayQueue<IpAddr>,
    pub_to_priv_ip: Mutex<HashMap<SocketAddr, IpAddr>>,
    priv_ip_to_client: Mutex<HashMap<IpAddr, VPNClient>>,
}

struct VPNClient {
    client_nonce: u128,
    server_nonce: u128,
    public_ip: SocketAddr,
    authorized: bool,
    cipher: Aes256GcmSiv,
    lastseen: Instant
    // Other client-specific data
}


fn create_tun(tun_ip : &str, tun_netmask: &str) -> Result<AsyncDevice, Box<dyn std::error::Error + Send + Sync>> {
    let dev = DeviceBuilder::new()
        .name("sucktun0")
        .multi_queue(true)
        .offload(true)
        .ipv4(tun_ip, tun_netmask, None)
        .mtu(1400u16)
        .build_async()?;
        

    Ok(dev)
}


impl Server {
    pub async fn new(
        credentials_path: &String,
        signing_key_path: &str,
        listen_port: &String, 
        tun_ip: &String, 
        tun_netmask: &String
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        //creating tunnel interface  
        let signing_key = load_signing_key(signing_key_path)?;
        
        let tun_interface = create_tun(tun_ip, tun_netmask)?;
        let tun_interface = Arc::new(tun_interface);
        

        //let listener = TcpListener::bind(format!("{}:{}", listen_addr, listen_port)).await?;
        //let listener = UdpSocket::bind(format!("{}:{}", listen_addr, listen_port)).await?;
        let udp_socket = CustomUdpSocket::new(u16::from_str(listen_port)?)?;
        let async_udp_socket_fd = AsyncFd::new(udp_socket)?;

        let address_count: u32 = (!std::net::Ipv4Addr::from_str(&tun_netmask)?).to_bits();
        
        let tun_ip_addr = Ipv4Addr::from_str(&tun_ip)?;
        let tun_netmask_addr = Ipv4Addr::from_str(&tun_netmask)?;
        let tun_network =  tun_ip_addr & tun_netmask_addr;
        
        //generation ip pool
        let available_ip_addresses = ArrayQueue::<IpAddr>::new(address_count as usize);
        for i in 1..address_count {
            let new_ip_addr = IpAddr::V4(Ipv4Addr::from_bits(tun_network.to_bits() + i));
            if new_ip_addr != IpAddr::V4(tun_ip_addr) {
                    available_ip_addresses.push(new_ip_addr).unwrap();
            }
        }
        
        //reading credentials from file
        let credentials = read_credentials_file(credentials_path).await?;

        Ok(Self {
            credentials,
             //tun_interface: Arc::new(Mutex::new(tun_interface)),
            signing_key,
            tun_ip: tun_ip_addr,
            tun_netmask: tun_netmask_addr,
            tun_device: tun_interface,
            udpsocket_fd: async_udp_socket_fd,
            available_ip_addresses,
            pub_to_priv_ip: Mutex::new(HashMap::new()),
            priv_ip_to_client: Mutex::new(HashMap::new())
        })
    }


    fn encrypt_packet(self: &Arc<Self>, bytes: &[u8], cipher: &mut Aes256GcmSiv) -> Result<EncryptedMessage, Box<dyn std::error::Error + Send + Sync>> {
        let nonce = Aes256GcmSiv::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, bytes)
            .map_err(|e| format!("{e}")).unwrap();
        let encrypted_pkt = EncryptedMessage {
            ciphertext,
            nonce: nonce.to_vec(),
        };
        Ok(encrypted_pkt)
    }

    fn decrypt_packet(self: &Arc<Self>, encrypted_msg: &EncryptedMessage, cipher: &mut Aes256GcmSiv) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let decrypted = cipher.decrypt(&Nonce::from_slice(&encrypted_msg.nonce), &encrypted_msg.ciphertext[..])
            .map_err(|e| format!("{e}")).unwrap();
        Ok(decrypted)
    }
    //TODO 
    fn sock_write_batch(
        self: &Arc<Self>,
        batch: &mut [(SocketAddr, Vec<u8>)]
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

        // let mut msghdrs: [mmsghdr; MAX_DATAGRAMS] = unsafe { std::mem::zeroed() };
        // let mut iovs: [iovec; MAX_DATAGRAMS] = unsafe { std::mem::zeroed() };
        // let mut addrs: [sockaddr_in; MAX_DATAGRAMS] = unsafe { std::mem::zeroed() };
        // let mut addr_lens: [socklen_t; MAX_DATAGRAMS] = [std::mem::size_of::<sockaddr_in>() as socklen_t; MAX_DATAGRAMS];

        let mut msghdrs: Vec<mmsghdr> = Vec::with_capacity(batch.len());
        let mut iovs: Vec<iovec> = Vec::with_capacity(batch.len());
        let mut addrs: Vec<sockaddr_storage> = Vec::with_capacity(batch.len());
        let mut addr_lens: Vec<socklen_t> = Vec::with_capacity(batch.len());

        for i in 0..batch.len() {
            iovs.push(
                iovec {
                    iov_base: batch[i].1.as_mut_ptr() as *mut libc::c_void,
                    iov_len: batch[i].1.len(),
                }
            );

            addrs.push(
                match batch[i].0 {
                    SocketAddr::V4(socket_addr_v4) => {
                        let sockaddr = sockaddr_in {
                            sin_family: libc::AF_INET as sa_family_t,
                            sin_port: socket_addr_v4.port().to_be(),
                            sin_addr: libc::in_addr {
                                s_addr: u32::from(socket_addr_v4.ip().to_bits()).to_be(),
                            },
                            sin_zero: [0; 8],
                        };
                        unsafe { *(&sockaddr as *const sockaddr_in as *const sockaddr_storage) }
                    },
                    SocketAddr::V6(socket_addr_v6) => {
                        let sockaddr = sockaddr_in6 {
                            sin6_family: libc::AF_INET6 as sa_family_t,
                            sin6_port: socket_addr_v6.port().to_be(),
                            sin6_flowinfo: socket_addr_v6.flowinfo(),
                            sin6_addr: libc::in6_addr {
                                s6_addr: socket_addr_v6.ip().octets(),
                            },
                            sin6_scope_id: socket_addr_v6.scope_id(),
                        };
                        unsafe { *(&sockaddr as *const sockaddr_in6 as *const sockaddr_storage) }
                    },
                }
            );

            addr_lens.push(
                match batch[i].0 {
                    SocketAddr::V4(_) => {
                        std::mem::size_of::<sockaddr_in>() as u32
                    },
                    SocketAddr::V6(_) => {
                        std::mem::size_of::<sockaddr_in6>() as u32
                    },
                }
            );

            msghdrs.push(
                mmsghdr {
                    msg_hdr: libc::msghdr {
                        msg_name: &mut addrs[i] as *mut _ as *mut libc::c_void,
                        msg_namelen: addr_lens[i],
                        msg_iov: &mut iovs[i],
                        msg_iovlen: 1,
                        msg_control: std::ptr::null_mut(),
                        msg_controllen: 0,
                        msg_flags: 0,
                    },
                    msg_len: 0,
                }
            ); 
        }

        let result = unsafe { 
            libc::sendmmsg(
                self.udpsocket_fd.as_raw_fd(), 
                msghdrs.as_mut_ptr(), 
                MAX_DATAGRAMS as u32, 
                0) 
        };

        match result {
            -1 => {
                let err = std::io::Error::last_os_error();
                return Err(err.into());
            },
            _ => Ok(())
        }
    }

    async fn sock_write(
        self: &Arc<Self>,
        data: PacketType,
        dst_addr: SocketAddr
    )  -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        // while let Some((msg, addr)) = consumer.recv().await {
        //     let bytes = bincode::encode_to_vec(msg, bincode::config::standard())?;
        //     write.send_to(&bytes, addr).await?;
        // }
        // Ok(())
        //let guard = self.udpsocket_fd.writable().await?;
        let bytes = bincode::encode_to_vec(data, bincode::config::standard())
            .map_err(|e| {println!("{e}"); format!("{e}")})?;

        self.udpsocket_fd.get_ref().send_to(&bytes, dst_addr)?;
        Ok(())
    }


    async fn tun_read_loop(
        self: Arc<Self>
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        let mut original_buffer = vec![0; VIRTIO_NET_HDR_LEN + 65535];
        let mut bufs = vec![vec![0u8; 1500]; IDEAL_BATCH_SIZE];
        let mut sizes = vec![0; IDEAL_BATCH_SIZE];

        loop {
            match self.tun_device.recv_multiple(&mut original_buffer, &mut bufs, &mut sizes, 0).await {
                Ok(read_count) => {
                    let mut send_buffers: Vec<(SocketAddr, Vec<u8>)> = Vec::with_capacity(MAX_DATAGRAMS);
                    let mut send_count = 0;

                    for i in 0..read_count {
                        let len = sizes[i];
                        if len < 20 {
                            continue;
                        }

                        
                        if let Some((_, destination)) = get_packet_info(&bufs[i][..len]) {
                            if let Some(client) = self.priv_ip_to_client.lock().await.get_mut(&destination) {
                                let encrypted_msg = self.encrypt_packet(&bufs[i][..len], &mut client.cipher)?;
                                let encrypted_pkt = PacketType::EncryptedPkt(encrypted_msg);
                                let bytes = bincode::encode_to_vec(encrypted_pkt, bincode::config::standard())
                                    .map_err(|e| {eprintln!("{e}"); format!("{e}")})?;
                                send_buffers.push((client.public_ip, bytes));
                                // let mut test = vec![(client.public_ip, bytes)];
                                // self.sock_write_batch(&mut test)?;
                                send_count += 1;
                                //self.sock_write(PacketType::EncryptedPkt(encrypted_pkt), client.public_ip).await?;
                            }
                        }
                    }
                    
                    if send_count > 0 {
                        self.sock_write_batch(&mut send_buffers[..send_count])?;
                    }
                },
                Err(e) => {
                    eprintln!("{e}")
                },
            }
        }
        return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
    }


    fn check_authdata(self : &Arc<Self>, authdata: AuthData) 
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> 
    {
        if let Some(password_hash) = self.credentials.get(&authdata.username) {
            if authdata.password == *password_hash {
                return Ok(())
            } else {
                return Err("Wrong Credentials".into())
            }
        } else {
            return Err("User data not found".into())
        }
    }

    fn find_available_ip(self: &Arc<Self>) 
    -> Result<IpAddr, Box<dyn std::error::Error + Send + Sync>>
    {
        //let mut ip_pool_lock = self.available_ip_addresses.lock().await;
        
        if let Some(ip_to_assign) = self.available_ip_addresses.pop() {
            return Ok(ip_to_assign)
        } else {
            eprintln!("No IP addresses available for new client");
            return Err("No IP addresses available for new client".into());
        };
    }

    async fn handle_handshake(self: &Arc<Self>, client_dhkey_pkt: &DHKeyPacket, src_addr: &SocketAddr) 
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> 
    {
        if let Some(_) = self.pub_to_priv_ip.lock().await.get(src_addr) {
            eprintln!("User {} is already connected", src_addr);
            return Err(format!("User {} is already connected", src_addr).into());
        }

        let sized_key_array: [u8; 32] = client_dhkey_pkt.pub_key.clone().try_into().unwrap();
        let other_pubkey = PublicKey::from(sized_key_array);

        let (secret, public) = generate_keypair();
        let shared_key = secret.diffie_hellman(&other_pubkey);

        let cipher = Aes256GcmSiv::new(shared_key.as_bytes().into());


        let server_nonce: u128 = rand::thread_rng().r#gen();
        
        let public_key = public.to_bytes().to_vec();
        let signature = self.signing_key.sign(&public_key).to_vec();
        let dh_key_pkt_response = PacketType::HandshakeResponse(
            DHKeyResponsePacket { 
                pub_key: public_key,
                nonce: server_nonce,
                signature: signature
            }
        );

        self.sock_write(dh_key_pkt_response, *src_addr).await?;

        let vpnclient = VPNClient {
            client_nonce: client_dhkey_pkt.nonce,
            server_nonce: server_nonce,
            public_ip: *src_addr,
            authorized: false,
            cipher,
            lastseen: Instant::now(),
        };

        //4. find available tunnel ip
        if let Ok(assigned_ip) = self.find_available_ip() {
            self.pub_to_priv_ip.lock().await.insert(*src_addr, assigned_ip);
            self.priv_ip_to_client.lock().await.insert(assigned_ip, vpnclient);
            
            println!("New client connected: {} -> {}", src_addr, assigned_ip);

            //remove client if he doesnt send auth data
            //remove his pub ip from assigned as well
            //add his assigned address to ip pool
            tokio::spawn({
                let self_clone = Arc::clone(&self);
                let pub_ip = src_addr.clone();
                let assigned_ip = assigned_ip.clone();
                async move {
                    tokio::time::sleep(tokio::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS)).await;
                    let mut clients_lock = self_clone.priv_ip_to_client.lock().await;
                    if let Some(_) = clients_lock.get(&assigned_ip).filter(|v| v.authorized == false) {
                        clients_lock.remove(&assigned_ip);
                        self_clone.pub_to_priv_ip.lock().await.remove(&pub_ip);
                        self_clone.available_ip_addresses.push(assigned_ip).unwrap();
                        eprintln!("Handshake timeout was reached for {pub_ip}");
                    }
                    //clients_lock.remove(&client_addr);
                }
            });
        }

        //self.priv_ip_tp_client.lock().await.insert(src_addr.ip(), vpnclient);
        Ok(())
    }


    async fn handle_auth_packet(self: &Arc<Self>, enc_auth_data: &EncryptedMessage, src_addr: &SocketAddr) 
    -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        //If users sent handshake and it is still relevant
        let mut pub_to_priv_lock = self.pub_to_priv_ip.lock().await;
        if let Some(private_ip) = pub_to_priv_lock.get(&src_addr) {
            
            //If client is valid and has private ip assigned
            let mut priv_to_client_lock = self.priv_ip_to_client.lock().await;
            if let Some(client) = priv_to_client_lock.get_mut(private_ip) {
                
                //Decrypt and check login and password
                match AuthData::decrypt(enc_auth_data, &client.cipher) {
                    Ok(auth_data) => {
                        if auth_data.client_nonce != client.client_nonce || auth_data.server_nonce != client.server_nonce {
                            return Err(format!("Possible replay attack from {src_addr}, client tries to authenticate with wrong nonces").into())
                        }
                        match self.check_authdata(auth_data) {
                            Ok(_) => {
                                let tun_set_pkt = PacketType::TunnelSettings(
                                    TunnelSettingsPkt {
                                        ip_string: private_ip.to_string(),
                                        netmask_string: self.tun_netmask.to_string(),
                                        gateway_string: self.tun_ip.to_string()
                                    }.encrypt(&client.cipher)?
                                );
                                

                                self.sock_write(tun_set_pkt, *src_addr).await?;
                                client.authorized = true;
                                client.lastseen = Instant::now();

                            },
                            Err(e) => {
                                if let Some(priv_to_client) = pub_to_priv_lock.remove(&src_addr) {
                                    priv_to_client_lock.remove(&priv_to_client);
                                }
                                eprintln!("{e}")
                            },
                        }

                    },
                    Err(e) => {
                        if let Some(priv_to_client) = pub_to_priv_lock.remove(&src_addr) {
                            priv_to_client_lock.remove(&priv_to_client);
                        }
                        eprintln!("{e}");
                    }
                };
                
            } else {
                pub_to_priv_lock.remove(&src_addr);
            }
        } 
        else {
            eprintln!("Error for user address {} : Auth data sent, but user is not present it active clients", src_addr);
        }
        Ok(())
    }

    async fn handle_encrypted_packet(self: &Arc<Self>, enc_msg: &EncryptedMessage, src_addr: &SocketAddr)
    -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        if let Some(pub_to_private) = self.pub_to_priv_ip.lock().await.get(&src_addr) {
            if let Some(client) = self.priv_ip_to_client.lock().await.get_mut(pub_to_private) {
                match client.authorized {
                    true => {
                        let decrypted = self.decrypt_packet(enc_msg, &mut client.cipher)?;
                        match ip::Packet::new(&decrypted) {
                            Ok(_pkt) => {
                                let mut gro_table = GROTable::default();
                                //let mut bufs = vec![vec![0u8; 1500]; IDEAL_BATCH_SIZE];
                                let mut bufs = vec![vec![0u8; 1500]; 1]; 
                                bufs[0].extend_from_slice(&decrypted);
                                self.tun_device.send_multiple(&mut gro_table,  &mut bufs, VIRTIO_NET_HDR_LEN).await?;
                                //self.tun_write.lock().await.write_all(&decrypted).await?;
                                client.lastseen = Instant::now();
                                return Ok(())
                            }
                            Err(e) => {
                                eprintln!("PKT ERROR");
                                return Err(Box::new(e));
                            }
                        }
                    },
                    false => {
                        eprintln!("User {} is not authorized", src_addr);
                        return Err(format!("User {} is not authorized", src_addr).into());
                    },
                }
            }
            eprintln!("Client {} private address is not assigned", src_addr);
            return Err(format!("Client {} private address is not assigned", src_addr).into());
        }
        eprintln!("Client {} is not in active users", src_addr);
        return Err(format!("Client {} is not in active users", src_addr).into());
    }

    async fn handle_packet(self: &Arc<Self>, pkt: &PacketType, src_addr: &SocketAddr) 
    -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        match pkt {
            PacketType::Handshake(dhkey_packet) => {
                self.handle_handshake(dhkey_packet, src_addr).await?;
            },
            PacketType::AuthPacket(enc_auth_data) => {
                self.handle_auth_packet(enc_auth_data, src_addr).await?;
            },
            PacketType::EncryptedPkt(encrypted_message) => {
                self.handle_encrypted_packet(encrypted_message, src_addr).await?;
            },
            _ => {
                eprintln!("Unknown packet type from {}", src_addr);
            }
        }
        Ok(())
    }

    async fn handle_packet_batch(self: &Arc<Self>, batch: Vec<(PacketType, SocketAddr)>, mut gro_table: &mut GROTable) 
    -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        let mut bufs = Vec::with_capacity(IDEAL_BATCH_SIZE); //vec![vec![0u8; 1500 + VIRTIO_NET_HDR_LEN]; IDEAL_BATCH_SIZE];
        let mut send_count = 0;
        for (pkt_type, src_addr) in batch.iter() {
            match pkt_type {
                PacketType::Handshake(dhkey_packet) => {
                    if let Err(e) = self.handle_handshake(dhkey_packet, src_addr).await {
                        eprintln!("Handshake error {e}");
                    }
                },
                PacketType::AuthPacket(enc_auth_data) => {
                    if let Err(e) = self.handle_auth_packet(enc_auth_data, src_addr).await {
                        eprintln!("Auth error {e}");
                    }
                },
                PacketType::EncryptedPkt(encrypted_message) => {
                    if let Some(pub_to_private) = self.pub_to_priv_ip.lock().await.get(&src_addr) {
                        if let Some(client) = self.priv_ip_to_client.lock().await.get_mut(pub_to_private) {
                            match client.authorized {
                                true => {
                                    let decrypted = match self.decrypt_packet(encrypted_message, &mut client.cipher) {
                                        Ok(bytes) => bytes,
                                        Err(e) => {
                                            eprintln!("Decryption error {e}");
                                            continue;
                                        },
                                    };

                                    if decrypted.len() < VIRTIO_NET_HDR_LEN {
                                        continue;
                                    }
                                    
                                    match ip::Packet::new(&decrypted) {
                                        Ok(_pkt) => {
                                            send_count += 1;

                                            let mut decrypted_with_header = Vec::with_capacity(VIRTIO_NET_HDR_LEN + decrypted.len());
                                            decrypted_with_header.resize( VIRTIO_NET_HDR_LEN, 0u8);
                                            decrypted_with_header.extend_from_slice(&decrypted);
                                            
                                            bufs.push(decrypted_with_header);
                                            //self.tun_write.lock().await.write_all(&decrypted).await?;
                                            client.lastseen = Instant::now();
                                        }
                                        Err(e) => {
                                            eprintln!("Packet error {e}");
                                            continue;
                                        }
                                    }
                                },
                                false => {
                                    eprintln!("User {} is not authorized", src_addr);
                                    continue;
                                },
                            }
                        }
                        else {
                            eprintln!("Client {} private address is not assigned", src_addr);
                            continue;
                        }
                    }
                    else { 
                        eprintln!("Client {} is not in active users", src_addr);
                        continue;
                    }
                },
                _ => {
                    eprintln!("Unknown packet type from {}", src_addr);
                }
            }
        }
        if send_count > 0 {
            self.tun_device.send_multiple(&mut gro_table,  &mut bufs[..send_count], VIRTIO_NET_HDR_LEN).await?;
        }
        Ok(())
    }

    async fn user_cleaup_task(self: &Arc<Self>) {
        let mut interval = tokio::time::interval(USER_CLEANUP_INTERVAL);
        loop {
            interval.tick().await;

            let removed: HashMap<IpAddr, VPNClient> = self.priv_ip_to_client.lock().await.extract_if(|_, client| {
                Instant::now() - client.lastseen > USER_TIMEOUT_DURATION
            }).collect();

            for (_, client) in removed {
                self.pub_to_priv_ip.lock().await.remove(&client.public_ip);
                println!("User {} disconnected", client.public_ip);
            }
        }
    }

    pub async fn run(self : &Arc<Self>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        
        tokio::spawn({
            let me = Arc::clone(&self);
            async move {
                me.user_cleaup_task().await;
            }
        });
        
        tokio::spawn({
            let me = self.clone();
            async move {
                me.tun_read_loop().await
            }
        });

        let (packet_tx, mut packet_rx) = mpsc::channel::<(PacketType, SocketAddr)>(100000);
        tokio::spawn({
            let me = Arc::clone(&self);
            async move {
                // while let Some((pkt, src_addr)) = packet_rx.recv().await {
                //      if let Err(e) = me.handle_packet(&pkt, &src_addr).await {
                //             eprintln!("{e}");
                //     }
                // }
                let mut gro_table = GROTable::default();
                loop {
                    let mut packet_buffer: Vec<(PacketType, SocketAddr)> = Vec::with_capacity(IDEAL_BATCH_SIZE * 4);
                    packet_rx.recv_many(&mut packet_buffer,IDEAL_BATCH_SIZE).await;

                    if let Err(e) = me.handle_packet_batch(packet_buffer, &mut gro_table).await {
                        eprintln!("Batch processing error {e}");
                        break;
                    }
                    
                }
            }
        });


        //prepare recvmmsg
        let mut msghdrs: [mmsghdr; MAX_DATAGRAMS] = unsafe { std::mem::zeroed() };
        let mut iovs: [iovec; MAX_DATAGRAMS] = unsafe { std::mem::zeroed() };
        let mut addrs: [sockaddr_in; MAX_DATAGRAMS] = unsafe { std::mem::zeroed() };
        let addr_lens: [socklen_t; MAX_DATAGRAMS] = [std::mem::size_of::<sockaddr_in>() as socklen_t; MAX_DATAGRAMS];
        
        // Allocate buffers for received data
        let mut bufs = vec![vec![0u8; 1500]; MAX_DATAGRAMS];

        for i in 0..MAX_DATAGRAMS {
            iovs[i] = iovec {
                iov_base: bufs[i].as_mut_ptr() as *mut libc::c_void,
                iov_len: 1500,
            };

            msghdrs[i] = mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: &mut addrs[i] as *mut _ as *mut libc::c_void,
                    msg_namelen: addr_lens[i],
                    msg_iov: &mut iovs[i],
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            };
        }


        println!("Listening...");
        //let mut udp_buffer = vec![0u8; 65536];
        'outer: loop {
            let mut guard = self.udpsocket_fd.readable().await?;

            let result = unsafe {
                libc::recvmmsg(
                    guard.get_inner().as_raw_fd(),
                    msghdrs.as_mut_ptr(),
                    MAX_DATAGRAMS as u32,
                    libc::MSG_DONTWAIT, // No flags
                    std::ptr::null_mut(), // No timeout
                )
            };

            if result < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    // No data available, continue
                    guard.clear_ready();
                    tokio::task::yield_now().await;
                    continue;
                } else {
                    eprintln!("recvmmsg error: {}", err);
                    break;
                }
            }
            let num_received = result as usize;


            for i in 0..num_received {
                let len = msghdrs[i].msg_len as usize;
                if len > 0 {
                    // Convert the source address to a SocketAddr
                    let src_addr = unsafe {
                        let sockaddr_in = &*(&addrs[i] as *const _ as *const libc::sockaddr_in);
                        std::net::SocketAddrV4::new(
                            std::net::Ipv4Addr::from(sockaddr_in.sin_addr.s_addr.to_ne_bytes()),
                            u16::from_be(sockaddr_in.sin_port),
                        )
                    };
                    let src_addr = SocketAddr::V4(src_addr);

                    
                    // Copy the received data
                    // let mut data = vec![0u8; len];
                    // data.copy_from_slice(&bufs[i][0..len]);

                    let pkt: PacketType = match bincode::decode_from_slice(&bufs[i][..len], bincode::config::standard()){
                        Ok(r) => r.0,
                        Err(e) => {
                            eprintln!("Failed to deserialize packet {e}");
                            continue;
                        }
                    };
                    
                    // Send to processing channel
                    if let Err(e) = packet_tx.send((pkt, src_addr)).await {
                        eprintln!("Failed to send to processing channel: {}", e);
                        break 'outer;
                    }
                }
            }
            guard.clear_ready();
            tokio::task::yield_now().await
        }
        
        Ok(())
    }
        
}


 fn get_packet_info(data: &[u8]) -> Option<(usize, IpAddr)> {
        let pkt_version = data[0] >> 4;

        match pkt_version {
            4 => {
                let total_length = u16::from_be_bytes([data[2], data[3]]) as usize;

                let dest_addr = std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19]);
                let dest_addr = IpAddr::V4(dest_addr);
                Some((total_length, dest_addr))
            },
            6 => {
                let payload_length = u16::from_be_bytes([data[4], data[5]]) as usize;

                let total_length = 40 + payload_length;

                let mut dest_addr_bytes = [0u8; 16];
                dest_addr_bytes.copy_from_slice(&data[24..40]);
                let dest_addr = std::net::Ipv6Addr::from(dest_addr_bytes);
                let dest_addr = IpAddr::V6(dest_addr);
                Some((total_length, dest_addr))
            },
            _ => None
        }
    }