use std::os::fd::AsRawFd;
use std::{collections::HashMap, net::{IpAddr, Ipv4Addr, SocketAddr}, path::Path, str::FromStr, sync::Arc, usize};

use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

use crossbeam_queue::ArrayQueue;
use dashmap::DashMap;

use libc::{iovec, mmsghdr, sockaddr_in, sockaddr_storage, socklen_t};
use rand::{Rng};

use tokio::io::unix::AsyncFd;
use tokio::{io::{AsyncBufReadExt}, time::Instant};
use flume::{bounded, Receiver, Sender};

use tun_rs::{AsyncDevice, DeviceBuilder, ExpandBuffer, GROTable, IDEAL_BATCH_SIZE};

use tokio::io::{BufReader};

use x25519_dalek::PublicKey;
use ed25519_dalek::{ed25519::signature::Signer, SigningKey};

use tokio::fs::File;
use crate::bufferpool::{BufferHandle, BytesPool};
use crate::client::VPNClient;
use crate::messages::constants::ENCRYPTED_PACKET_HEADER_SIZE;
use crate::messages::{
    traits::{Decryptable, Encryptable}, 
    authdata::{AuthPacket, AuthPacketEncrypted}, 
    handshake::HandshakePacket,
    handshake_response::HandshakeResponsePacket,
    tunnel_settings::TunnelSettingsPacket,
    encrypted::{EncryptedPacket},
    decrypted::{DecryptedPacket},
    constants::{PKT_TYPE_HANDSHAKE, PKT_TYPE_AUTH, PKT_TYPE_ENCRYPTED_PKT}
};

use crate::socket_wrapper::CustomUdpSocket;
use crate::{diffie_hellman::generate_keypair, key_management::load_signing_key};
use std::thread::available_parallelism;

const HANDSHAKE_TIMEOUT_SECS: u64 = 5;
const MAX_DATAGRAMS : usize = 128;
const USER_CLEANUP_INTERVAL: tokio::time::Duration = tokio::time::Duration::from_secs(5);
const USER_TIMEOUT_DURATION: tokio::time::Duration = tokio::time::Duration::from_secs(10);

const BUFFER_POOL_SIZE: usize = 4096;
const BUFFER_POOL_BUFFER_SIZE: usize = 2048;

const TUN_WRITE_MAX_BATCH_SIZE: usize = 32;

const BATCH_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_micros(500);

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
    bufferpool: Arc<BytesPool>,
    available_ip_addresses: ArrayQueue<Ipv4Addr>,
    pub_to_priv_ip: DashMap<SocketAddr, Ipv4Addr>,
    priv_ip_to_client: DashMap<Ipv4Addr, VPNClient>,
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
        let available_ip_addresses = ArrayQueue::<Ipv4Addr>::new(address_count as usize);
        for i in 1..address_count {
            let new_ip_addr = Ipv4Addr::from_bits(tun_network.to_bits() + i);
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
            bufferpool: Arc::new(BytesPool::new(BUFFER_POOL_SIZE, BUFFER_POOL_BUFFER_SIZE)),
            available_ip_addresses,
            pub_to_priv_ip: DashMap::new(),
            priv_ip_to_client: DashMap::new()
        })
    }


    
    //TODO 
    fn sock_write_batch(
        self: &Arc<Self>,
        batch: &[(EncryptedPacket, SocketAddr)]
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

        let mut msghdrs = [unsafe { std::mem::zeroed::<mmsghdr>() }; MAX_DATAGRAMS];
        let mut iovs = [unsafe { std::mem::zeroed::<iovec>() }; MAX_DATAGRAMS];
        let mut addrs = [unsafe { std::mem::zeroed::<sockaddr_storage>() }; MAX_DATAGRAMS];
        let mut addr_lens = [0u32; MAX_DATAGRAMS];
        
        // let msghdrs_ptr = msghdrs.as_mut_ptr() as *mut mmsghdr;
        // let iovs_ptr = iovs.as_mut_ptr() as *mut iovec;
        // let addrs_ptr = addrs.as_mut_ptr() as *mut sockaddr_storage;

        // let mut msghdrs: [mmsghdr; MAX_DATAGRAMS] = unsafe { std::mem::zeroed() };
        // let mut iovs: [iovec; MAX_DATAGRAMS] = unsafe { std::mem::zeroed() };
        //let mut addr_lens: [socklen_t; MAX_DATAGRAMS] = [std::mem::size_of::<sockaddr_in>() as socklen_t; MAX_DATAGRAMS];

        for (i, (encrypted_handle, sockaddr)) in batch.iter().enumerate() {
            iovs[i] = iovec {
                iov_base: encrypted_handle.data().as_ptr() as *mut libc::c_void,
                iov_len: encrypted_handle.data().len(),
            };
  
            match sockaddr {
                SocketAddr::V4(addr_v4) => {
                    let sockaddr_in = libc::sockaddr_in {
                        sin_family: libc::AF_INET as u16,
                        sin_port: addr_v4.port().to_be(),
                        sin_addr: libc::in_addr {
                            s_addr: u32::from_be_bytes(addr_v4.ip().octets()),
                        },
                        sin_zero: [0; 8],
                    };
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            &sockaddr_in as *const _ as *const u8,
                            &mut addrs[i] as *mut _ as *mut u8,
                            std::mem::size_of::<libc::sockaddr_in>()
                        );
                    }
                    addr_lens[i] = std::mem::size_of::<libc::sockaddr_in>() as u32;
                }
                SocketAddr::V6(addr_v6) => {
                    let sockaddr_in6 = libc::sockaddr_in6 {
                        sin6_family: libc::AF_INET6 as u16,
                        sin6_port: addr_v6.port().to_be(),
                        sin6_flowinfo: addr_v6.flowinfo(),
                        sin6_addr: libc::in6_addr {
                            s6_addr: addr_v6.ip().octets(),
                        },
                        sin6_scope_id: addr_v6.scope_id(),
                    };
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            &sockaddr_in6 as *const _ as *const u8,
                            &mut addrs[i] as *mut _ as *mut u8,
                            std::mem::size_of::<libc::sockaddr_in6>()
                        );
                    }
                    addr_lens[i] = std::mem::size_of::<libc::sockaddr_in6>() as u32;
                }
            }
           
            msghdrs[i] = libc::mmsghdr {
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

        //let mut msghdrs_init = unsafe { msghdrs.assume_init() };

        let result = unsafe { 
            libc::sendmmsg(
                self.udpsocket_fd.as_raw_fd(), 
                msghdrs.as_mut_ptr(), 
                batch.len() as u32, 
                libc::MSG_DONTWAIT) 
        };

        if result as usize == batch.len() {
            Ok(())
        } else if result < 0 {
            Err(std::io::Error::last_os_error().into())
        } else {
            // Частичная отправка
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Partial send: {}/{} packets", result, batch.len())
            ).into())
        }
    }

    async fn sock_write(
        self: &Arc<Self>,
        data: &[u8],
        dst_addr: &SocketAddr
    )  -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        // while let Some((msg, addr)) = consumer.recv().await {
        //     let bytes = bincode::encode_to_vec(msg, bincode::config::standard())?;
        //     write.send_to(&bytes, addr).await?;
        // }
        // Ok(())
        //let guard = self.udpsocket_fd.writable().await?;

        self.udpsocket_fd.get_ref().send_to(&data, *dst_addr)?;
        Ok(())
    }


    async fn tun_read_task(
        self: Arc<Self>,
        to_encryption_tx: Sender<DecryptedPacket>
    )
    {
        // let mut original_buffer = vec![0; VIRTIO_NET_HDR_LEN + 65535];
        // let mut bufs = vec![vec![0u8; 1500]; IDEAL_BATCH_SIZE];
        // let mut sizes = vec![0; IDEAL_BATCH_SIZE];

        let mut original_buffer = [0u8; 65535 + 10];
        // Используем буферы из пула
        let mut decrypted_buffer_handles: Vec<DecryptedPacket> = Vec::with_capacity(IDEAL_BATCH_SIZE);
        //let mut bufs: Vec<&mut [u8]> = Vec::with_capacity(32);
        let mut sizes = vec![0; IDEAL_BATCH_SIZE];
        
        // Заранее выделяем буферы из пула
        
        println!("tun_read_task started");
        loop {
            decrypted_buffer_handles.clear();
            for _ in 0..IDEAL_BATCH_SIZE {
                if let Some(handle) = self.bufferpool.acquire() {
                    //handle.buf_resize(handle.buf_capacity(), 0);
                    let mut dec_buf_handle = DecryptedPacket::new(handle);
                    dec_buf_handle.buf_resize(dec_buf_handle.buf_capacity(), 0);
                    
                    decrypted_buffer_handles.push(dec_buf_handle);
                } else {
                    break;
                }
            }

            if decrypted_buffer_handles.is_empty() {
                tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
                continue;
            }

            match self.tun_device.recv_multiple(&mut original_buffer, &mut decrypted_buffer_handles, &mut sizes, ENCRYPTED_PACKET_HEADER_SIZE).await {
                Ok(read_count) => {
                    if read_count == 0 {
                        continue;
                    }

                    for (i, mut used_handle) in decrypted_buffer_handles.drain(0..read_count).enumerate() {
                        let size_with_header = sizes[i] + ENCRYPTED_PACKET_HEADER_SIZE;
                        
                        used_handle.buf_resize(size_with_header, 0);
                        if let Err(e) = to_encryption_tx.send_async(used_handle).await {
                            eprintln!("Failed to send to encryption channel: {}", e);
                            break;
                            // Оставшиеся в buffer_handles буферы вернутся в пул через drop
                        }
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    break;
                },
            }
        }
        println!("tun read task finished...");
    }

    

    async fn encryption_worker(
        self: Arc<Self>,
        to_encrypt_rx: Receiver<DecryptedPacket>,
    ) {

        let mut send_batch = Vec::with_capacity(IDEAL_BATCH_SIZE);
        //let mut bufs: Vec<&mut BytesMut> = Vec::with_capacity(MAX_DATAGRAMS);
        let mut packet_count = 0;

        println!("encryption worker started");
        loop {
            tokio::select! {
                // Получаем пакет из канала
                item = to_encrypt_rx.recv_async() => {
                    match item {
                        Ok(decrypted_handle) => {
                            let start = tokio::time::Instant::now();

                            if let Some((_, destination)) = get_packet_info(&decrypted_handle.data()[ENCRYPTED_PACKET_HEADER_SIZE..]) {
                                if let Some(client) = self.priv_ip_to_client.get(&destination) {
                                    match decrypted_handle.encrypt(&client.cipher) {
                                        Ok(enc) => {
                                            send_batch.push((enc, client.public_ip));
                                            packet_count += 1;
                                        },
                                        Err(e) => {
                                            eprintln!("Encrypt failed: {}", e);
                                            continue;
                                        },
                                    };
                                    let encrypt_time = start.elapsed();
                                    if encrypt_time > tokio::time::Duration::from_millis(1) {
                                        eprintln!("Slow encryption: {:?}", encrypt_time);
                                    }

   
                                    if packet_count >= MAX_DATAGRAMS {
                                        if let Err(e) = self.sock_write_batch(
                                            &mut send_batch[..packet_count]
                                        ) {
                                            eprintln!("Failed to send batch to sock: {}", e);
                                            break;
                                        }

                                        packet_count = 0;
                                        send_batch.clear();
                                    }
                                    //self.sock_write(PacketType::EncryptedPkt(encrypted_pkt), client.public_ip).await?;
                                } else {
                                    eprintln!("Failed to get client by destination address {}", destination);
                                    continue;
                                }
                            } else {
                                eprintln!("Failed to get destination address from packet");
                                continue;
                            }
                        },
                        Err(_) => {
                            break;
                        },
                    }

                }
                // Таймаут для отправки частичного батча
                _ = tokio::time::sleep(BATCH_TIMEOUT) => {
                    if packet_count > 0 {

                        
                        for (buf, addr) in send_batch[..packet_count].iter() {
                            if let Err(e) = self.sock_write(buf.data(), addr ).await {
                                eprintln!("Failed to send batch to sock: {}", e);
                                break;
                            }
                        }

                        if let Err(e) = self.sock_write_batch(
                            &mut send_batch[..packet_count]
                        ) {
                            eprintln!("Failed to send batch to sock: {}", e);
                            break;
                        }
                        // for buf in &mut tun_send_bufs[0..packet_count] {
                        //     buf.clear();
                        // }
                        packet_count = 0;
                        send_batch.clear();
                    }
                }
            }
        }
        println!("encryption worker stopped...");
    }


    fn check_authdata(
        self : &Arc<Self>, 
        authdata_handle: &AuthPacket,
        prev_client_nonce: &u128,
        prev_server_nonce: &u128
    ) 
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> 
    {

        let username_bytes = authdata_handle.get_username_bytes();
        let username = match std::str::from_utf8(username_bytes) {
            Ok(s) => s,
            Err(e) => {
                return Err(format!("Failed to transform username bytes to utf8: {e}").into());
            }
        };

        let password_bytes = authdata_handle.get_password_bytes();

        let password_hex = hex::encode(password_bytes);

        let client_nonce: u128 = {
            let bytes: [u8; 16] = authdata_handle.get_client_nonce_bytes().try_into().unwrap();
            u128::from_be_bytes(bytes)
        };

        let server_nonce: u128 = {
            let bytes: [u8; 16] = authdata_handle.get_server_nonce_bytes().try_into().unwrap();
            u128::from_be_bytes(bytes)
        };
    
        if client_nonce != *prev_client_nonce || server_nonce != *prev_server_nonce {
            return Err("Nonces are invalid".into())
        }

        if let Some(password_hash) = self.credentials.get(username) {
            if password_hex == *password_hash {
                return Ok(())
            } else {
                return Err("Wrong Credentials".into())
            }
        } else {
            return Err("User data not found".into())
        }
    }

    fn get_available_ip(self: &Arc<Self>) 
    -> Option<Ipv4Addr>
    {
        //let mut ip_pool_lock = self.available_ip_addresses.lock().await;
        self.available_ip_addresses.pop()
    }



    async fn handshake_worker(self: Arc<Self>, handshake_rx: Receiver::<(HandshakePacket, SocketAddr)>) 
    {
        let mut sized_key_array: [u8; 32] = [0u8; 32];
        let mut client_nonce_array: [u8; 16] = [0u8; 16];

        println!("handshake_worker started");
        while let Ok((handshake_handle, src_addr)) = handshake_rx.recv_async().await {
            if let Some(_) = self.pub_to_priv_ip.get(&src_addr) {
                eprintln!("User {} is already connected", src_addr);
                continue;
            }
            //Parse handshake buffer
            sized_key_array.copy_from_slice(handshake_handle.get_key_bytes());
            client_nonce_array.copy_from_slice(handshake_handle.get_client_nonce_bytes());

            let client_nonce = u128::from_be_bytes(client_nonce_array);

            //2. generate shared key and fill response buffer
            let other_pubkey = PublicKey::from(sized_key_array);
            let (secret, public) = generate_keypair();
            let shared_key = secret.diffie_hellman(&other_pubkey);


            let cipher = ChaCha20Poly1305::new(shared_key.as_bytes().into());

            let server_nonce: u128 = rand::thread_rng().r#gen();

            let signature = self.signing_key.sign(&public.to_bytes());

            let buffer_handle = handshake_handle.clear_release();
            let handshake_resp_handle = HandshakeResponsePacket::new(
                buffer_handle,
                public, 
                server_nonce,
                signature
            );

            //3. find available tunnel ip
            let assigned_ip = match self.get_available_ip() {
                Some(ip) => ip,
                None => {
                    eprintln!("No IP addresses available for new client");
                    continue;
                }
            };

            let vpnclient = VPNClient {
                client_nonce: client_nonce,
                server_nonce: server_nonce,
                public_ip: src_addr,
                authorized: false,
                cipher,
                lastseen: Instant::now(),
            };

            //4. Send client handshake responce
            if let Err(e) = self.sock_write(&handshake_resp_handle.data(), &src_addr).await {
                eprintln!("Failed to send handshake responce to {}: {}", src_addr, e);
                continue;
            }

            self.pub_to_priv_ip.insert(src_addr, assigned_ip);
            self.priv_ip_to_client.insert(assigned_ip, vpnclient);

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
                    
                    if let Some(_) = self_clone.priv_ip_to_client.get(&assigned_ip).filter(|v| v.authorized == false) {
                        self_clone.priv_ip_to_client.remove(&assigned_ip);
                        self_clone.pub_to_priv_ip.remove(&pub_ip);
                        self_clone.available_ip_addresses.push(assigned_ip).unwrap();
                        eprintln!("Handshake timeout was reached for {pub_ip}");
                    }
                    //clients_lock.remove(&client_addr);
                }
            });
        }

        println!("handshake worker stopped...");
        //self.priv_ip_tp_client.lock().await.insert(src_addr.ip(), vpnclient);
    }


    async fn authentication_worker(self: Arc<Self>, authdata_rx: Receiver::<(AuthPacketEncrypted, SocketAddr)>)
    {
        println!("authentication_worker started");
        while let Ok((authdata_handle, src_addr)) = authdata_rx.recv_async().await {
            let private_ip_opt = self.pub_to_priv_ip.get(&src_addr);
            if let None = private_ip_opt {
                eprintln!("Error for user address {} : Auth data sent, but user is not present it active clients", src_addr);
                continue;
            }
            let private_ip = private_ip_opt.unwrap();

            let client_opt = self.priv_ip_to_client.get_mut(&private_ip);
            if let None = client_opt {
                self.pub_to_priv_ip.remove(&src_addr);
                eprintln!("Public ip {} is presend, but client does not exist", src_addr);
                continue;
            }
            let mut client = client_opt.unwrap();
            
            let decrypted_auth_handle = match authdata_handle.decrypt(&client.cipher) {
                Ok(dec) => dec,
                Err(e) => {
                    eprintln!("Failed to decrypt auth data: {e}");
                    if let Some((_, priv_to_client)) = self.pub_to_priv_ip.remove(&src_addr) {
                        self.priv_ip_to_client.remove(&priv_to_client);
                    }
                    continue;
                },
            };
            match self.check_authdata(&decrypted_auth_handle, &client.client_nonce, &client.server_nonce) {
                Ok(_) => {
                    let buffer_handle = decrypted_auth_handle.clear_release();
                    let tunnel_settings_handle = TunnelSettingsPacket::new(
                        buffer_handle,
                        private_ip.to_bits(),
                        self.tun_netmask.to_bits(),
                        self.tun_ip.to_bits()
                    );

                    let tunnel_settings_encrypted = match tunnel_settings_handle.encrypt(&client.cipher) {
                        Ok(enc) => enc,
                        Err(e) => {
                            eprintln!("Failed to encrypt tunnel settings: {e}");
                            continue;
                        },
                    };

                    if self.sock_write(&tunnel_settings_encrypted.data(), &src_addr).await.is_err() {
                        eprintln!("Failed to send tunnel settings to client: {}", src_addr);
                        break;
                    }
                    client.authorized = true;
                    client.lastseen = Instant::now();

                },
                Err(e) => {
                    if let Some((_, priv_to_client)) = self.pub_to_priv_ip.remove(&src_addr) {
                        self.priv_ip_to_client.remove(&priv_to_client);
                    }
                    eprintln!("{e}")
                },
            }
        }
        println!("authentication worker stopped...");
    }


    fn get_client_by_public_ip(self: &Arc<Self>, public_ip: &SocketAddr) -> Option<dashmap::mapref::one::RefMut<'_, Ipv4Addr, VPNClient>> {
        let pub_to_priv_opt = self.pub_to_priv_ip.get(public_ip);
        if let None = pub_to_priv_opt {
            eprintln!("Client {} is not in active users", public_ip);
            return None;
        }
        let pub_to_priv = pub_to_priv_opt.unwrap();

        let client_opt = self.priv_ip_to_client.get_mut(&pub_to_priv);
        if let None = client_opt {
            eprintln!("Client {} private address is not assigned", public_ip);
            return None;
        }
        client_opt
    }



    async fn user_cleaup_task(self: &Arc<Self>) {
        let mut interval = tokio::time::interval(USER_CLEANUP_INTERVAL);
        loop {
            interval.tick().await;

            let now = Instant::now();
            self.priv_ip_to_client.retain(|_priv_ip, client| {
                if now - client.lastseen > USER_TIMEOUT_DURATION {
                    self.pub_to_priv_ip.remove(&client.public_ip);
                    println!("User {} disconnected", client.public_ip);
                    false
                } else {
                    true
                }
            });
        }
    }


    async fn sock_read_task(
        self: &Arc<Self>,
        //udp_socket: &CustomUdpSocket,
        handshake_tx: Sender<(HandshakePacket, SocketAddr)>,
        authdata_tx: Sender<(AuthPacketEncrypted, SocketAddr)>,
        decryption_tx: Sender<(EncryptedPacket, SocketAddr)>
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut msghdrs: [mmsghdr; MAX_DATAGRAMS] = unsafe { std::mem::zeroed() };
        let mut iovs: [iovec; MAX_DATAGRAMS] = unsafe { std::mem::zeroed() };
        let mut addrs: [sockaddr_in; MAX_DATAGRAMS] = unsafe { std::mem::zeroed() };
        let addr_lens: [socklen_t; MAX_DATAGRAMS] = [std::mem::size_of::<sockaddr_in>() as socklen_t; MAX_DATAGRAMS];
        
        let mut buffer_handles: Vec<Option<BufferHandle>> = Vec::with_capacity(MAX_DATAGRAMS);

        println!("sock_read_task started");
        let task_result: Result<(), Box<dyn std::error::Error + Send + Sync>> = 'task: loop {
            // 1. Получаю буфферы
            buffer_handles.clear();
            for _ in 0..MAX_DATAGRAMS {
                if let Some(handle) = self.bufferpool.acquire() {
                    buffer_handles.push(Some(handle));
                } else {
                    break;
                }
            }

            if buffer_handles.is_empty() {
                tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
                continue;
            }

            // 2. Set up iovecs
            for (i, handle_opt) in buffer_handles.iter_mut().enumerate() {
                if let Some(handle) = handle_opt {
                    let buf = handle.data_mut();

                    let ptr = buf.as_mut_ptr() as *mut libc::c_void;
                    let capacity = buf.capacity();

                    iovs[i] = iovec { 
                        iov_base: ptr, 
                        iov_len: capacity 
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
                        msg_len: 0 
                    }
                }
            }

          
            // 3 read packets
            let num_recieved = unsafe {
                let recieve_count = libc::recvmmsg(
                    self.udpsocket_fd.as_raw_fd(),
                    msghdrs.as_mut_ptr(),
                    buffer_handles.len() as u32,
                    libc::MSG_DONTWAIT,
                    std::ptr::null_mut()
                );

                if recieve_count < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        0
                    } else {
                        eprintln!("recvmmsg error: {}", err);
                        for handle_opt in buffer_handles.drain(..) {
                            if let Some(handle) = handle_opt {
                                drop(handle);
                            }
                        }
                        continue;
                    }
                } else {
                    recieve_count as usize
                }
            };

            //4 Process packets
            for i in 0..num_recieved {
                let len = msghdrs[i].msg_len as usize;
                if len == 0 {
                    continue;
                }

                let mut handle = buffer_handles[i].take().unwrap();

                unsafe {
                    handle.set_len(len);
                }

                let src_addr = unsafe {
                    let sockaddr_in = &*(&addrs[i] as *const _ as *const libc::sockaddr_in);
                    std::net::SocketAddrV4::new(
                        std::net::Ipv4Addr::from(sockaddr_in.sin_addr.s_addr.to_ne_bytes()),
                        u16::from_be(sockaddr_in.sin_port),
                    ).into()
                };
            
                

                match handle.data()[0] {
                    PKT_TYPE_HANDSHAKE => {
                        if HandshakePacket::is_valid_buffer_size(len) {
                            let handshake_pkt = HandshakePacket::from_recieved(handle);
                            if let Err(e) = handshake_tx.send_async((handshake_pkt, src_addr)).await {
                                eprintln!("Failed to send to handshake channel: {}", e);
                                break 'task Err(format!("Failed to send to handshake channel: {}", e).into())
                            }
                        }

                    },
                    PKT_TYPE_AUTH => {
                        if AuthPacketEncrypted::is_valid_buffer_size(&handle) {
                            let auth_pkt_enc = AuthPacketEncrypted::new(handle);
                            if let Err(e) = authdata_tx.send_async((auth_pkt_enc, src_addr)).await {
                                eprintln!("Failed to send to authdata channel: {}", e);
                                break 'task Err(format!("Failed to send to authdata channel: {}", e).into())
                            }
                        }
                    },
                    PKT_TYPE_ENCRYPTED_PKT => {
                        if EncryptedPacket::is_valid_buffer_size(&handle) {
                            let encrypted_pkt = EncryptedPacket::new(handle);
                            if let Err(e) = decryption_tx.send_async((encrypted_pkt, src_addr)).await {
                                eprintln!("Failed to send to decryption channel: {}", e);
                                break 'task Err(format!("Failed to send to decryption channel: {}", e).into())
                            }
                        }
                    },
                    _ => {
                        eprintln!("Unknown packet type: {}", handle.data()[0]);
                    }
                }
   
            }

            //return unused buffer to pool
            for handle_opt in buffer_handles.drain(..) {
                if let Some(handle) = handle_opt {
                    drop(handle);
                }
            }

            if num_recieved == 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
            }
        };
        println!("sock_read_task finished");
        task_result
    }

    async fn decryption_worker(
        self: Arc<Self>, 
        to_decrypt_rx: Receiver<(EncryptedPacket, SocketAddr)>
    ) {
        let mut gro_table = GROTable::default();
        let mut tun_send_bufs = Vec::<DecryptedPacket>::with_capacity(TUN_WRITE_MAX_BATCH_SIZE);
        let mut packet_count = 0;

        //let (tx, mut rx_decrypted) = mpsc::channel::<(BufferHandle, SocketAddr)>(32);

        loop {
            tokio::select! {
                // Получаем пакет из канала
                item = to_decrypt_rx.recv_async() => {
                    match item {
                        Ok((encrypted_handle, src_addr)) => {
                            let start = tokio::time::Instant::now();

                            let mut client = match self.get_client_by_public_ip(&src_addr) {
                                Some(client) => {
                                    client
                                },
                                None => {
                                    continue;
                                }
                            };
                            
                            let decrypted_handle = match client.authorized {
                                true => {
                                    match encrypted_handle.decrypt(&client.cipher) {
                                        Ok(dec) => {
                                            client.lastseen = Instant::now();
                                            dec
                                        },
                                        Err(e) => {
                                            eprintln!("Failed to encrypt packet: {e}");
                                            continue;
                                        },
                                    }
                                },
                                false => {
                                    eprintln!("user {} is not authorized", client.public_ip);
                                    continue;
                                },
                            };
                          
                            let encrypt_time = start.elapsed();
                                if encrypt_time > tokio::time::Duration::from_millis(1) {
                                    eprintln!("Slow encryption: {:?}", encrypt_time);
                                }
                                
                                tun_send_bufs.push(decrypted_handle);
                                packet_count += 1;


                                if packet_count >= TUN_WRITE_MAX_BATCH_SIZE {
                                    if let Err(e) = self.tun_device.send_multiple(
                                        &mut gro_table, 
                                        &mut tun_send_bufs[0..packet_count], 
                                        ENCRYPTED_PACKET_HEADER_SIZE
                                    ).await {
                                        eprintln!("Failed to send batch to tun: {}", e);
                                    }
                                    
                                    tun_send_bufs.clear();
                                    packet_count = 0;
                                }
                            },
                        Err(_) => {
                            break;
                        },
                    }

                }
                // Таймаут для отправки частичного батча
                _ = tokio::time::sleep(BATCH_TIMEOUT) => {
                    if packet_count > 0 {
                        if let Err(e) = self.tun_device.send_multiple(
                            &mut gro_table, 
                            &mut tun_send_bufs[0..packet_count], 
                            ENCRYPTED_PACKET_HEADER_SIZE
                        ).await {
                            eprintln!("Failed to send batch to tun: {}", e);
                        }
                        tun_send_bufs.clear();
                        packet_count = 0;
                    }
                }
            }
        }
        println!("decryption worker stopped...");
    }

    pub async fn run(self : &Arc<Self>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        
        let (decryption_tx, decryption_rx) = bounded(1024);
        let (encryption_tx, encryption_rx) = bounded(1024);
        let (handshake_tx, handshake_rx) = bounded(1024);
        let (authdata_tx, authdata_rx) = bounded(1024);
        // let (decryption_tx, decryption_rx) = tokio::sync::mpsc::channel(1024);
        // let (encryption_tx, encryption_rx) = tokio::sync::mpsc::channel(1024);
        // let (handshake_tx, handshake_rx) = tokio::sync::mpsc::channel(1024);
        // let (authdata_tx, authdata_rx) = tokio::sync::mpsc::channel(1024);

        let mut encryption_worker_count = available_parallelism().unwrap().get();
        encryption_worker_count = std::cmp::max(encryption_worker_count - 2, 1);

        for _ in 0..encryption_worker_count {
            
            tokio::spawn({
                let me = self.clone();
                let encryption_rx_clone = encryption_rx.clone();
                async move {
                    me.encryption_worker(encryption_rx_clone).await
                }
            });

            tokio::spawn({
                let decryption_rx_clone = decryption_rx.clone();
                let me = Arc::clone(&self);
                async move {
                    me.decryption_worker(decryption_rx_clone).await
                }
            });
        }

        tokio::spawn({
            let me = Arc::clone(&self);
            async move {
                me.user_cleaup_task().await;
            }
        });

        tokio::spawn({
            let me = self.clone();
            let encryption_tx_clone = encryption_tx.clone();
            async move {
                me.tun_read_task(encryption_tx_clone).await
            }
        });

        tokio::spawn({
            let me = Arc::clone(&self);
            async move {
                me.handshake_worker(handshake_rx).await
            }
        });

        tokio::spawn({
            let me = Arc::clone(&self);
            async move {
                me.authentication_worker(authdata_rx).await
            }
        });

        println!("Listening...");

        let handshake_tx_clone = handshake_tx.clone();
        let authdata_tx_clone = authdata_tx.clone();
        let decryption_tx_clone = decryption_tx.clone();
        
        let _ = self.sock_read_task(
            handshake_tx_clone,
            authdata_tx_clone,
            decryption_tx_clone
        ).await;

        println!("Exiting..");
        Ok(())
    }
        
}


 fn get_packet_info(data: &[u8]) -> Option<(usize, Ipv4Addr)> {
    let pkt_version = data[0] >> 4;

    match pkt_version {
        4 => {
            let total_length = u16::from_be_bytes([data[2], data[3]]) as usize;

            let dest_addr = std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19]);
            //let dest_addr = IpAddr::V4(dest_addr);
            
            Some((total_length, dest_addr))
        },
        // 6 => {
        //     let payload_length = u16::from_be_bytes([data[4], data[5]]) as usize;

        //     let total_length = 40 + payload_length;

        //     let mut dest_addr_bytes = [0u8; 16];
        //     dest_addr_bytes.copy_from_slice(&data[24..40]);
        //     let dest_addr = std::net::Ipv6Addr::from(dest_addr_bytes);
        //     let dest_addr = IpAddr::V6(dest_addr);
        //     Some((total_length, dest_addr))
        // },
        _ => None
    }
}
