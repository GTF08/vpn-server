use std::os::fd::AsRawFd;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{collections::HashMap, net::{IpAddr, Ipv4Addr, SocketAddr}, path::Path, str::FromStr, sync::Arc, usize};

use bytes::{Bytes, BytesMut};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

use crossbeam_queue::ArrayQueue;
use dashmap::DashMap;

use libc::{AF_INET, AF_INET6, in_addr, iovec, mmsghdr, sockaddr, sockaddr_in, sockaddr_in6, sockaddr_storage, socklen_t};
use rand::{Rng};

use tokio::io::unix::AsyncFd;
use tokio::{io::{AsyncBufReadExt}, time::Instant};
use flume::{bounded, Receiver, Sender};

use rayon::prelude::*;

use tun_rs::{AsyncDevice, DeviceBuilder, ExpandBuffer, GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

use tokio::io::{BufReader};

use x25519_dalek::PublicKey;
use ed25519_dalek::{ed25519::signature::Signer, SigningKey};

use tokio::fs::File;
use crate::bufferpool::{self, BatchBufferPool, BatchHandle};
use crate::client::VPNClient;
use crate::messages::constants::{ENCRYPTED_PACKET_HEADER_SIZE, PKT_TYPE_HANDSHAKE_RESP, PKT_TYPE_TUNNEL_SETTINGS};
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
//const USER_TIMEOUT_DURATION: tokio::time::Duration = tokio::time::Duration::from_secs(120);
const USER_TIMEOUT_SECONDS: u64 = 120;

const BUFFER_POOL_SIZE: usize = 32;
const BUFFER_POOL_BUFFER_SIZE: usize = 65535 + 10;

//const TUN_WRITE_MAX_BATCH_SIZE: usize = 32;


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
    bufferpool: BatchBufferPool,
    available_ip_addresses: ArrayQueue<in_addr>,
    pub_to_priv_ip: Arc<DashMap<(sockaddr_storage, socklen_t), in_addr>>,
    priv_ip_to_client: Arc<DashMap<in_addr, VPNClient>>,
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
        let available_ip_addresses = ArrayQueue::<in_addr>::new(address_count as usize);
        for i in 1..address_count {
            let new_ip_addr = Ipv4Addr::from_bits(tun_network.to_bits() + i);
            if new_ip_addr != IpAddr::V4(tun_ip_addr) {
                let s_addr = new_ip_addr.to_bits();
                available_ip_addresses.push(in_addr { s_addr }).unwrap();
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
            bufferpool: BatchBufferPool::new(BUFFER_POOL_SIZE, IDEAL_BATCH_SIZE, BUFFER_POOL_BUFFER_SIZE),
            available_ip_addresses,
            pub_to_priv_ip: Arc::new(DashMap::new()),
            priv_ip_to_client: Arc::new(DashMap::new())
        })
    }


    
    //TODO 
   fn sock_write_batch(
        fd: &AsyncFd<CustomUdpSocket>,
        count: usize,
        batch: &mut BatchHandle
    ) -> Result<usize, std::io::Error> {

        let mut msghdrs = [unsafe { std::mem::zeroed::<mmsghdr>() }; MAX_DATAGRAMS];
        let mut iovs = [unsafe { std::mem::zeroed::<iovec>() }; MAX_DATAGRAMS];
        // let mut addrs = [unsafe { std::mem::zeroed::<sockaddr_storage>() }; MAX_DATAGRAMS];
        // let mut addr_lens = [0u32; MAX_DATAGRAMS];

        let (addrs, buffers) = batch.inner_mut();
        let addrs = &mut addrs[..count];
        let buffers = &mut buffers[..count];

        let mut send_count = 0;
        for ((addr, addrlen), buffer) in addrs.iter_mut().zip(buffers.iter_mut()) {
            match buffer[0] {
                PKT_TYPE_ENCRYPTED_PKT => {
                    iovs[send_count] = iovec {
                        iov_base: buffer.as_ptr() as *mut libc::c_void,
                        iov_len: buffer.len(),
                    };

                    msghdrs[send_count] = libc::mmsghdr {
                        msg_hdr: libc::msghdr {
                            msg_name: addr as *mut _ as *mut libc::c_void,
                            msg_namelen: *addrlen,
                            msg_iov: &mut iovs[send_count],
                            msg_iovlen: 1,
                            msg_control: std::ptr::null_mut(),
                            msg_controllen: 0,
                            msg_flags: 0,
                        },
                        msg_len: 0,
                    };

                    send_count += 1;
                },
                _ => {}
            }
        }
        
    
        let result = unsafe { 
            libc::sendmmsg(
            fd.as_raw_fd(), 
            msghdrs.as_mut_ptr(), 
            send_count as u32, 
            libc::MSG_DONTWAIT) 
        };
        if result < 0 {
            let err = std::io::Error::last_os_error();
            Err(err)
        } else {
            Ok(result as usize)
        }
    }


    async fn sock_send_worker(
        self: Arc<Self>,
        to_sock_rx: Receiver<(usize, BatchHandle)>
    ) {
        'task: while let Ok((count, mut batch)) = to_sock_rx.recv_async().await {
            let expected_send_count = batch.inner().1[..count].iter()
                .filter(|buffer| {
                    match buffer[0] {
                        PKT_TYPE_ENCRYPTED_PKT => true,
                        _ => false
                    }
                })
                .count();
            
            let mut sent = 0;
            while sent < expected_send_count {
                //let remaining = &batch[sent..];
                //let current_batch_len = remaining.len();
                let mut guard = match self.udpsocket_fd.writable().await {
                    Ok(g) => g,
                    Err(e) => {
                        eprintln!("Error getting udp socket for write: {e}");
                        break 'task;
                    },
                };

                match guard.try_io(|inner_fd| {
                    let result = Self::sock_write_batch(inner_fd, count, &mut batch);
                    result
                }) {
                    Ok(result) => {
                        match result {
                            Ok(sent_count) => {
                                sent += sent_count;
                            },
                            Err(err) => {
                                match err.kind() {
                                    std::io::ErrorKind::WouldBlock => {
                                        continue;
                                    }
                                    std::io::ErrorKind::Interrupted => {
                                        continue;
                                    },
                                    _ => break 'task
                                }
                            },
                        }
                    },
                    Err(_would_block) => {
                        continue;
                    },
                }
            }
        }
    }
    
    // async fn sock_write(
    //     self: &Arc<Self>,
    //     data: &[u8],
    //     dst_addr: &SocketAddr
    // )  -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    // {
    //     self.udpsocket_fd.get_ref().send_to(&data, *dst_addr)?;
    //     Ok(())
    // }


    async fn tun_read_task(
        self: Arc<Self>,
        to_tun_process_tx: Sender<(usize, BatchHandle)>
    )
    {

        let mut original_buffer = [0u8; 65535 + 10];
        const HDR_START: usize = 0;
        original_buffer[HDR_START] = 1;
        
        
        //let mut decrypted_buffer_handles: Vec<BufferHandle> = Vec::with_capacity(IDEAL_BATCH_SIZE);
        let mut sizes = vec![0; IDEAL_BATCH_SIZE];
         
        println!("tun_read_task started");
        loop {
            // decrypted_buffer_handles.clear();
            // for _ in 0..IDEAL_BATCH_SIZE {
            //     if let Some(mut handle) = self.bufferpool.acquire() {
            //         //handle.buf_resize(handle.buf_capacity(), 0);
            //         //handle.data_mut().resize(handle.data().capacity(), 0);
            //         let new_capacity = handle.capacity();
            //         handle.resize(new_capacity, 0);
            //         //let mut dec_buf_handle = DecryptedPacket::new(handle);
            //         //dec_buf_handle.buf_resize(dec_buf_handle.buf_capacity(), 0);
                    
            //         decrypted_buffer_handles.push(handle);
            //     } else {
            //         break;
            //     }
            // }

            // if decrypted_buffer_handles.is_empty() {
            //     tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
            //     continue;
            // }

            if let Some(mut decrypted_batch) = self.bufferpool.acquire() {
                let (_, buffers) = decrypted_batch.inner_mut();

                // for i in 0..buffers.len() {
                //     buffers[i].resize(2048, 0);
                // }
                buffers.iter_mut().for_each(|b| {
                    b.resize(1400, 0);
                });
                match self.tun_device.recv_multiple(&mut original_buffer, buffers, &mut sizes, ENCRYPTED_PACKET_HEADER_SIZE).await {
                    Ok(read_count) => {
                        if read_count == 0 {
                            continue;
                        }

                        for (i, buffer) in buffers[0..read_count].iter_mut().enumerate() {
                            let size_with_header = sizes[i] + ENCRYPTED_PACKET_HEADER_SIZE;
                            buffer.resize(size_with_header, 0);
                        }
                        if let Err(e) = to_tun_process_tx.send_async((read_count, decrypted_batch)).await {
                            eprintln!("Failed to send to encryption channel: {}", e);
                            break;

                        }
                    },
                    Err(e) => {
                        eprintln!("Failed to read batch from tun: {e}");
                        break;
                    },
                }
            }
        }
        println!("tun read task finished...");
    }

    

    fn tun_data_worker(
        self: Arc<Self>,
        //to_encrypt_rx: Receiver<DecryptedPacket>,
        to_encrypt_rx: Receiver<(usize, BatchHandle)>,
        to_send_tx: Sender<(usize, BatchHandle)>
    ) {

        //let mut send_batch = Vec::with_capacity(IDEAL_BATCH_SIZE);
        println!("tun data processing worker started");
        while let Ok((count, mut batch)) = to_encrypt_rx.recv() {

            let (addrs, buffers) = batch.inner_mut();
            let addrs = &mut addrs[..count];
            let buffers = &mut buffers[..count];

            addrs.par_iter_mut()
                .zip(buffers.par_iter_mut())
                .for_each(|(addr, buffer)| {
                    if let Some((_, destination)) = get_packet_info(&buffer[ENCRYPTED_PACKET_HEADER_SIZE..]) {
                        if let Some(client) = self.priv_ip_to_client.get(&destination) {
                            if DecryptedPacket::encrypt_in_place(buffer, &client.cipher).is_ok() {
                                *addr = client.public_ip;
                            }
                        }
                    }
                });
            
            if to_send_tx.send((count, batch)).is_err() {
                break;
            }
        }
        println!("tun data processing worker stopped...");
    }


    
    fn check_authdata(
        self : &Arc<Self>, 
        authdata_handle: &BytesMut,
        prev_client_nonce: &u128,
        prev_server_nonce: &u128
    ) 
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> 
    {
        let username_bytes = AuthPacket::get_username_bytes(&authdata_handle);
        //let username_bytes = authdata_handle.get_username_bytes();
        let username = match std::str::from_utf8(username_bytes) {
            Ok(s) => s,
            Err(e) => {
                return Err(format!("Failed to transform username bytes to utf8: {e}").into());
            }
        };

        let password_bytes = AuthPacket::get_password_bytes(&authdata_handle);

        let password_hex = hex::encode(password_bytes);

        let client_nonce: u128 = {
            let bytes: [u8; 16] = *AuthPacket::get_client_nonce_bytes(&authdata_handle).as_array().unwrap();
            //authdata_handle.get_client_nonce_bytes().try_into().unwrap();
            u128::from_be_bytes(bytes)
        };

        let server_nonce: u128 = {
            let bytes: [u8; 16] = *AuthPacket::get_server_nonce_bytes(&authdata_handle).as_array().unwrap();
            //authdata_handle.get_server_nonce_bytes().try_into().unwrap();
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
    -> Option<in_addr>
    {
        //let mut ip_pool_lock = self.available_ip_addresses.lock().await;
        self.available_ip_addresses.pop()
    }

    async fn send_all_to_sock(
        self: &Arc<Self>,
        buffer: &BytesMut,
        addr: &sockaddr_storage,
        addrlen: &socklen_t
    ) -> Result<(), std::io::Error> {
        let mut sent_size = 0;
        while sent_size < buffer.len() {
            let mut guard = match self.udpsocket_fd.writable().await {
                Ok(g) => g,
                Err(e) => {
                    eprintln!("Error getting udp socket for write: {e}");
                    return Err(e);
                },
            };

            match guard.try_io(|fd| {
                let result = unsafe { libc::sendto(
                fd.as_raw_fd(), 
                buffer.as_ptr().add(sent_size) as * const _, 
                buffer.len(), 
                libc::MSG_DONTWAIT, 
                addr as *const sockaddr_storage as *const sockaddr,
                *addrlen
                )};
                if result > 0 {
                    Ok(result)
                } else {
                    let err = std::io::Error::last_os_error();
                    Err(err)
                }
            }) {
                Ok(result) => { 
                    match result {
                        Ok(sent) => {
                            sent_size += sent as usize;
                        },
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                continue;
                            } else {
                                return Err(e);
                            }
                        },
                    }
                },
                Err(_would_block) => { continue; },
            }
        }
        Ok(())
    }

    async fn handshake_worker(
        self: &Arc<Self>, 
        to_handshake_rx: Receiver<(BytesMut, sockaddr_storage, socklen_t)>,
    ) 
    {
        //let mut sized_key_array: [u8; 32] = [0u8; 32];
        //let mut client_nonce_array: [u8; 16] = [0u8; 16];
        println!("Handshake worker started");
        while let Ok((mut buffer, addr, addrlen)) = to_handshake_rx.recv_async().await {
            if let Some(_) = self.pub_to_priv_ip.get(&(addr, addrlen)) {
                match addr.ss_family as i32 {
                    AF_INET => unsafe {
                        let sockaddr_in = &*(&addr as *const _ as * const sockaddr_in);
                        eprintln!("User {}:{} is already connected", sockaddr_in.sin_addr.s_addr, sockaddr_in.sin_port);
                    },
                    AF_INET6 => unsafe {
                        let sockaddr_in6 = &*(&addr as *const _ as *const sockaddr_in6);
                        eprintln!("User {:?}:{} is already connected", sockaddr_in6.sin6_addr.s6_addr, sockaddr_in6.sin6_port);
                    },  
                    _  => {
                        eprintln!("Unknown address family");
                    }
                }
                continue;
            }
            //Parse handshake buffer
            let sized_key_array: [u8; 32] = *HandshakePacket::get_key_bytes(&buffer).as_array().unwrap();
            let client_nonce_array : [u8; 16] = *HandshakePacket::get_client_nonce_bytes(&buffer).as_array().unwrap();

            let client_nonce = u128::from_be_bytes(client_nonce_array);

            //2. generate shared key and fill response buffer
            let other_pubkey = PublicKey::from(sized_key_array);
            let (secret, public) = generate_keypair();
            let shared_key = secret.diffie_hellman(&other_pubkey);


            let cipher = ChaCha20Poly1305::new(shared_key.as_bytes().into());

            let server_nonce: u128 = rand::thread_rng().r#gen();

            let signature = self.signing_key.sign(&public.to_bytes());

            //let buffer_handle = handshake_handle.clear_release();
            //Just renaming, it will get overridden internally by HandshakeResponsePacket::new()
           // let buffer_handle = buffer;
            HandshakeResponsePacket::new(
                &mut buffer,
                public, 
                server_nonce,
                signature
            );
            //let handshake_resp_handle = buffer_handle;

            //3. find available tunnel ip
            let assigned_ip = match self.get_available_ip() {
                Some(ip) => ip,
                None => {
                    eprintln!("No IP addresses available for new client");
                    continue;
                }
            };

            
            
           if let Err(e) = self.send_all_to_sock(&buffer, &addr, &addrlen).await {
                eprintln!("Failed to send handshake to client");
                continue;
           }

            let vpnclient = VPNClient::new(client_nonce, server_nonce, (addr, addrlen), cipher);
            // let vpnclient = VPNClient {
            //     client_nonce: client_nonce,
            //     server_nonce: server_nonce,
            //     public_ip: src_addr,
            //     authorized: false,
            //     cipher,
            //     lastseen: Instant::now(),
            // };

            self.pub_to_priv_ip.insert((addr, addrlen), assigned_ip);
            self.priv_ip_to_client.insert(assigned_ip, vpnclient);


            match addr.ss_family as i32 {
                AF_INET => unsafe {
                    let sockaddr_in = &*(&addr as *const _ as * const sockaddr_in);
                    println!("New client connected: {}:{} -> {}", sockaddr_in.sin_addr.s_addr, sockaddr_in.sin_port, assigned_ip.s_addr);
                },
                AF_INET6 => unsafe {
                    let sockaddr_in6 = &*(&addr as *const _ as *const sockaddr_in6);
                    println!("New client connected: {:?}:{} -> {}", sockaddr_in6.sin6_addr.s6_addr, sockaddr_in6.sin6_port, assigned_ip.s_addr);
                },  
                _  => {
                    eprintln!("Unknown address family");
                }
            }

        }

        println!("Handshake worker stopped...");
    }


    ///Must take Encrypted Auth Packet VIA Channel
    async fn auth_worker(
        self: &Arc<Self>, 
        to_auth_rx: Receiver<(BytesMut, sockaddr_storage, socklen_t)>
    )
    {
        //while let Ok((mut authdata_handle, src_addr)) = encrypted_authpkt_rx.recv_async().await {
        println!("Auth worker started");
        while let Ok((mut buffer, addr, addrlen)) = to_auth_rx.recv_async().await {
            let private_ip_opt = self.pub_to_priv_ip.get(&(addr, addrlen));
            if let None = private_ip_opt {
                match addr.ss_family as i32 {
                    AF_INET => unsafe {
                        let sockaddr_in = &*(&addr as *const _ as * const sockaddr_in);
                        eprintln!("Error for user address {}:{} : Auth data sent, but user is not present it active clients", sockaddr_in.sin_addr.s_addr, sockaddr_in.sin_port);
                    },
                    AF_INET6 => unsafe {
                        let sockaddr_in6 = &*(&addr as *const _ as *const sockaddr_in6);
                        eprintln!("Error for user address {:?}:{} : Auth data sent, but user is not present it active clients", sockaddr_in6.sin6_addr.s6_addr, sockaddr_in6.sin6_port);
                    },
                    _  => {
                        eprintln!("Unknown address family");
                    }
                }
                continue;
            }
            let private_ip = private_ip_opt.unwrap();

            let client_opt = self.priv_ip_to_client.get(&private_ip);
            if let None = client_opt {
                match addr.ss_family as i32 {
                    AF_INET => unsafe {
                        let sockaddr_in = &*(&addr as *const _ as * const sockaddr_in);
                        eprintln!("Public ip {}:{} is presend, but client does not exist", sockaddr_in.sin_addr.s_addr, sockaddr_in.sin_port);
                    },
                    AF_INET6 => unsafe {
                        let sockaddr_in6 = &*(&addr as *const _ as *const sockaddr_in6);
                        eprintln!("Public ip {:?}:{} is presend, but client does not exist", sockaddr_in6.sin6_addr.s6_addr, sockaddr_in6.sin6_port);
                    },
                    _  => {
                        eprintln!("Unknown address family");
                    }
                }

                self.pub_to_priv_ip.remove(&(addr, addrlen));
                
                continue;
            }
            let client = client_opt.unwrap();
                
            if let Err(e) = AuthPacketEncrypted::decrypt_in_place(&mut buffer, &client.cipher) {
                eprintln!("Failed to decrypt auth data: {e}");
                if let Some((_, priv_to_client)) = self.pub_to_priv_ip.remove(&(addr, addrlen)) {
                    self.priv_ip_to_client.remove(&priv_to_client);
                }
                continue;
            }
            //Renaming again
            let decrypted_auth_handle = buffer;

            match self.check_authdata(&decrypted_auth_handle, &client.client_nonce, &client.server_nonce) {
                Ok(_) => {
                    //let buffer_handle = decrypted_auth_handle.clear_release();
                    //TODO
                    //Renaming, will think about it later
                    let mut buffer_handle = decrypted_auth_handle;
                    TunnelSettingsPacket::new(
                        &mut buffer_handle,
                        private_ip.s_addr,
                        self.tun_netmask.to_bits(),
                        self.tun_ip.to_bits()
                    );
                    let mut tunnel_settings_handle = buffer_handle;

                    if let Err(e) = TunnelSettingsPacket::encrypt_in_place(&mut tunnel_settings_handle, &client.cipher) {
                        eprintln!("Failed to encrypt tunnel settings: {e}");
                        continue;
                    }

                    if let Err(e) = self.send_all_to_sock(&tunnel_settings_handle, &addr, &addrlen).await {
                        eprintln!("Failed to send tunnel settings: {e}");
                        continue;
                    }

                    client.set_authorized(true);
                    client.update_lastseen();

                },
                Err(e) => {
                    if let Some((_, priv_to_client)) = self.pub_to_priv_ip.remove(&(addr, addrlen)) {
                        self.priv_ip_to_client.remove(&priv_to_client);
                    }
                    eprintln!("{e}")
                },
            }
        }
        println!("Auth worker stopped...");
        //println!("authentication worker stopped...");
    }


    fn get_client_by_public_ip(self: &Arc<Self>, addr: &sockaddr_storage, addrlen: socklen_t) -> Option<dashmap::mapref::one::Ref<'_, in_addr, VPNClient>> {
        let pub_to_priv_opt = self.pub_to_priv_ip.get(&(*addr, addrlen));
        if let None = pub_to_priv_opt {
            match addr.ss_family as i32 {
                AF_INET => unsafe {
                    let sockaddr_in = &*(addr as *const _ as * const sockaddr_in);
                    eprintln!("Client {}:{} is not in active users", sockaddr_in.sin_addr.s_addr, sockaddr_in.sin_port);
                },
                AF_INET6 => unsafe {
                    let sockaddr_in6 = &*(addr as *const _ as *const sockaddr_in6);
                    eprintln!("Client {:?}:{} is not in active users", sockaddr_in6.sin6_addr.s6_addr, sockaddr_in6.sin6_port);
                },
                _  => {
                    eprintln!("Unknown address family");
                }
            }
            return None;
        }
        let pub_to_priv = pub_to_priv_opt.unwrap();

        let client_opt = self.priv_ip_to_client.get(&pub_to_priv);
        if let None = client_opt {
            match addr.ss_family as i32 {
                AF_INET => unsafe {
                    let sockaddr_in = &*(addr as *const _ as * const sockaddr_in);
                    eprintln!("Client {}:{} private address is not assigned", sockaddr_in.sin_addr.s_addr, sockaddr_in.sin_port);
                },
                AF_INET6 => unsafe {
                    let sockaddr_in6 = &*(addr as *const _ as *const sockaddr_in6);
                    eprintln!("Client {:?}:{} private address is not assigned", sockaddr_in6.sin6_addr.s6_addr, sockaddr_in6.sin6_port);
                },
                _  => {
                    eprintln!("Unknown address family");
                }
            }
            return None;
        }
        client_opt
    }



    async fn user_cleaup_task(self: &Arc<Self>) {
        let mut interval = tokio::time::interval(USER_CLEANUP_INTERVAL);
        loop {
            interval.tick().await;

            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            //let now = Instant::now();
            self.priv_ip_to_client.retain(|_priv_ip, client| {
                let last_secs = client.lastseen.load(std::sync::atomic::Ordering::Relaxed);
                if now_secs.saturating_sub(last_secs) > USER_TIMEOUT_SECONDS {
                    self.pub_to_priv_ip.remove(&client.public_ip);
                    println!("User {:?} disconnected", client.public_ip);
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
        to_sock_process: Sender<(usize, BatchHandle)>
    ) {
        let mut msghdrs: [mmsghdr; MAX_DATAGRAMS] = unsafe { std::mem::zeroed() };
        let mut iovs: [iovec; MAX_DATAGRAMS] = unsafe { std::mem::zeroed() };
        //let mut addrs: [sockaddr_in; MAX_DATAGRAMS] = unsafe { std::mem::zeroed() };
        //let addr_lens: [socklen_t; MAX_DATAGRAMS] = [std::mem::size_of::<sockaddr_in>() as socklen_t; MAX_DATAGRAMS];
        
        //let mut buffer_handles: Vec<Option<BytesMut>> = Vec::with_capacity(MAX_DATAGRAMS);

        println!("sock_read_task started");
        loop {
            // 1. Получаю буфферы
            let mut batch_handle = match self.bufferpool.acquire() {
                Some(batch) => batch,
                None => continue,
            };

            // 2. Set up iovecs
            let buffer_count = batch_handle.inner().0.len();

            let (addrs, buffers) = batch_handle.inner_mut();

            for (i,  ((sockaddr, socklen), buffer)) in addrs.iter_mut().zip(buffers.iter_mut()).enumerate() {
                
                
                let ptr = buffer.as_mut_ptr() as *mut libc::c_void;
                let capacity = buffer.capacity();

                iovs[i] = iovec { 
                    iov_base: ptr, 
                    iov_len: capacity 
                };

                msghdrs[i] = mmsghdr { 
                    msg_hdr: libc::msghdr {
                        msg_name: sockaddr as *mut _ as *mut libc::c_void,
                        msg_namelen: *socklen,
                        msg_iov: &mut iovs[i],
                        msg_iovlen: 1,
                        msg_control: std::ptr::null_mut(),
                        msg_controllen: 0,
                        msg_flags: 0,
                    }, 
                    msg_len: 0 
                }
            
            }

                
            // 3 read packets
            let num_recieved = unsafe {
                let recieve_count = libc::recvmmsg(
                    self.udpsocket_fd.as_raw_fd(),
                    msghdrs.as_mut_ptr(),
                    buffer_count as u32,
                    libc::MSG_DONTWAIT,
                    std::ptr::null_mut()
                );

                if recieve_count < 0 {
                    let err = std::io::Error::last_os_error();
                    match err.kind() {
                        std::io::ErrorKind::WouldBlock => {
                            continue;
                        }
                        _ => {
                            eprintln!("recvmmsg error: {}", err);
                            //drop(batch_handle);
                            continue;
                        },
                    }
                } else {
                    recieve_count as usize
                }
            };

            //4 Process packets
            if num_recieved > 0 {
                for i in 0..num_recieved {
                    let len = msghdrs[i].msg_len as usize;
                    // if len == 0 {
                    //     continue;
                    // }

                    unsafe {
                        buffers[i].set_len(len);
                    }
                }

                if to_sock_process.send_async((num_recieved, batch_handle)).await.is_err() {
                    break;
                }
            }
           
        };
        println!("sock_read_task finished");
    }

    fn socket_data_worker(
        self: &Arc<Self>, 
        to_process_rx: Receiver<(usize, BatchHandle)>,
        to_handshake_tx: Sender<(BytesMut, sockaddr_storage, socklen_t)>,
        to_auth_tx: Sender<(BytesMut, sockaddr_storage, socklen_t)>,
        to_tun_tx: Sender<(usize, BatchHandle)>
    ) {
        //let mut gro_table = GROTable::default();
        //let mut tun_send_bufs = Vec::<BufferHandle>::with_capacity(IDEAL_BATCH_SIZE);
        //let mut packet_count = 0;

        //let (tx, mut rx_decrypted) = mpsc::channel::<(BufferHandle, SocketAddr)>(32);
        println!("sock_data_worker started");
        while let Ok((count, mut batch)) = to_process_rx.recv() {
            let (addrs, buffers) = batch.inner_mut();
            let addrs = &mut addrs[..count];
            let buffers = &mut buffers[..count];

            addrs.par_iter_mut().zip(buffers.par_iter_mut())
                .for_each(|((addr, addrlen), buffer)| {
                    match buffer[0] {
                        PKT_TYPE_HANDSHAKE => {
                            if HandshakePacket::is_valid_buffer_size(buffer.len()) {
                                let _ = to_handshake_tx.send((buffer.clone(), addr.clone(), addrlen.clone()));
                                //self.handle_handshake_packet(addr, addrlen, buffer);
                            }

                        },
                        PKT_TYPE_AUTH => {
                            if AuthPacketEncrypted::is_valid_buffer_size(buffer) {
                                let _ = to_auth_tx.send((buffer.clone(), addr.clone(), addrlen.clone()));
                                //self.handle_auth_packet(addr, addrlen, buffer);
                            }
                        },
                        PKT_TYPE_ENCRYPTED_PKT => {
                            if EncryptedPacket::is_valid_buffer_size(buffer) {
                                if let Some(client) = self.get_client_by_public_ip(addr, *addrlen) {
                                    if client.authorized.load(std::sync::atomic::Ordering::Relaxed) {
                                        if let Ok(_) = EncryptedPacket::decrypt_in_place(buffer, &client.cipher) {
                                            client.update_lastseen();
                                        }
                                    }
                                }
                            }
                        },
                        _ => {
                            eprintln!("Unknown packet type: {}", buffer[0]);
                        }
                    }
                });
            
            if to_tun_tx.send((count, batch)).is_err() {
                break;
            }
        }

        println!("sock_data_worker stopped...");
    }

    pub async fn tun_send_worker(self: Arc<Self>, to_tun_rx: Receiver<(usize, BatchHandle)>) {
        let mut gro_table = GROTable::default();
        while let Ok((count, mut batch)) = to_tun_rx.recv_async().await {
            if count > 0 {
                let (_, buffers) = batch.inner_mut();
                //let buffers = &mut buffers[..count];

                let mut buffers: Vec<BytesMut> = buffers[0..count].iter()
                    .filter(|b| b[0] == PKT_TYPE_ENCRYPTED_PKT)
                    .map(|b| b.clone())
                    .collect();

                if let Err(e) = self.tun_device.send_multiple(
                    &mut gro_table, 
                    &mut buffers, 
                    ENCRYPTED_PACKET_HEADER_SIZE
                ).await {
                    eprintln!("Failed to send batch to tun: {}", e);
                }
            }
        }
    }

    pub async fn run(self : &Arc<Self>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        
        let (to_sock_process_tx, to_sock_process_rx) = bounded(256);
        let (to_tun_tx, to_tun_rx) = bounded(256);

        let (to_tun_process_tx, to_tun_process_rx) = bounded(256);
        let (to_sock_tx, to_sock_rx) = bounded(256);

        let (to_handshake_tx, to_handshake_rx) = bounded(256);
        let (to_auth_tx, to_auth_rx) = bounded(256);
        
        //handshake worker
        tokio::spawn({
            let me = self.clone();
            async move {
                me.handshake_worker(to_handshake_rx).await;
            }
        });

        //auth worker
        tokio::spawn({
            let me = self.clone();
            async move {
                me.auth_worker(to_auth_rx).await;
            }
        });

        {
            //tun read worker
            tokio::spawn({
                let me = self.clone();
                //let encryption_tx_clone = to_encrypt_tx.clone();
                async move {
                    me.tun_read_task(to_tun_process_tx).await
                }
            });
            //tun data processor
            tokio::task::spawn_blocking({
                let me = self.clone();
                move || {
                    me.tun_data_worker(to_tun_process_rx, to_sock_tx);
                }
            });
            //sock send worker
            tokio::spawn({
                let me = self.clone();
                async move {
                    me.sock_send_worker(to_sock_rx).await;
                }
            });
        }
      

        //sock data processor
        tokio::task::spawn_blocking({
            let me = self.clone();
            move || {
                me.socket_data_worker(
                    to_sock_process_rx, 
                    to_handshake_tx,
                    to_auth_tx,
                    to_tun_tx
                );
            }
        });
        //tun send worker
        tokio::spawn({
            let me = Arc::clone(&self);
            async move {
                me.tun_send_worker(to_tun_rx).await;
            }
        });

        tokio::spawn({
            let me = Arc::clone(&self);
            async move {
                me.user_cleaup_task().await;
            }
        });

        println!("Listening...");
        
        let _ = self.sock_read_task(to_sock_process_tx).await;

        println!("Exiting..");
        Ok(())
    }
        
}


 fn get_packet_info(data: &[u8]) -> Option<(usize, in_addr)> {
    let pkt_version = data[0] >> 4;

    match pkt_version {
        4 => {
            let total_length = u16::from_be_bytes([data[2], data[3]]) as usize;

            let addr_bytes = [data[16], data[17], data[18], data[19]];

            let s_addr = u32::from_be_bytes(addr_bytes);

            let dest_addr = in_addr { s_addr };
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
