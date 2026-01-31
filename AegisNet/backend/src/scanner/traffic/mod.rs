use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::task;
use socket2::{Socket, Domain, Type, Protocol};
use std::net::{SocketAddr, IpAddr, UdpSocket};
use std::mem::MaybeUninit;

pub mod store;
pub use store::TrafficStore;

const SIO_RCVALL: u32 = 0x98000001;

pub struct TrafficAnalyzer {
    running: Arc<AtomicBool>,
    store: Arc<TrafficStore>,
}

impl TrafficAnalyzer {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            store: Arc::new(TrafficStore::new()),
        }
    }

    pub fn get_store(&self) -> Arc<TrafficStore> {
        self.store.clone()
    }

    pub async fn start(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }

        let running = self.running.clone();
        let store = self.store.clone();
        
        task::spawn_blocking(move || {
            tracing::info!("Starting Raw Socket Sniffer...");
            
            let local_ip = match get_local_ip() {
                Some(ip) => ip,
                None => {
                    tracing::error!("Could not determine local IP.");
                    return;
                }
            };
            tracing::info!("Binding raw socket to: {}", local_ip);

            let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(0))) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Failed to create raw socket: {}", e);
                    tracing::warn!("Traffic Analysis requires Admin privileges!");
                    return;
                }
            };

            let addr = SocketAddr::new(local_ip, 0);
            if let Err(e) = socket.bind(&addr.into()) {
                tracing::error!("Failed to bind raw socket: {}", e);
                return;
            }

            #[cfg(windows)]
            {
                use windows_sys::Win32::Networking::WinSock::{WSAIoctl, SOCKET_ERROR};
                use std::os::windows::io::AsRawSocket;
                use std::ptr;

                let raw_socket = socket.as_raw_socket(); 
                let mut enabled: u32 = 1;
                let mut bytes_returned: u32 = 0;
                
                let res = unsafe {
                    WSAIoctl(
                        raw_socket as usize,
                        SIO_RCVALL,
                        &mut enabled as *mut _ as *mut _,
                        std::mem::size_of::<u32>() as u32,
                        ptr::null_mut(),
                        0,
                        &mut bytes_returned,
                        ptr::null_mut(),
                        None
                    )
                };

                if res == SOCKET_ERROR {
                    tracing::error!("WSAIoctl SIO_RCVALL failed. Run as Administrator!");
                } else {
                    tracing::info!("Promiscuous mode enabled (SIO_RCVALL).");
                }
            }

            let mut uninit_buf = [MaybeUninit::<u8>::uninit(); 65535];

            while running.load(Ordering::SeqCst) {
                 match socket.recv_from(&mut uninit_buf) {
                     Ok((size, _)) => {
                         let packet = unsafe { 
                             std::slice::from_raw_parts(uninit_buf.as_ptr() as *const u8, size) 
                         };
                         
                         if packet.len() > 20 {
                             let version = packet[0] >> 4;
                             if version == 4 {
                                 let header_len = (packet[0] & 0x0F) as usize * 4;
                                 let protocol = packet[9];
                                 let src_ip = std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
                                 let dst_ip = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                                 
                                 let payload = if packet.len() > header_len {
                                     &packet[header_len..]
                                 } else {
                                     &[]
                                 };

                                 store.process_packet(
                                     src_ip.to_string(), 
                                     dst_ip.to_string(), 
                                     size as u64, 
                                     protocol, 
                                     payload
                                 );
                             }
                         }
                     },
                     Err(e) => {
                         tracing::warn!("Recv error: {}", e);
                         std::thread::sleep(std::time::Duration::from_millis(100));
                     }
                 }
            }
            
            tracing::info!("Packet Sniffer stopped.");
        });
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

fn get_local_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip())
}
