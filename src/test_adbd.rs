use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;

use crate::protocol::{self, AdbMessage};
use crate::transport::{self, Transport};

pub(crate) struct StubAdbd {
    addr: SocketAddr,
    handle: thread::JoinHandle<()>,
}

impl StubAdbd {
    pub(crate) fn spawn<F>(banner: impl Into<Vec<u8>>, script: F) -> Self
    where
        F: FnOnce(&mut TcpStream) + Send + 'static,
    {
        let banner = banner.into();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let hello = AdbMessage::read_from(&mut stream, protocol::MAX_PAYLOAD).unwrap();
            assert_eq!(hello.command, protocol::A_CNXN);
            assert_eq!(hello.arg0, protocol::A_VERSION);
            assert_eq!(hello.arg1, protocol::MAX_PAYLOAD as u32);
            assert!(
                String::from_utf8_lossy(&hello.payload).starts_with("host::features="),
                "host CNXN banner 必须声明 feature 列表"
            );

            AdbMessage::new(
                protocol::A_CNXN,
                protocol::A_VERSION,
                protocol::MAX_PAYLOAD as u32,
                banner,
            )
            .unwrap()
            .write_to(&mut stream, protocol::A_VERSION)
            .unwrap();

            script(&mut stream);
        });

        Self { addr, handle }
    }

    pub(crate) fn target(&self) -> String {
        self.addr.to_string()
    }

    pub(crate) fn connect_transport(&self, id: u64) -> Transport {
        transport::connect_tcp(id, &self.target()).unwrap()
    }

    pub(crate) fn connect_transport_with_burst(&self, id: u64) -> Transport {
        transport::connect_tcp_with_burst_for_test(id, &self.target()).unwrap()
    }

    pub(crate) fn join(self) {
        self.handle.join().unwrap();
    }
}
