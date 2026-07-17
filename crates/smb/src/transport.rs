//! SMB over direct TCP/445: each message is prefixed with a 4-byte length (a zero byte
//! then a 24-bit big-endian length), per the NetBIOS-less "direct TCP" framing.

use crate::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct SmbTransport {
    stream: TcpStream,
}

impl SmbTransport {
    pub async fn connect(host: &str) -> Result<Self> {
        let addr = if host.contains(':') { host.to_string() } else { format!("{host}:445") };
        Ok(SmbTransport { stream: TcpStream::connect(addr).await? })
    }

    pub async fn send(&mut self, message: &[u8]) -> Result<()> {
        let len = message.len() as u32;
        let prefix = [0, (len >> 16) as u8, (len >> 8) as u8, len as u8];
        self.stream.write_all(&prefix).await?;
        self.stream.write_all(message).await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        let mut prefix = [0u8; 4];
        self.stream.read_exact(&mut prefix).await?;
        let len = ((prefix[1] as usize) << 16) | ((prefix[2] as usize) << 8) | prefix[3] as usize;
        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn framing_length_encoding() {
        let len = 0x0123_u32;
        let prefix = [0, (len >> 16) as u8, (len >> 8) as u8, len as u8];
        assert_eq!(prefix, [0, 0, 0x01, 0x23]);
    }
}
