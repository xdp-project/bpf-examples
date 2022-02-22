use aya::maps::{MapRefMut, SockMap};
use aya::programs::SkSkb;
use aya::{include_bytes_aligned, Bpf};
use tokio::io::AsyncReadExt;
use tokio::signal;

use std::convert::{TryFrom, TryInto};

use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/echo"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/echo"
    ))?;
    let mut sock_map = SockMap::<MapRefMut>::try_from(bpf.map_mut("sockmap")?)?;

    let parser: &mut SkSkb = bpf.program_mut("stream_parser")?.try_into()?;
    parser.load()?;
    parser.attach(&sock_map)?;

    let verdict: &mut SkSkb = bpf.program_mut("stream_verdict")?.try_into()?;
    verdict.load()?;
    verdict.attach(&sock_map)?;

    let listener = TcpListener::bind("127.0.0.1:41234").await?;

    println!("Server Listening on {}", listener.local_addr().unwrap());
    // TODO: currently this will only accept one connection at a time. add up to map max_entries handlers
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            sock_map.set(0, &socket, 0).unwrap();
            let mut buf = [0; 0];
            socket.read(&mut buf[..]).await.unwrap();
            sock_map.clear_index(&0).unwrap();
        }
    });
    signal::ctrl_c().await?;
    Ok(())
}
