//! This is the goal:
//!
//! ```nocompile
//! pub async fn send_plaintext(dest: &PublicKey, message: &[u8]) -> io::Result<()>;
//! pub async fn recv_plaintext(dest: &KeyPair, buf: &mut [u8]) -> io::Result<Range<usize>>;
//! pub async fn send(src: &KeyPair, dest: &PublicKey, message: &[u8]) -> io::Result<()>;
//! pub async fn recv(dest: &KeyPair, buf: &mut [u8]) -> io::Result<(Range<usize>, PublicKey)>;
//! ```
//!
//! The user would call these functions directly. They shouldn't need to think about
//! which directory servers they use, sensible defaults should be provided.
//! A default instance of [Pkip] will used for the static functions mentioned above.
//!
//! # Customizability
//!
//! Both these options will be supported:
//! Method one, user creates a custom [Pkip] object rather than using the global one.
//! Method two, user sets the `PKIP_DIRECTORIES` env var or similar.

mod center;
mod directory_server;
mod packet;
mod signatures;

pub use center::{recv_plaintext, register_unreliable, send_plaintext};
pub use directory_server::directory_server;
pub use packet::{PkipPacket, PUBLIC_KEY_SIZE, TAG_REGISTER, TAG_SEND};
pub use signatures::{KeyPair, PublicKey, Signature};
