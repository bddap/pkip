// be a pkip registry, listen for udp
//
// when a register packet is recieved, verify the signature
//   maybe verify that actual ip == specified ip (do we need this?)
//   save in registry
//
// when a forward packet is recieved, forward it byte for byte to
// the socketaddr of the target. if you don't have the ip of the target stored
// drop the packet
fn main() {
    todo!()
}
