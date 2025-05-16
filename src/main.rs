mod signature;

use signature::Signer;
///
///
fn main() {
    println!("Hello, world!");
    let signer = Signer::new();
    println!("to_private_key:{:?}", signer.to_private_key());
    println!("address:{:?}", signer.to_address());
}
