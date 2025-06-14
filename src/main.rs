mod signature;

use signature::Signer;
///
///
fn main() {
    println!("Hello, world!");
    let signer = Signer::new();
    println!("to_private_key:{:?}", signer.private_key_str());
    println!("address:{:?}", signer.address());
}
