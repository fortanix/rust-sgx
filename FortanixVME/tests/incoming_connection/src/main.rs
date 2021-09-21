use std::net::TcpListener;

fn main() {
    println!("Bind to socket to 3400");
    let listener = TcpListener::bind("127.0.0.1:3400").expect("Bind failed");

    println!("Listening for incoming connections...");
    for _i in 0..2 {
        match listener.accept() {
            Ok((stream, _addr)) => println!("Connected"),
            Err(e)              => println!("Accept failed: {:?}", e),
        }
    }
}
