
fn foo() {
    println!("Foo!\n");
    panic!("Panicking")
}
fn main() {
    std::env::set_var("RUST_BACKTRACE", "1");
    println!("Hello, world!");
    foo();
    println!("Hello, again!");
}
