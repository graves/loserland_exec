pub fn get_proc(name: &str, dll_data: &Vec<u8>) -> extern "C" fn() {
    println!("Test crossplatform migration");
    let callme: extern "C" fn() = unsafe { std::mem::transmute(1) };
    callme
}
