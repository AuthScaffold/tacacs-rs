use std::ffi::CStr;
use std::os::raw::c_char;

pub(crate) fn c_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    }
}

pub(crate) fn argv_strings(argv: *mut *mut c_char) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = argv;
    while !current.is_null() {
        unsafe {
            let arg = *current;
            if arg.is_null() {
                break;
            }
            args.push(c_string(arg));
            current = current.add(1);
        }
    }
    args
}
