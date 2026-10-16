use std::ffi::CStr;
use std::os::raw::c_char;

/// Copies an optional C string supplied by the host.
///
/// # Safety
/// A non-null pointer must reference a readable NUL-terminated string for this call.
pub(crate) unsafe fn c_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        // SAFETY: Callers pass pointers from Bash or libc. These pointers remain
        // valid for this call and identify a NUL-terminated C string.
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    }
}

/// Copies an optional argument vector supplied by the host.
///
/// # Safety
/// A non-null pointer must reference a readable null-terminated pointer array.
/// Every non-null entry must reference a live NUL-terminated string.
pub(crate) unsafe fn argv_strings(argv: *mut *mut c_char) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = argv;
    while !current.is_null() {
        // SAFETY: Bash supplies argv as a readable, NUL-terminated pointer
        // array. Each non-null entry points to a valid C string. The array and
        // strings remain valid while this function copies them.
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

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::ptr;

    use super::{argv_strings, c_string};

    #[test]
    fn null_host_pointers_are_empty() {
        // SAFETY: Both helpers explicitly accept null pointers.
        unsafe {
            assert!(c_string(ptr::null()).is_empty());
            assert!(argv_strings(ptr::null_mut()).is_empty());
        }
    }

    #[test]
    fn copied_values_outlive_host_buffers() {
        let (name, arguments) = {
            let command = CString::new("show").unwrap();
            let argument = CString::new("interfaces").unwrap();
            let mut pointers = [
                command.as_ptr().cast_mut(),
                argument.as_ptr().cast_mut(),
                ptr::null_mut(),
            ];
            // SAFETY: The terminated pointer array and both C strings remain live during copying.
            unsafe { (c_string(command.as_ptr()), argv_strings(pointers.as_mut_ptr())) }
        };
        assert_eq!(name, "show");
        assert_eq!(arguments, ["show", "interfaces"]);
    }
}
