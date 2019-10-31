extern crate libc;
extern crate pelite;
extern crate winapi;

use pelite::pe64::image::IMAGE_NT_HEADERS;
use pelite::pe64::{Pe, PeFile};

use std::mem;
use winapi::shared::minwindef::{DWORD, FARPROC, HINSTANCE, HIWORD, HMODULE, LPVOID, WORD};
use winapi::um::libloaderapi::LoadLibraryA;
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree, VirtualProtect};
use winapi::um::sysinfoapi::GetNativeSystemInfo;
use winapi::um::winbase::IsBadReadPtr;
use winapi::um::winnt::{
    DLL_PROCESS_ATTACH, IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_EXPORT,
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_OPTIONAL_HEADER,
    IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_MEM_DISCARDABLE,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_NOT_CACHED, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
    IMAGE_SNAP_BY_ORDINAL, LPCSTR, MEM_COMMIT, MEM_DECOMMIT, MEM_RESERVE, PAGE_EXECUTE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, PAGE_NOCACHE,
    PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, PIMAGE_EXPORT_DIRECTORY, PIMAGE_IMPORT_BY_NAME,
    PIMAGE_IMPORT_DESCRIPTOR, PIMAGE_NT_HEADERS, PIMAGE_SECTION_HEADER, PIMAGE_TLS_DIRECTORY,
    PVOID,
};

/// Type definition for an interface to the Windows API
///
/// Usually the same as extern "C", except on Win32, in which case it's "stdcall"
///
/// Arguments
/// * `hinstDLL`: A handle to the DLL module. The value is the base address of the DLL. The HINSTANCE of a DLL is the same as the HMODULE of the DLL, so hinstDLL can be used in calls to functions that require a module handle.
/// * `fdwReason`: The reason code that indicates why the DLL entry-point function is being called. See [Microsoft's DllMain entry point docs](https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain) for valid values.
/// * `lpReserved`: If fdwReason is DLL_PROCESS_ATTACH, lpvReserved is NULL for dynamic loads and non-NULL for static loads. If fdwReason is DLL_PROCESS_DETACH, lpvReserved is NULL if FreeLibrary has been called or the DLL load failed and non-NULL if the process is terminating.
type DllEntryProc =
    unsafe extern "stdcall" fn(hinstDLL: HINSTANCE, fdwReason: DWORD, lpReserved: LPVOID);

// The #[link] attribute is used to link to native libraries for FFI.
#[link(name = "kernel32")]
#[link(name = "user32")]
/// Retrieves the address of an exported function or variable from the specified dynamic-link library (DLL).
///
/// Arguments
/// * `hModule`: A handle to the DLL module that contains the function or variable. The LoadLibrary, LoadLibraryEx, LoadPackagedLibrary, or GetModuleHandle function returns this handle. The GetProcAddress function does not retrieve addresses from modules that were loaded using the LOAD_LIBRARY_AS_DATAFILE flag. For more information, see LoadLibraryEx.
/// * `lpProcName`: The function or variable name, or the function's ordinal value. If this parameter is an ordinal value, it must be in the low-order word; the high-order word must be zero.
extern "stdcall" {
    pub fn GetProcAddress(
        hModule: *const winapi::shared::minwindef::HINSTANCE__,
        lpProcName: *const i8,
    ) -> *mut usize;
}

pub fn get_proc(name: &str, dll_data: &Vec<u8>) -> FARPROC {
    let pe = PeFile::from_bytes(&dll_data).unwrap();
    let dos_header = pe.dos_header();
    let nt_headers = pe.nt_headers();

    let mut sysinfo;
    unsafe {
        sysinfo = mem::zeroed();
        GetNativeSystemInfo(&mut sysinfo);
    }

    let aligned_image_size =
        align_value_up(nt_headers.OptionalHeader.SizeOfImage, sysinfo.dwPageSize);

    let code: *mut std::ffi::c_void;
    unsafe {
        code = VirtualAlloc(
            nt_headers.OptionalHeader.ImageBase as *mut winapi::ctypes::c_void,
            aligned_image_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        ) as *mut std::ffi::c_void;
    }

    let headers;
    unsafe {
        headers = VirtualAlloc(
            code as *mut winapi::ctypes::c_void,
            nt_headers.OptionalHeader.SizeOfHeaders as usize,
            MEM_COMMIT,
            PAGE_READWRITE,
        );
    }

    let mut result = MemoryModule {
        headers: headers as PIMAGE_NT_HEADERS,
        code_base: code,
        initialized: false,
        is_dll: true,
        is_relocated: false,
        modules: Vec::new(),
        page_size: sysinfo.dwPageSize,
    };

    let dos_headerp = dos_header as *const _;
    unsafe {
        libc::memcpy(
            headers as *mut libc::c_void,
            dos_headerp as *const libc::c_void,
            nt_headers.OptionalHeader.SizeOfHeaders as usize,
        );
    }

    result.headers = (headers as usize + dos_header.e_lfanew as usize) as PIMAGE_NT_HEADERS;

    unsafe { (*result.headers).OptionalHeader.ImageBase = code as u64 };

    copy_sections(&result, &pe, &nt_headers, &dll_data);

    let location_delta;
    unsafe {
        location_delta =
            (*result.headers).OptionalHeader.ImageBase - nt_headers.OptionalHeader.ImageBase;
    }

    if location_delta != 0 {
        result.is_relocated = false;
    // TODO
    // PerformBaseRelocation(result, locationDelta);
    } else {
        result.is_relocated = true;
    }

    build_import_table(&mut result);
    finalize_sections(&result);
    execute_tls(&result);

    get_proc_address(&result, name)
}

fn copy_sections(
    result: &MemoryModule,
    pe: &PeFile,
    nt_headers: &IMAGE_NT_HEADERS,
    dll_data: &Vec<u8>,
) {
    for (count, s) in pe.section_headers().iter().enumerate() {
        let mut section = image_first_section(result.headers);
        unsafe {
            section = section.offset(count as isize);
        }

        if s.SizeOfRawData == 0 {
            let section_size = nt_headers.OptionalHeader.SectionAlignment;
            let dest;
            unsafe {
                dest = VirtualAlloc(
                    result.code_base.offset(
                        s.VirtualAddress as isize
                            / std::mem::size_of::<*mut std::ffi::c_void>() as isize,
                    ) as *mut winapi::ctypes::c_void,
                    section_size as usize,
                    MEM_COMMIT,
                    PAGE_READWRITE,
                );
            };

            unsafe { libc::memset(dest as *mut libc::c_void, 0, section_size as usize) };
        }

        let dest: *mut libc::c_void;
        let offset = result.code_base as usize + s.VirtualAddress as usize;
        unsafe {
            dest = VirtualAlloc(
                offset as *mut winapi::ctypes::c_void,
                s.SizeOfRawData as usize,
                MEM_COMMIT,
                PAGE_READWRITE,
            ) as *mut libc::c_void;
        }

        let datap;
        unsafe {
            datap = dll_data.as_ptr() as usize + s.PointerToRawData as usize;
            libc::memcpy(
                dest as *mut libc::c_void,
                datap as *const libc::c_void,
                s.SizeOfRawData as usize,
            );
        }

        let addr;
        unsafe {
            addr = (*section).Misc.PhysicalAddress_mut();
        }
        *addr = (dest as usize & 0xffffffff) as u32;
    }
}

fn build_import_table(result: &mut MemoryModule) {
    let directory = get_header_dictionary(&result, IMAGE_DIRECTORY_ENTRY_IMPORT);
    let mut import_desc: PIMAGE_IMPORT_DESCRIPTOR;
    import_desc = (result.code_base as usize + directory.VirtualAddress as usize)
        as *mut winapi::um::winnt::IMAGE_IMPORT_DESCRIPTOR;

    let mut proc_addr;
    unsafe {
        while IsBadReadPtr(import_desc as *const winapi::ctypes::c_void, 0 as usize) == 0
            && (*import_desc).Name != 0
        {
            let handle: HMODULE;
            let libloc = result.code_base as usize + (*import_desc).Name as usize;
            handle = LoadLibraryA(libloc as LPCSTR);
            result.modules.push(handle);
            let orig_first_thunk = *(*import_desc).u.OriginalFirstThunk();

            let mut thunk_ref;
            let mut func_ref: *mut FARPROC;
            if orig_first_thunk > 0 {
                thunk_ref = (result.code_base as usize + orig_first_thunk as usize) as *mut u64;
                func_ref = (result.code_base as usize + (*import_desc).FirstThunk as usize)
                    as *mut FARPROC;
            } else {
                thunk_ref =
                    (result.code_base as usize + (*import_desc).FirstThunk as usize) as *mut u64;
                func_ref = (result.code_base as usize + (*import_desc).FirstThunk as usize)
                    as *mut FARPROC;
            }

            while *thunk_ref != 0 {
                if IMAGE_SNAP_BY_ORDINAL(*thunk_ref) {
                    // TODO
                    // do some stuff
                } else {
                    let thunk_data: PIMAGE_IMPORT_BY_NAME = (result.code_base as usize
                        + (*thunk_ref) as usize)
                        as *mut winapi::um::winnt::IMAGE_IMPORT_BY_NAME;
                    proc_addr = GetProcAddress(handle, (*thunk_data).Name.as_ptr()) as FARPROC;
                    *func_ref = proc_addr;
                }

                thunk_ref = thunk_ref.offset(1);
                func_ref = func_ref.offset(1);
            }

            import_desc = import_desc.offset(1);
        }
    }
}

fn finalize_sections(result: &MemoryModule) {
    let image_offset;
    unsafe {
        image_offset = (*result.headers).OptionalHeader.ImageBase & 0xffffffff00000000;
    }

    let section = image_first_section(result.headers);

    let mut section_data = SectionFinalizeData {
        address: 0 as *mut _,
        address_aligned: 0 as *mut _,
        size: 0,
        characteristics: 0,
        last: false,
    };

    let phys;
    unsafe {
        phys = (*section).Misc.PhysicalAddress();
    }

    section_data.address = (*phys as u64 | image_offset) as *mut libc::c_void;
    section_data.address_aligned = align_address_down(section_data.address, result.page_size);
    section_data.size = real_section_size(&result, section);

    unsafe {
        section_data.characteristics = (*section).Characteristics;
    }

    let number_of_sections;
    unsafe { number_of_sections = (*result.headers).FileHeader.NumberOfSections }
    for i in 1..number_of_sections {
        let this_section;
        unsafe { this_section = section.offset(i as isize) }

        let this_phys;
        unsafe {
            this_phys = (*this_section).Misc.PhysicalAddress();
        }

        let section_address = (*this_phys as usize | image_offset as usize) as *mut usize;
        let address_aligned =
            align_address_down(section_address as *mut libc::c_void, result.page_size);
        let section_size = real_section_size(&result, this_section);

        if section_data.address_aligned == address_aligned
            || section_data.address as usize + section_data.size as usize > address_aligned as usize
        {
            let characteristics;
            unsafe {
                characteristics = (*this_section).Characteristics;
            }

            if (characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0
                || (section_data.characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0
            {
                section_data.characteristics =
                    (section_data.characteristics | characteristics) & !IMAGE_SCN_MEM_DISCARDABLE;
            } else {
                section_data.characteristics |= characteristics;
            }

            section_data.size =
                (section_address as usize + section_size as usize) - section_data.address as usize;
        }

        finalize_section(&result, &section_data);
        section_data.address = section_address as *mut libc::c_void;
        section_data.address_aligned = address_aligned;
        section_data.size = section_size;
        unsafe {
            section_data.characteristics = (*this_section).Characteristics;
        }
    }
    section_data.last = true;
    finalize_section(&result, &section_data);
}

fn execute_tls(result: &MemoryModule) {
    let directory = get_header_dictionary(&result, IMAGE_DIRECTORY_ENTRY_TLS);
    let tls: PIMAGE_TLS_DIRECTORY =
        (result.code_base as usize + directory.VirtualAddress as usize) as PIMAGE_TLS_DIRECTORY;
    let callback;
    unsafe {
        callback = (*tls).AddressOfCallBacks as *const ();
    }
    let callback: *const unsafe extern "system" fn(
        DllHandle: PVOID,
        Reason: DWORD,
        Reserved: PVOID,
    ) = unsafe { std::mem::transmute(callback) };
    unsafe {
        (*callback)(result.code_base as PVOID, DLL_PROCESS_ATTACH, 0 as PVOID);
    }
    let address_of_entrypoint;
    unsafe {
        address_of_entrypoint = (*result.headers).OptionalHeader.AddressOfEntryPoint;
    }
    if address_of_entrypoint != 0 {
        let dll_entry;
        unsafe {
            dll_entry = (result.code_base as usize
                + (*result.headers).OptionalHeader.AddressOfEntryPoint as usize)
                as *const ();
        }
        let dll_entry: DllEntryProc = unsafe { std::mem::transmute(dll_entry) };
        unsafe {
            dll_entry(
                result.code_base as *mut winapi::shared::minwindef::HINSTANCE__,
                DLL_PROCESS_ATTACH,
                0 as *mut winapi::ctypes::c_void,
            );
        }
    }
}

fn get_proc_address(result: &MemoryModule, name: &str) -> FARPROC {
    let directory = get_header_dictionary(&result, IMAGE_DIRECTORY_ENTRY_EXPORT);
    let exports: PIMAGE_EXPORT_DIRECTORY =
        (result.code_base as usize + directory.VirtualAddress as usize) as PIMAGE_EXPORT_DIRECTORY;
    if HIWORD(name.as_ptr() as DWORD) == 0 {
        println!("HIIWORD");
    // TODO
    } else {
        unsafe {
            let mut name_ref =
                (result.code_base as usize + (*exports).AddressOfNames as usize) as *const DWORD;
            let mut ordinal = (result.code_base as usize
                + (*exports).AddressOfNameOrdinals as usize)
                as *const WORD;
            for _ in 0..(*exports).NumberOfNames {
                let namep =
                    (result.code_base as usize + (*name_ref) as usize) as *const libc::c_char;
                let exported_name = std::ffi::CStr::from_ptr(namep);
                let idx = *ordinal;

                if exported_name.to_str().unwrap() == name {
                    let offset = (result.code_base as usize
                        + (*exports).AddressOfFunctions as usize
                        + (idx as usize * 4)) as *const DWORD;
                    return (result.code_base as usize + *offset as usize) as FARPROC;
                }

                name_ref = name_ref.offset(1);
                ordinal = ordinal.offset(1);
            }
        }
    }

    return 0 as FARPROC;
}

fn get_header_dictionary(result: &MemoryModule, idx: u16) -> IMAGE_DATA_DIRECTORY {
    let ret;
    unsafe { ret = (*result.headers).OptionalHeader.DataDirectory[idx as usize] }
    ret
}

fn finalize_section(result: &MemoryModule, section: &SectionFinalizeData) -> bool {
    if section.size == 0 {
        return true;
    }

    if section.characteristics & IMAGE_SCN_MEM_DISCARDABLE != 0 {
        // section is not needed any more and can safely be freed
        unsafe {
            if section.address == section.address_aligned
                && (section.last
                    || (*result.headers).OptionalHeader.SectionAlignment == result.page_size
                    || (section.size % result.page_size as usize) == 0)
            {
                VirtualFree(
                    section.address as *mut winapi::ctypes::c_void,
                    section.size,
                    MEM_DECOMMIT,
                );
            }

            return true;
        }
    }

    let executable = (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    let readable = (section.characteristics & IMAGE_SCN_MEM_READ) != 0;
    let writeable = (section.characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    let mut protect = protection_flags(executable as usize, readable as usize, writeable as usize);

    if section.characteristics & IMAGE_SCN_MEM_NOT_CACHED != 0 {
        protect |= PAGE_NOCACHE;
    }

    let mut old_protect;
    unsafe {
        old_protect = mem::zeroed();
        VirtualProtect(
            section.address as *mut winapi::ctypes::c_void,
            section.size,
            protect,
            &mut old_protect,
        );
    }

    true
}

fn protection_flags(executable: usize, readable: usize, writeable: usize) -> u32 {
    [
        [
            // not executable
            [PAGE_NOACCESS, PAGE_WRITECOPY],
            [PAGE_READONLY, PAGE_READWRITE],
        ],
        [
            // executable
            [PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY],
            [PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE],
        ],
    ][executable][readable][writeable]
}

fn image_first_section(nt_headers: PIMAGE_NT_HEADERS) -> PIMAGE_SECTION_HEADER {
    let optional_hdr_ptr: *const IMAGE_OPTIONAL_HEADER;
    unsafe {
        optional_hdr_ptr = &(*nt_headers).OptionalHeader as *const _;
    }

    let section: PIMAGE_SECTION_HEADER;
    unsafe {
        section = optional_hdr_ptr.offset(1 as isize) as PIMAGE_SECTION_HEADER;
    }

    section as PIMAGE_SECTION_HEADER
}

fn align_value_up(value: u32, alignment: u32) -> usize {
    let ret = (value + alignment - 1) & !(alignment - 1);
    ret as usize
}

fn align_address_down(address: *mut std::ffi::c_void, alignment: u32) -> *mut std::ffi::c_void {
    (address as usize & !(alignment as usize - 1)) as *mut std::ffi::c_void
}

fn real_section_size(result: &MemoryModule, section: PIMAGE_SECTION_HEADER) -> usize {
    let mut size;
    unsafe {
        size = (*section).SizeOfRawData;

        if size == 0 {
            if (*section).Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
                size = (*result.headers).OptionalHeader.SizeOfInitializedData;
            } else if (*section).Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
                size = (*result.headers).OptionalHeader.SizeOfUninitializedData;
            }
        }
    }

    size as usize
}

#[derive(Debug)]
struct MemoryModule {
    headers: PIMAGE_NT_HEADERS,
    code_base: *mut std::ffi::c_void,
    initialized: bool,
    is_dll: bool,
    is_relocated: bool,
    modules: Vec<HMODULE>,
    page_size: u32,
}

#[derive(Debug)]
struct SectionFinalizeData {
    address: *mut std::ffi::c_void,
    address_aligned: *mut std::ffi::c_void,
    size: usize,
    characteristics: u32,
    last: bool,
}
