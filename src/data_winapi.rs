use const_str::split_lines;

pub const FNS_ADVAPI32: &[&str] = &split_lines!(include_str!("staticdata/winapi/advapi32.txt"));
pub const FNS_GDI32: &[&str] = &split_lines!(include_str!("staticdata/winapi/gdi32.txt"));
pub const FNS_KERNEL32: &[&str] = &split_lines!(include_str!("staticdata/winapi/kernel32.txt"));
pub const FNS_KERNELBASE: &[&str] = &split_lines!(include_str!("staticdata/winapi/KernelBase.txt"));
pub const FNS_MSCOREE: &[&str] = &split_lines!(include_str!("staticdata/winapi/mscoree.txt"));
pub const FNS_MSVCP60: &[&str] = &split_lines!(include_str!("staticdata/winapi/msvcp60.txt"));
pub const FNS_MSVCP140: &[&str] = &split_lines!(include_str!("staticdata/winapi/msvcp140.txt"));
pub const FNS_MSVCRT: &[&str] = &split_lines!(include_str!("staticdata/winapi/msvcrt.txt"));
pub const FNS_NTDLL: &[&str] = &split_lines!(include_str!("staticdata/winapi/ntdll.txt"));
pub const FNS_RPCRT4: &[&str] = &split_lines!(include_str!("staticdata/winapi/rpcrt4.txt"));
pub const FNS_SECHOST: &[&str] = &split_lines!(include_str!("staticdata/winapi/sechost.txt"));
pub const FNS_SHELL32: &[&str] = &split_lines!(include_str!("staticdata/winapi/shell32.txt"));
pub const FNS_SHLWAPI: &[&str] = &split_lines!(include_str!("staticdata/winapi/shlwapi.txt"));
pub const FNS_UCRTBASE: &[&str] = &split_lines!(include_str!("staticdata/winapi/ucrtbase.txt"));
pub const FNS_URLMON: &[&str] = &split_lines!(include_str!("staticdata/winapi/urlmon.txt"));
pub const FNS_USER32: &[&str] = &split_lines!(include_str!("staticdata/winapi/user32.txt"));
pub const FNS_VCRUNTIME140_1: &[&str] = &split_lines!(include_str!("staticdata/winapi/vcruntime140_1.txt"));
pub const FNS_VCRUNTIME140: &[&str] = &split_lines!(include_str!("staticdata/winapi/vcruntime140.txt"));
pub const FNS_WIN32U: &[&str] = &split_lines!(include_str!("staticdata/winapi/win32u.txt"));
pub const FNS_WINHTTP: &[&str] = &split_lines!(include_str!("staticdata/winapi/winhttp.txt"));
pub const FNS_WININET: &[&str] = &split_lines!(include_str!("staticdata/winapi/wininet.txt"));
pub const FNS_WS2_32: &[&str] = &split_lines!(include_str!("staticdata/winapi/ws2_32.txt"));

pub const FNS_ALL: &[&[&str]] = &[
    FNS_ADVAPI32,
    FNS_GDI32,
    FNS_KERNEL32,
    FNS_KERNELBASE,
    FNS_MSCOREE,
    FNS_MSVCP60,
    FNS_MSVCP140,
    FNS_MSVCRT,
    FNS_NTDLL,
    FNS_RPCRT4,
    FNS_SECHOST,
    FNS_SHELL32,
    FNS_SHLWAPI,
    FNS_UCRTBASE,
    FNS_URLMON,
    FNS_USER32,
    FNS_VCRUNTIME140_1,
    FNS_VCRUNTIME140,
    FNS_WIN32U,
    FNS_WINHTTP,
    FNS_WININET,
    FNS_WS2_32
];