#[derive(Debug, PartialEq, PartialOrd)]
pub enum LogLevel {
    Error = 0,
    Warn = 1,
    Debug = 2,
}

#[macro_export]
macro_rules! log_println {
    ($current_level:expr, $required_level:expr, $($arg:tt)*) => {
        if $current_level >= $required_level {
            println!($($arg)*);
        }
    };
}