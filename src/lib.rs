//! ue5-dumper as a library, so tools (the dumper bin, the ESP) can reuse the
//! memory reader, scanner, and UE walking code.

pub mod codegen;
pub mod mem;
pub mod scanner;
pub mod ue;
