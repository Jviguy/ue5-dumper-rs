//! One-shot probe: resolve a UClass's C++ vtable from the live process and map
//! chosen virtual slots back to static IDA addresses (ImageBase 0x140000000).
//!
//! Usage: vtable [ClassName] [off1,off2,...]
//!   defaults: RuntimePaintableComponent  0x4e0,0x500,0x578,0x580

use ue5_dumper::mem::ProcessHandle;
use ue5_dumper::scanner;
use ue5_dumper::ue::fname::FNamePool;
use ue5_dumper::ue::objects::GObjects;

const PROCESS: &str = "PenguinHotel-Win64-Shipping.exe";
const IMAGE_BASE: usize = 0x140000000;
const OBJ_NAME: usize = 0x18;

fn main() {
    let mut args = std::env::args().skip(1);
    let target = args.next().unwrap_or_else(|| "RuntimePaintableComponent".into());
    let offsets: Vec<usize> = args
        .next()
        .map(|s| {
            s.split(',')
                .filter_map(|x| usize::from_str_radix(x.trim_start_matches("0x"), 16).ok())
                .collect()
        })
        .unwrap_or_else(|| vec![0x4e0, 0x500, 0x578, 0x580]);

    let proc = ProcessHandle::attach(PROCESS).expect("attach failed — is the game running?");
    eprintln!("[+] base {:#x}", proc.base);
    let scan = scanner::scan(&proc).expect("scan failed");
    let mut names = FNamePool::with_addr(&proc, scan.gnames).expect("fname init failed");
    names.validate(&proc);
    let gobjects = GObjects::with_addr(&proc, scan.gobjects, scan.layout).expect("gobjects failed");
    eprintln!("[+] {} objects", gobjects.objects.len());

    // Find an instance (or CDO) whose class name == target. Cache class names.
    let mut cache: std::collections::HashMap<usize, String> = std::collections::HashMap::new();
    let mut inst = 0usize;
    for o in &gobjects.objects {
        let cn = cache.entry(o.class_addr).or_insert_with(|| {
            names.resolve(&proc, o.class_addr + OBJ_NAME).unwrap_or_default()
        });
        if cn == &target {
            inst = o.addr;
            break;
        }
    }
    if inst == 0 {
        eprintln!("[!] no instance of {target} found (is a match loaded?)");
        return;
    }
    eprintln!("[+] {target} instance @ {inst:#x}");

    let vtable = proc.ptr(inst).expect("vtable ptr null");
    eprintln!(
        "[+] vtable @ {:#x}  (rva {:#x}, IDA {:#x})",
        vtable,
        vtable - proc.base,
        IMAGE_BASE + (vtable - proc.base)
    );

    println!("\nslot            runtime            rva          IDA static");
    for off in offsets {
        match proc.ptr(vtable + off) {
            Some(fnptr) => {
                let rva = fnptr.wrapping_sub(proc.base);
                println!("+{off:#06x}  ->  {fnptr:#018x}   {rva:#010x}   {:#x}", IMAGE_BASE + rva);
            }
            None => println!("+{off:#06x}  ->  null"),
        }
    }
}
