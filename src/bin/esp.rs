//! Minimal ESP for a UE5 game, built on the dumper's memory/scanner code.
//!
//! Single-player, no anti-cheat: reads actor positions out of the running
//! process, projects them to screen, and (overlay mode) draws boxes over the
//! game window. `--probe` prints the resolved chain + an actor class histogram
//! so you can sanity-check the math before drawing anything.

use std::collections::HashMap;
use ue5_dumper::mem::ProcessHandle;
use ue5_dumper::scanner;
use ue5_dumper::ue::fname::FNamePool;

// ── Offsets for this build (from sdk_dump.json) ─────────────────────
const OBJ_CLASS: usize = 0x10;
const OBJ_NAME: usize = 0x18;
const WORLD_GAME_INSTANCE: usize = 0x228;
const WORLD_PERSISTENT_LEVEL: usize = 0x30;
const GI_LOCAL_PLAYERS: usize = 0x38; // TArray<ULocalPlayer*>
const PLAYER_PLAYER_CONTROLLER: usize = 0x30;
const PC_ACK_PAWN: usize = 0x350;
const PC_CAMERA_MANAGER: usize = 0x360;
const CAMERA_CACHE: usize = 0x1530; // FCameraCacheEntry
const CACHE_POV: usize = 0x10; // FMinimalViewInfo within the cache entry
const POV_LOCATION: usize = 0x00; // FVector  (3x f64)
const POV_ROTATION: usize = 0x18; // FRotator (3x f64: Pitch, Yaw, Roll)
const POV_FOV: usize = 0x30; // f32
const ACTOR_ROOT: usize = 0x1b8; // AActor::RootComponent
const SCENE_REL_LOCATION: usize = 0x140; // USceneComponent::RelativeLocation (3x f64)

type Vec3 = [f64; 3];

/// Read a UObject's class name (ClassPrivate -> FName).
fn class_name(p: &ProcessHandle, names: &mut FNamePool, obj: usize) -> Option<String> {
    let cls = p.ptr(obj + OBJ_CLASS)?;
    names.resolve(p, cls + OBJ_NAME)
}

/// First element of a TArray<*> at `addr`. Returns the pointed-to object.
fn tarray_first(p: &ProcessHandle, addr: usize) -> Option<usize> {
    let data = p.ptr(addr)?;
    let count = p.read::<i32>(addr + 8)?;
    if count < 1 {
        return None;
    }
    p.ptr(data)
}

/// World-space location of an actor via RootComponent.RelativeLocation.
// ponytail: RelativeLocation, not ComponentToWorld — correct for top-level
// actors (pawns/characters); actors attached to a moving parent would be off.
fn actor_location(p: &ProcessHandle, actor: usize) -> Option<Vec3> {
    let root = p.ptr(actor + ACTOR_ROOT)?;
    p.read::<Vec3>(root + SCENE_REL_LOCATION)
}

struct Camera {
    loc: Vec3,
    rot: Vec3, // pitch, yaw, roll (degrees)
    fov: f32,
}

const CONTROLLER_PLAYER_STATE: usize = 0x2b0;
const PLAYERSTATE_NAME: usize = 0x340; // FString PlayerNamePrivate

// ── PlayerState / player-list ESP ───────────────────────────────────
const WORLD_GAMESTATE: usize = 0x1b0; // UWorld::GameState
const GS_PLAYER_ARRAY: usize = 0x2c0; // AGameStateBase::PlayerArray (TArray<APlayerState*>)
const PS_FLAGS_BYTE: usize = 0x2b2; // packed bools
const PS_MASK_SPECTATOR: u8 = 0x02; // bIsSpectator
const PS_MASK_ONLY_SPECTATOR: u8 = 0x04; // bOnlySpectator
const PS_PAWN_PRIVATE: usize = 0x320; // APlayerState::PawnPrivate
const PS_HEALTH_ATTRSET: usize = 0x3b0; // RedpointAbilityPlayerState::HealthAttributeSet
const ATTR_CURRENT_HEALTH: usize = 0x30; // RedpointAttributeSetHealth::CurrentHealth (FGameplayAttributeData)
const ATTRDATA_CURRENT_VALUE: usize = 0x0c; // FGameplayAttributeData::CurrentValue (f32)

struct PlayerView {
    name: String,
    spectator: bool,
    pawn: usize,       // 0 = no pawn (dead/respawning)
    health: Option<f32>, // None if no GAS health set
    is_self: bool,
}

impl PlayerView {
    /// A live, drawable opponent: has a pawn, not a spectator, not dead, not us.
    fn drawable(&self) -> bool {
        !self.spectator
            && !self.is_self
            && self.pawn != 0
            && self.health.map(|h| h > 0.0).unwrap_or(true)
    }
}

/// Walk GameState.PlayerArray and read each player's name/flags/pawn/health.
fn read_players(p: &ProcessHandle, world: usize) -> Vec<PlayerView> {
    let mut out = Vec::new();
    let self_pawn = read_camera(p, world).map(|(_, pawn)| pawn).unwrap_or(0);
    let Some(gs) = p.ptr(world + WORLD_GAMESTATE) else { return out };
    let Some(data) = p.ptr(gs + GS_PLAYER_ARRAY) else { return out };
    let count = p.read::<i32>(gs + GS_PLAYER_ARRAY + 8).unwrap_or(0).max(0) as usize;

    for i in 0..count.min(64) {
        let Some(ps) = p.ptr(data + i * 8) else { continue };
        let flags = p.read::<u8>(ps + PS_FLAGS_BYTE).unwrap_or(0);
        let pawn = p.ptr(ps + PS_PAWN_PRIVATE).unwrap_or(0);
        let health = p
            .ptr(ps + PS_HEALTH_ATTRSET)
            .and_then(|h| p.read::<f32>(h + ATTR_CURRENT_HEALTH + ATTRDATA_CURRENT_VALUE));
        let name = read_fstring(p, ps + PLAYERSTATE_NAME).unwrap_or_else(|| "Player".into());
        out.push(PlayerView {
            name,
            spectator: flags & (PS_MASK_SPECTATOR | PS_MASK_ONLY_SPECTATOR) != 0,
            pawn,
            health,
            is_self: pawn != 0 && pawn == self_pawn,
        });
    }
    out
}

/// Read a UE FString { *u16 data, i32 len, i32 max } as a Rust String.
fn read_fstring(p: &ProcessHandle, addr: usize) -> Option<String> {
    let data = p.ptr(addr)?;
    let len = p.read::<i32>(addr + 8)?;
    if len <= 0 || len > 512 {
        return None;
    }
    let bytes = p.read_bytes(data, len as usize * 2)?;
    let utf16: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let s = String::from_utf16_lossy(&utf16);
    Some(s.trim_end_matches('\0').to_string())
}

const PARTY_SLOT: usize = 0x2e8; // RedpointPartyMember::PartyMemberSlot

/// Best human-readable label for an actor.
/// - the local player's pawn -> their real PlayerState name
/// - a party-slot actor      -> "Member N" (no per-actor name exists)
/// - anything else           -> class name minus BP_/_C noise
fn display_name(p: &ProcessHandle, actor: usize, cls: &str, pawn: usize, local: &str) -> String {
    if actor == pawn && !local.is_empty() {
        return local.to_string();
    }
    if cls.contains("PartyMember") {
        let slot = p.read::<i32>(actor + PARTY_SLOT).unwrap_or(-1);
        return format!("Member {slot}");
    }
    let s = cls.strip_suffix("_C").unwrap_or(cls);
    s.strip_prefix("BP_").unwrap_or(s).to_string()
}

/// Local player's display name via PlayerController -> PlayerState -> PlayerNamePrivate.
fn local_player_name(p: &ProcessHandle, world: usize) -> Option<String> {
    let gi = p.ptr(world + WORLD_GAME_INSTANCE)?;
    let lp = tarray_first(p, gi + GI_LOCAL_PLAYERS)?;
    let pc = p.ptr(lp + PLAYER_PLAYER_CONTROLLER)?;
    let ps = p.ptr(pc + CONTROLLER_PLAYER_STATE)?;
    read_fstring(p, ps + PLAYERSTATE_NAME)
}

/// Standard UE world->screen using the camera POV and viewport size.
fn world_to_screen(t: Vec3, cam: &Camera, w: f64, h: f64) -> Option<(f64, f64)> {
    let (sp, cp) = cam.rot[0].to_radians().sin_cos();
    let (sy, cy) = cam.rot[1].to_radians().sin_cos();
    let (sr, cr) = cam.rot[2].to_radians().sin_cos();

    // UE FRotationMatrix axes.
    let ax_x = [cp * cy, cp * sy, sp]; // forward
    let ax_y = [sr * sp * cy - cr * sy, sr * sp * sy + cr * cy, -sr * cp]; // right
    let ax_z = [-(cr * sp * cy + sr * sy), cy * sr - cr * sp * sy, cr * cp]; // up

    let d = [t[0] - cam.loc[0], t[1] - cam.loc[1], t[2] - cam.loc[2]];
    let dot = |a: Vec3, b: Vec3| a[0] * b[0] + a[1] * b[1] + a[2] * b[2];

    let tz = dot(d, ax_x);
    if tz < 1.0 {
        return None; // behind camera
    }
    let tx = dot(d, ax_y);
    let ty = dot(d, ax_z);

    let cx = w / 2.0;
    let cyc = h / 2.0;
    let fov_rad = (cam.fov as f64).to_radians();
    let scale = cx / (fov_rad / 2.0).tan();
    Some((cx + tx * scale / tz, cyc - ty * scale / tz))
}

/// Auto-detect ULevel::Actors (a TArray<AActor*> that isn't a UPROPERTY, so
/// its offset isn't in the dump). Scan the level object for a plausible array.
fn find_actors_offset(p: &ProcessHandle, names: &mut FNamePool, level: usize) -> Option<usize> {
    for off in (0x80..0x300).step_by(8) {
        let (Some(data), Some(count), Some(max)) = (
            p.ptr(level + off),
            p.read::<i32>(level + off + 8),
            p.read::<i32>(level + off + 12),
        ) else {
            continue;
        };
        if count < 1 || count > 0x20000 || max < count || max > count + 0x8000 {
            continue;
        }
        let probe = 8.min(count as usize);
        let mut valid = 0;
        for i in 0..probe {
            if let Some(actor) = p.ptr(data + i * 8) {
                if class_name(p, names, actor).is_some_and(|s| !s.is_empty()) {
                    valid += 1;
                }
            }
        }
        if valid == probe && probe > 0 {
            return Some(off);
        }
    }
    None
}

/// Resolve the GWorld -> camera + player chain.
fn read_camera(p: &ProcessHandle, world: usize) -> Option<(Camera, usize)> {
    let gi = p.ptr(world + WORLD_GAME_INSTANCE)?;
    let local_player = tarray_first(p, gi + GI_LOCAL_PLAYERS)?;
    let pc = p.ptr(local_player + PLAYER_PLAYER_CONTROLLER)?;
    let cam_mgr = p.ptr(pc + PC_CAMERA_MANAGER)?;
    let pov = cam_mgr + CAMERA_CACHE + CACHE_POV;
    let cam = Camera {
        loc: p.read::<Vec3>(pov + POV_LOCATION)?,
        rot: p.read::<Vec3>(pov + POV_ROTATION)?,
        fov: p.read::<f32>(pov + POV_FOV)?,
    };
    let pawn = p.ptr(pc + PC_ACK_PAWN).unwrap_or(0);
    Some((cam, pawn))
}

const PROCESS_NAME: &str = "PenguinHotel-Win64-Shipping.exe";

struct Ctx {
    proc: ProcessHandle,
    names: FNamePool,
    gworld: usize, // address of the GWorld pointer (static)
}

fn setup() -> Ctx {
    let proc = ProcessHandle::attach(PROCESS_NAME).expect("game process not found — is it running?");
    eprintln!("[+] attached pid {} base {:#x}", proc.pid, proc.base);
    let scan = scanner::scan(&proc).expect("scan failed");
    let mut names = FNamePool::with_addr(&proc, scan.gnames).expect("fname init failed");
    if !names.validate(&proc) {
        panic!("fname validation failed");
    }
    Ctx { proc, names, gworld: scan.gworld }
}

fn main() {
    let filter = std::env::args().skip(1).find(|a| !a.starts_with('-'));
    let probe_mode = std::env::args().any(|a| a == "--probe");
    let draw_all = std::env::args().any(|a| a == "--all");
    let players = std::env::args().any(|a| a == "--players");

    let ctx = setup();
    if probe_mode {
        probe(ctx);
        return;
    }
    #[cfg(windows)]
    overlay::run(ctx, filter, draw_all, players);
    #[cfg(not(windows))]
    {
        let _ = (filter, draw_all, players);
        eprintln!("[!] overlay mode is Windows-only; use --probe");
    }
}

fn probe(ctx: Ctx) {
    let Ctx { proc, mut names, gworld } = ctx;
    let world = proc.ptr(gworld).expect("GWorld null");
    eprintln!("[+] UWorld @ {world:#x}");

    let (cam, pawn) = read_camera(&proc, world).expect("camera chain failed");
    eprintln!(
        "[+] camera loc=({:.1},{:.1},{:.1}) rot=({:.1},{:.1},{:.1}) fov={:.1}",
        cam.loc[0], cam.loc[1], cam.loc[2], cam.rot[0], cam.rot[1], cam.rot[2], cam.fov
    );
    if pawn != 0 {
        if let Some(pos) = actor_location(&proc, pawn) {
            let cls = class_name(&proc, &mut names, pawn).unwrap_or_default();
            eprintln!(
                "[+] player pawn {cls} @ ({:.1},{:.1},{:.1})",
                pos[0], pos[1], pos[2]
            );
        }
    }

    let level = proc.ptr(world + WORLD_PERSISTENT_LEVEL).expect("level null");
    let actors_off = find_actors_offset(&proc, &mut names, level).expect("could not find Actors array");
    let actors_data = proc.ptr(level + actors_off).unwrap();
    let actors_count = proc.read::<i32>(level + actors_off + 8).unwrap() as usize;
    eprintln!("[+] ULevel.Actors @ +{actors_off:#x}: {actors_count} actors");

    // Histogram of actor classes + sample projections (assume 1920x1080 for probe).
    let (vw, vh) = (1920.0, 1080.0);
    let mut hist: HashMap<String, usize> = HashMap::new();
    let mut on_screen = 0;
    let mut samples = Vec::new();
    for i in 0..actors_count {
        let Some(actor) = proc.ptr(actors_data + i * 8) else { continue };
        let Some(cls) = class_name(&proc, &mut names, actor) else { continue };
        *hist.entry(cls.clone()).or_default() += 1;
        if let Some(pos) = actor_location(&proc, actor) {
            if let Some((sx, sy)) = world_to_screen(pos, &cam, vw, vh) {
                if sx >= 0.0 && sx < vw && sy >= 0.0 && sy < vh {
                    on_screen += 1;
                    if samples.len() < 15 {
                        let dist =
                            ((pos[0] - cam.loc[0]).powi(2) + (pos[1] - cam.loc[1]).powi(2)).sqrt()
                                / 100.0;
                        samples.push((cls, sx, sy, dist));
                    }
                }
            }
        }
    }

    match local_player_name(&proc, world) {
        Some(n) => eprintln!("[+] local player name = '{n}'"),
        None => eprintln!("[!] local player name unavailable (no PlayerState/name yet)"),
    }

    let players = read_players(&proc, world);
    eprintln!("\n[+] GameState.PlayerArray: {} players", players.len());
    eprintln!("    {:20} spec  self  pawn        health   -> drawn?", "name");
    for pv in &players {
        let hp = pv.health.map(|h| format!("{h:.0}")).unwrap_or_else(|| "n/a".into());
        eprintln!(
            "    {:20} {:5} {:5} {:#012x}  {:>6}   {}",
            pv.name,
            pv.spectator,
            pv.is_self,
            pv.pawn,
            hp,
            if pv.drawable() { "YES" } else { "skip" }
        );
    }

    let mut sorted: Vec<_> = hist.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    eprintln!("\n[+] actor class histogram (top 30):");
    for (cls, n) in sorted.iter().take(30) {
        eprintln!("    {n:5}  {cls}");
    }
    eprintln!("\n[+] {on_screen} actors projected on-screen; samples:");
    for (cls, sx, sy, dist) in &samples {
        eprintln!("    ({sx:7.1},{sy:7.1})  {dist:6.1}m  {cls}");
    }
}

#[cfg(windows)]
mod overlay {
    use super::{
        actor_location, class_name, find_actors_offset, read_camera, world_to_screen, Camera, Ctx,
        Vec3, OBJ_CLASS, WORLD_PERSISTENT_LEVEL,
    };
    use std::collections::HashMap;
    use std::mem::{size_of, zeroed};
    use std::ptr::{null, null_mut};
    use ue5_dumper::mem::ProcessHandle;
    use ue5_dumper::ue::fname::FNamePool;
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
    use windows_sys::Win32::Graphics::Gdi::*;
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
    use windows_sys::Win32::UI::WindowsAndMessaging::*;

    type Predicate = std::boxed::Box<dyn Fn(&str) -> bool>;

    fn rgb(r: u8, g: u8, b: u8) -> u32 {
        (r as u32) | ((g as u32) << 8) | ((b as u32) << 16)
    }

    struct FindData {
        pid: u32,
        hwnd: HWND,
    }

    unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> i32 {
        let data = &mut *(lparam as *mut FindData);
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, &mut pid);
        if pid == data.pid && IsWindowVisible(hwnd) != 0 {
            let mut r: RECT = zeroed();
            GetClientRect(hwnd, &mut r);
            if r.right - r.left > 100 && r.bottom - r.top > 100 {
                data.hwnd = hwnd;
                return 0; // stop enumeration
            }
        }
        1
    }

    fn find_game_window(pid: u32) -> Option<HWND> {
        let mut d = FindData { pid, hwnd: null_mut() };
        unsafe { EnumWindows(Some(enum_proc), &mut d as *mut _ as LPARAM) };
        (!d.hwnd.is_null()).then_some(d.hwnd)
    }

    unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
        if msg == WM_DESTROY {
            PostQuitMessage(0);
            return 0;
        }
        DefWindowProcA(hwnd, msg, w, l)
    }

    fn create_overlay() -> HWND {
        unsafe {
            let hinst = GetModuleHandleA(null());
            let class = b"meccha_esp\0";
            let wc = WNDCLASSEXA {
                cbSize: size_of::<WNDCLASSEXA>() as u32,
                style: 0,
                lpfnWndProc: Some(wndproc),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: hinst,
                hIcon: null_mut(),
                hCursor: null_mut(),
                hbrBackground: null_mut(),
                lpszMenuName: null(),
                lpszClassName: class.as_ptr(),
                hIconSm: null_mut(),
            };
            RegisterClassExA(&wc);
            let hwnd = CreateWindowExA(
                WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                class.as_ptr(),
                b"esp\0".as_ptr(),
                WS_POPUP | WS_VISIBLE,
                0,
                0,
                100,
                100,
                null_mut(),
                null_mut(),
                hinst,
                null(),
            );
            // Black (0x000000) is keyed to transparent; everything else draws.
            SetLayeredWindowAttributes(hwnd, 0, 0, LWA_COLORKEY);
            ShowWindow(hwnd, SW_SHOW);
            hwnd
        }
    }

    /// One drawn target: screen-space box + label.
    struct Target {
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
        label: String,
        enemy: bool,
    }

    /// Build a head-to-foot box from an actor's center location.
    fn make_box(pos: Vec3, cam: &Camera, w: f64, h: f64, name: &str, enemy: bool) -> Option<Target> {
        const HALF_HEIGHT: f64 = 88.0; // UE character capsule half-height
        let head = world_to_screen([pos[0], pos[1], pos[2] + HALF_HEIGHT], cam, w, h)?;
        let foot = world_to_screen([pos[0], pos[1], pos[2] - HALF_HEIGHT], cam, w, h)?;
        let bh = foot.1 - head.1;
        if bh < 4.0 {
            return None;
        }
        let bw = bh * 0.45;
        let cx = (head.0 + foot.0) / 2.0;
        let dist = ((pos[0] - cam.loc[0]).powi(2) + (pos[1] - cam.loc[1]).powi(2)).sqrt() / 100.0;
        Some(Target {
            left: (cx - bw / 2.0) as i32,
            top: head.1 as i32,
            right: (cx + bw / 2.0) as i32,
            bottom: foot.1 as i32,
            label: format!("{name}  {dist:.0}m"),
            enemy,
        })
    }

    /// Player ESP source: GameState.PlayerArray, skipping spectators and dead.
    fn collect_player_targets(
        proc: &ProcessHandle,
        gworld: usize,
        w: f64,
        h: f64,
    ) -> Vec<Target> {
        let mut out = Vec::new();
        let Some(world) = proc.ptr(gworld) else { return out };
        let Some((cam, _)) = read_camera(proc, world) else { return out };
        for pv in super::read_players(proc, world) {
            if !pv.drawable() {
                continue;
            }
            let Some(pos) = actor_location(proc, pv.pawn) else { continue };
            if let Some(b) = make_box(pos, &cam, w, h, &pv.name, true) {
                out.push(b);
            }
        }
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn collect_targets(
        proc: &ProcessHandle,
        names: &mut FNamePool,
        cache: &mut HashMap<usize, String>,
        gworld: usize,
        actors_off: usize,
        w: f64,
        h: f64,
        local_name: &str,
        want: &Predicate,
    ) -> Vec<Target> {
        let mut out = Vec::new();
        let Some(world) = proc.ptr(gworld) else { return out };
        let Some((cam, pawn)) = read_camera(proc, world) else { return out };
        let Some(level) = proc.ptr(world + WORLD_PERSISTENT_LEVEL) else { return out };
        let Some(data) = proc.ptr(level + actors_off) else { return out };
        let count = proc.read::<i32>(level + actors_off + 8).unwrap_or(0).max(0) as usize;

        for i in 0..count.min(0x4000) {
            let Some(actor) = proc.ptr(data + i * 8) else { continue };
            let Some(cls_ptr) = proc.ptr(actor + OBJ_CLASS) else { continue };
            let cls = match cache.get(&cls_ptr) {
                Some(c) => c.clone(),
                None => {
                    let c = class_name(proc, names, actor).unwrap_or_default();
                    cache.insert(cls_ptr, c.clone());
                    c
                }
            };
            if cls.is_empty() || !want(&cls) {
                continue;
            }
            let Some(pos) = actor_location(proc, actor) else { continue };
            let name = super::display_name(proc, actor, &cls, pawn, local_name);
            let enemy = cls.contains("PartyMember") || cls.contains("Enemy");
            if let Some(b) = make_box(pos, &cam, w, h, &name, enemy) {
                out.push(b);
            }
        }
        out
    }

    fn draw_frame(hwnd: HWND, w: i32, h: i32, boxes: &[Target]) {
        unsafe {
            let hdc = GetDC(hwnd);
            let mem = CreateCompatibleDC(hdc);
            let bmp = CreateCompatibleBitmap(hdc, w, h);
            let old = SelectObject(mem, bmp as _);

            let black = CreateSolidBrush(0);
            let full = RECT { left: 0, top: 0, right: w, bottom: h };
            FillRect(mem, &full, black);
            DeleteObject(black as _);

            let green = CreatePen(PS_SOLID as i32, 2, rgb(0, 255, 0));
            let red = CreatePen(PS_SOLID as i32, 2, rgb(255, 50, 50));
            let hollow = GetStockObject(HOLLOW_BRUSH as i32);
            SelectObject(mem, hollow);
            SetBkMode(mem, TRANSPARENT as i32);

            for b in boxes {
                let pen = if b.enemy { red } else { green };
                SelectObject(mem, pen as _);
                Rectangle(mem, b.left, b.top, b.right, b.bottom);
                SetTextColor(mem, if b.enemy { rgb(255, 80, 80) } else { rgb(0, 255, 0) });
                TextOutA(mem, b.left, b.top - 14, b.label.as_ptr(), b.label.len() as i32);
            }

            BitBlt(hdc, 0, 0, w, h, mem, 0, 0, SRCCOPY);

            SelectObject(mem, old);
            DeleteObject(bmp as _);
            DeleteObject(green as _);
            DeleteObject(red as _);
            DeleteDC(mem);
            ReleaseDC(hwnd, hdc);
        }
    }

    pub fn run(ctx: Ctx, filter: Option<String>, draw_all: bool, players: bool) {
        let Ctx { proc, mut names, gworld } = ctx;
        let pid = proc.pid as u32;

        let game = find_game_window(pid).expect("could not find game window");
        eprintln!("[+] game window found");
        if players {
            eprintln!("[+] player mode: GameState.PlayerArray (skipping spectators + dead)");
        }

        // Locate ULevel::Actors once (offset is layout-constant across levels).
        let world = proc.ptr(gworld).expect("GWorld null");
        let level = proc.ptr(world + WORLD_PERSISTENT_LEVEL).expect("level null");
        let actors_off = find_actors_offset(&proc, &mut names, level).expect("Actors array not found");
        eprintln!("[+] Actors @ +{actors_off:#x}");

        let local_name = super::local_player_name(&proc, world).unwrap_or_default();
        eprintln!("[+] local player = '{local_name}'");

        let want: Predicate = match (filter, draw_all) {
            (_, true) => std::boxed::Box::new(|_: &str| true),
            (Some(f), _) => std::boxed::Box::new(move |c: &str| c.contains(&f)),
            (None, _) => std::boxed::Box::new(|c: &str| {
                c.contains("PartyMember") || c.contains("Character") || c.contains("Pawn")
            }),
        };
        eprintln!("[+] overlay running — close the game window to stop");

        let hwnd = create_overlay();
        let mut cache: HashMap<usize, String> = HashMap::new();

        loop {
            unsafe {
                let mut msg: MSG = zeroed();
                while PeekMessageA(&mut msg, null_mut(), 0, 0, PM_REMOVE) != 0 {
                    if msg.message == WM_QUIT {
                        return;
                    }
                    TranslateMessage(&msg);
                    DispatchMessageA(&msg);
                }
                if IsWindow(game) == 0 {
                    return;
                }
                let mut cr: RECT = zeroed();
                GetClientRect(game, &mut cr);
                let mut tl: POINT = zeroed();
                ClientToScreen(game, &mut tl);
                let w = cr.right - cr.left;
                let h = cr.bottom - cr.top;
                SetWindowPos(hwnd, HWND_TOPMOST, tl.x, tl.y, w, h, SWP_NOACTIVATE);

                let boxes = if players {
                    collect_player_targets(&proc, gworld, w as f64, h as f64)
                } else {
                    collect_targets(
                        &proc, &mut names, &mut cache, gworld, actors_off, w as f64, h as f64, &local_name, &want,
                    )
                };
                draw_frame(hwnd, w, h, &boxes);
            }
            std::thread::sleep(std::time::Duration::from_millis(8));
        }
    }
}
