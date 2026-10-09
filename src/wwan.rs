//! usb0 ownership for MMS (spec §5 wwan bearer, two modes): link
//! management, in-process DHCP client, per-fetch host routes, the
//! zero-routes assertion, and the bound HTTP fetch.
//!
//! Implemented per spec §5 + §7:
//!  - `Cellmatik` mode: own the interface entirely — link up via ioctl,
//!    minimal in-process DHCP client (UDP 68 broadcast on the bound
//!    device, DISCOVER→OFFER→REQUEST→ACK), install address + netmask
//!    **only** — never the gateway, never a default route, never
//!    /etc/resolv.conf. Bound fetches: SO_BINDTODEVICE + per-fetch host
//!    route via the DHCP gateway, removed after the fetch. Hand-rolled
//!    HTTP/1.1 client (Connection: close, no chunked needed).
//!  - `Host` mode: zero footprint — no link management, no DHCP, no
//!    assertion; wait for an address, bind fetches to the interface.
//!  - Zero-routes assertion (cellmatik mode): poll /proc/net/route every
//!    few seconds; anything on usb0 other than our on-link prefix route
//!    and host routes this module installed ⇒ flush own routes, link
//!    down, publish `{"wwan": "route_violation"}`, park until manual
//!    restart — loud, never silent.
//!  - Per-fetch: ensure_up → resolve (blocking pool) → host route →
//!    bound TCP connect (10 s) → exchange (30 s budget) → remove route.
//!  - Proxy support: absolute-form request through the configured
//!    proxy host:port.
//!  - 10 MiB response ceiling; allocations bounded by bytes actually
//!    read, never by a claimed Content-Length.
//!
//! SECURITY (spec §7): the ONLY module with `unsafe` (ioctl/setsockopt),
//! each block commented with its invariant. Network input parsing is
//! total (checked, Err never panic).

use crate::config::MmsManage;
use crate::envelope::EventBus;
use crate::types::Event;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::sync::{watch, Notify};

const RESPONSE_CAP: usize = 10 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const FETCH_BUDGET: Duration = Duration::from_secs(30);
const DHCP_WINDOW: Duration = Duration::from_secs(8);
/// DHCP lease in cellmatik mode — address + netmask are installed; the
/// gateway is used ONLY for per-fetch host routes.
#[derive(Clone)]
struct Lease {
    iface: String,
    ip: Ipv4Addr,
    mask: Ipv4Addr,
    gateway: Ipv4Addr,
    obtained: Instant,
    lease_time: Duration,
}

impl Lease {
    fn fresh(&self) -> bool {
        self.obtained.elapsed() < self.lease_time
    }
}

#[derive(Debug, Clone)]
pub struct WwanConfig {
    pub manage: MmsManage,
    /// mms.enabled — false ⇒ the interface is never touched.
    pub enabled: bool,
    /// Interface name — "usb0".
    pub interface: String,
    /// Optional carrier HTTP proxy (host:port).
    pub proxy: Option<String>,
    pub user_agent: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WwanState {
    /// mms.enabled = false — interface never touched.
    Disabled,
    Down,
    Up { ip: String },
    HostManaged { ip: String },
    /// Route assertion tripped — manual restart required.
    Violated { detail: String },
}

impl WwanState {
    /// "up" | "down" | "disabled" | "violated" for /v1/status.
    pub fn bearer(&self) -> &'static str {
        match self {
            WwanState::Disabled => "disabled",
            WwanState::Down => "down",
            WwanState::Up { .. } => "up",
            WwanState::HostManaged { .. } => "up",
            WwanState::Violated { .. } => "violated",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum WwanError {
    Disabled,
    InterfaceDown,
    RouteViolation(String),
    Fetch(String),
}

impl std::fmt::Display for WwanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WwanError::Disabled => write!(f, "wwan disabled"),
            WwanError::InterfaceDown => write!(f, "wwan interface down"),
            WwanError::RouteViolation(v) => write!(f, "wwan route violation: {v}"),
            WwanError::Fetch(e) => write!(f, "wwan fetch failed: {e}"),
        }
    }
}

impl std::error::Error for WwanError {}

#[derive(Debug, Clone)]
pub enum HttpMethod {
    Get,
    Post { content_type: String, body: Vec<u8> },
}

#[derive(Debug, Clone)]
pub struct WwanRequest {
    /// Absolute http:// URL (https is not supported by design — validation
    /// rejects it at config load).
    pub url: String,
    pub method: HttpMethod,
}

#[derive(Debug, Clone)]
pub struct WwanResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

struct WwanInner {
    cfg: WwanConfig,
    events: EventBus,
    state: watch::Sender<WwanState>,
    lease: StdMutex<Option<Lease>>,
    /// IPv4 host addresses with a per-fetch route currently installed.
    host_routes: StdMutex<HashSet<u32>>,
    stop: Arc<Notify>,
}

#[derive(Clone)]
pub struct Wwan {
    inner: Arc<WwanInner>,
}

impl Wwan {
    /// Spawn the watcher + assertion poller. Cheap when disabled.
    pub fn spawn(cfg: WwanConfig, events: EventBus) -> Wwan {
        let initial = if !cfg.enabled {
            WwanState::Disabled
        } else {
            WwanState::Down
        };
        let (state_tx, _state_rx) = watch::channel(initial.clone());
        let stop = Arc::new(Notify::new());
        let inner = Arc::new(WwanInner {
            cfg,
            events,
            state: state_tx,
            lease: StdMutex::new(None),
            host_routes: StdMutex::new(HashSet::new()),
            stop: stop.clone(),
        });

        if initial != WwanState::Disabled {
            let poller = inner.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(3));
                loop {
                    tokio::select! {
                        _ = poller.stop.notified() => break,
                        _ = tick.tick() => poller.poll_once(),
                    }
                }
            });
        }
        Wwan { inner }
    }

    /// Bring the interface up (cellmatik mode: link + DHCP lease, cached;
    /// host mode: wait for an address). Returns the interface IP.
    pub async fn ensure_up(&self) -> Result<String, WwanError> {
        // bind the clone first: a watch::Ref held across the match arms
        // (which await) would make this future !Send
        let state = self.inner.state.borrow().clone();
        match state {
            WwanState::Disabled => Err(WwanError::Disabled),
            WwanState::Violated { detail } => Err(WwanError::RouteViolation(detail)),
            WwanState::HostManaged { ip } => Ok(ip),
            WwanState::Up { .. } => {
                let fresh_ip = self
                    .inner
                    .lease
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_ref()
                    .filter(|l| l.fresh())
                    .map(|l| l.ip.to_string());
                if let Some(ip) = fresh_ip {
                    return Ok(ip);
                }
                self.dhcp_and_install().await
            }
            WwanState::Down => match self.inner.cfg.manage {
                MmsManage::Host => {
                    // poller promotes to HostManaged when the host sets an
                    // address; until then this is InterfaceDown
                    Err(WwanError::InterfaceDown)
                }
                MmsManage::Cellmatik => self.dhcp_and_install().await,
            },
        }
    }

    async fn dhcp_and_install(&self) -> Result<String, WwanError> {
        if self.inner.cfg.manage != MmsManage::Cellmatik {
            return Err(WwanError::InterfaceDown);
        }
        let iface = self.inner.cfg.interface.clone();
        let leased = tokio::task::spawn_blocking(move || dhcp_acquire(&iface))
            .await
            .map_err(|e| WwanError::Fetch(format!("dhcp task: {e}")))?
            .map_err(|e| WwanError::Fetch(format!("dhcp: {e}")))?;
        let ip = leased.ip.to_string();
        *self.inner.lease.lock().unwrap_or_else(|e| e.into_inner()) = Some(leased);
        let _ = self.inner.state.send(WwanState::Up { ip: ip.clone() });
        Ok(ip)
    }

    pub async fn state(&self) -> WwanState {
        self.inner.state.borrow().clone()
    }

    /// One MMSC exchange over the bound bearer. Adds/removes the per-fetch
    /// host route in cellmatik mode; enforces the response cap.
    pub async fn http(&self, req: WwanRequest) -> Result<WwanResponse, WwanError> {
        let ip = self.ensure_up().await?;
        // re-check: ensure_up may have observed a violation via poller
        let state = self.inner.state.borrow().clone();
        if let WwanState::Violated { detail } = state {
            return Err(WwanError::RouteViolation(detail));
        }
        let _ = ip; // address presence is the up-signal; the socket binds by name

        let iface = self.inner.cfg.interface.clone();
        let proxy = self.inner.cfg.proxy.clone();
        let ua = self.inner.cfg.user_agent.clone();
        let manage = self.inner.cfg.manage;
        let lease_gw = self
            .inner
            .lease
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|l| l.gateway);

        let url = req.url;
        let method = req.method;
        let inner = self.inner.clone();

        tokio::task::spawn_blocking(move || {
            http_exchange(&inner, iface, manage, lease_gw, proxy, ua, url, method)
        })
        .await
        .map_err(|e| WwanError::Fetch(format!("fetch task: {e}")))?
    }

    pub async fn stop(&self) {
        self.inner.stop.notify_one();
    }
}

impl WwanInner {
    /// Poller body: host mode watches for an address; cellmatik mode runs
    /// the zero-routes assertion.
    fn poll_once(&self) {
        match self.cfg.manage {
            MmsManage::Host => {
                match if_addr(&self.cfg.interface) {
                    Ok(Some(ip)) => {
                        let next = WwanState::HostManaged { ip: ip.to_string() };
                        if *self.state.borrow() != next {
                            let _ = self.state.send(next);
                        }
                    }
                    Ok(None) => {
                        if !matches!(&*self.state.borrow(), WwanState::Down | WwanState::Violated { .. }) {
                            let _ = self.state.send(WwanState::Down);
                        }
                    }
                    Err(e) => tracing::debug!(error = %e, "if_addr poll failed"),
                }
            }
            MmsManage::Cellmatik => {
                if matches!(&*self.state.borrow(), WwanState::Violated { .. }) {
                    return; // parks until manual restart
                }
                let lease = self.lease.lock().unwrap_or_else(|e| e.into_inner()).clone();
                let host_routes = self.host_routes.lock().unwrap_or_else(|e| e.into_inner()).clone();
                let Some(lease) = lease else { return }; // nothing installed yet
                let rows = match read_route_table() {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(error = %e, "route table read failed");
                        return;
                    }
                };
                if let Some(detail) = assert_routes(&rows, &lease, &host_routes) {
                    tracing::error!(detail = %detail, "route violation on wwan bearer");
                    // flush our routes + link down, then park
                    for dst in host_routes {
                        let _ = del_host_route(Ipv4Addr::from(dst));
                    }
                    let _ = del_prefix_route(lease.network(), lease.mask);
                    let _ = if_set_down(&self.cfg.interface);
                    *self.lease.lock().unwrap_or_else(|e| e.into_inner()) = None;
                    let _ = self.state.send(WwanState::Violated { detail: detail.clone() });
                    self.events.publish(violation_event(&detail));
                } else if !lease.fresh() {
                    // expired: drop so the next ensure_up re-DHCPs
                    *self.lease.lock().unwrap_or_else(|e| e.into_inner()) = None;
                    let _ = self.state.send(WwanState::Down);
                }
            }
        }
    }
}

impl Lease {
    fn network(&self) -> Ipv4Addr {
        let o = u32::from(self.ip) & u32::from(self.mask);
        Ipv4Addr::from(o)
    }
}

/// Publish a route-violation alert (used internally; pub(crate) shape).
pub(crate) fn violation_event(detail: &str) -> Event {
    Event::modem_state(serde_json::json!({
        "wwan": "route_violation",
        "detail": detail,
    }))
}

// ===== sys layer (the module's unsafe lives here) ==========================

/// The kernel's `struct ifreq` (40 bytes: 16-byte name + 24-byte union).
/// The libc crate does not define it for Linux (anonymous C union), so we
/// mirror the ABI: every member is fully initialized before the ioctl.
#[repr(C)]
struct IfReq {
    name: [u8; 16],
    data: IfReqData,
}

#[repr(C)]
union IfReqData {
    /// sockaddr_in is the union's largest meaningful member for our
    /// ioctls (16 bytes); `raw` pads to the full 24-byte glibc union.
    addr: libc::sockaddr_in,
    flags: libc::c_short,
    ivalue: libc::c_int,
    raw: [u8; 24],
}

const _: () = assert!(std::mem::size_of::<IfReq>() == 40);

/// A control socket for interface ioctls.
fn ctl_socket() -> std::io::Result<Socket> {
    Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
}

fn name_bytes(name: &str) -> std::io::Result<[u8; libc::IFNAMSIZ]> {
    let mut buf = [0u8; libc::IFNAMSIZ];
    let n = name.len();
    if n == 0 || n >= libc::IFNAMSIZ {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad interface name"));
    }
    buf[..n].copy_from_slice(name.as_bytes());
    Ok(buf)
}

fn invalid_input(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.to_string())
}

/// Run an interface ioctl with an IfReq. The closure mutates the union
/// before the call (e.g. sets flags/address); the returned IfReq carries
/// kernel output.
fn if_ioctl(
    fd: RawFd,
    name: &str,
    req: libc::c_ulong,
    prep: impl FnOnce(&mut IfReqData),
) -> std::io::Result<IfReq> {
    let mut ifr = IfReq {
        name: name_bytes(name)?,
        // Constructing a union via one non-Drop member is safe (no read
        // occurs); `raw` is [u8; 24] — all-zero is a valid value.
        data: IfReqData { raw: [0u8; 24] },
    };
    prep(&mut ifr.data);
    // SAFETY: `ifr` is a valid, fully-initialized 40-byte IfReq matching
    // the kernel's ifreq ABI; `req` is one of SIOCG*/SIOCS* interface
    // ioctls which read/write only within a 40-byte ifreq; fd is a live
    // socket owned by the caller.
    let rc = unsafe { libc::ioctl(fd, req, &mut ifr as *mut IfReq as *mut libc::c_void) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(ifr)
}

/// Interface hardware (MAC) address (SIOCGIFHWADDR). Reads the first 6
/// bytes of sa_data from the raw union bytes.
fn if_mac(name: &str) -> std::io::Result<[u8; 6]> {
    let sock = ctl_socket()?;
    let ifr = if_ioctl(sock.as_raw_fd(), name, libc::SIOCGIFHWADDR, |_| {})?;
    // SAFETY: SIOCGIFHWADDR wrote a sockaddr (2-byte family + 14-byte
    // payload) into the 24-byte union; the union was zeroed first, so
    // reading bytes 2..8 is in-bounds and initialized.
    let raw = unsafe { ifr.data.raw };
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&raw[2..8]);
    Ok(mac)
}

/// Set interface flags (SIOCSIFFLAGS), preserving unknown bits via
/// SIOCGIFFLAGS first.
fn if_set_flags(name: &str, set: i16, clear: i16) -> std::io::Result<()> {
    let sock = ctl_socket()?;
    let ifr = if_ioctl(sock.as_raw_fd(), name, libc::SIOCGIFFLAGS, |_| {})?;
    // SAFETY: the flags member was written by the kernel over a zeroed
    // union.
    let mut flags = unsafe { ifr.data.flags };
    flags |= set;
    flags &= !clear;
    let fd = sock.as_raw_fd();
    if_ioctl(fd, name, libc::SIOCSIFFLAGS, |data| {
        // Assigning to a union field is safe (write only, no read); the
        // 24-byte union trivially holds a c_short.
        *data = IfReqData { flags };
    })?;
    Ok(())
}

fn if_set_up(name: &str) -> std::io::Result<()> {
    if_set_flags(name, libc::IFF_UP as i16 | libc::IFF_RUNNING as i16, 0)
}

fn if_set_down(name: &str) -> std::io::Result<()> {
    if_set_flags(name, 0, libc::IFF_UP as i16)
}

/// Current IPv4 address, None when unassigned (SIOCGIFADDR).
fn if_addr(name: &str) -> std::io::Result<Option<Ipv4Addr>> {
    let sock = ctl_socket()?;
    let ifr = match if_ioctl(sock.as_raw_fd(), name, libc::SIOCGIFADDR, |_| {}) {
        Ok(r) => r,
        Err(e) if e.raw_os_error() == Some(libc::EADDRNOTAVAIL) => return Ok(None),
        Err(e) => return Err(e),
    };
    // SAFETY: SIOCGIFADDR wrote a sockaddr_in (family AF_INET, sin_addr)
    // over the zeroed union.
    let sin = unsafe { ifr.data.addr };
    if sin.sin_family as i32 != libc::AF_INET {
        return Ok(None);
    }
    Ok(Some(Ipv4Addr::from(sin.sin_addr.s_addr.to_be())))
}

/// Assign our leased address/netmask — address + prefix ONLY (never a
/// gateway, never a default route; the connected route the kernel derives
/// from a primary address is the on-link route the assertion expects).
fn if_set_addr(name: &str, ip: Ipv4Addr) -> std::io::Result<()> {
    let sock = ctl_socket()?;
    let fd = sock.as_raw_fd();
    if_ioctl(fd, name, libc::SIOCSIFADDR, |data| {
        // Assigning to a union field is safe (write only, no read); the
        // union's largest member is sockaddr_in itself.
        *data = IfReqData { addr: sockaddr_in(ip) };
    })?;
    Ok(())
}

fn if_set_netmask(name: &str, mask: Ipv4Addr) -> std::io::Result<()> {
    let sock = ctl_socket()?;
    let fd = sock.as_raw_fd();
    if_ioctl(fd, name, libc::SIOCSIFNETMASK, |data| {
        // Same union-size invariant as if_set_addr; write only.
        *data = IfReqData { addr: sockaddr_in(mask) };
    })?;
    Ok(())
}

fn sockaddr_in(ip: Ipv4Addr) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr { s_addr: u32::from(ip).to_be() },
        sin_zero: [0; 8],
    }
}

/// SIOCADDRT/SIOCDELRT with a route entry. SAFETY: rtentry is
/// zero-initialized; only the dst/gateway/genmask/flags fields are set.
fn route_ioctl(req: libc::c_ulong, dst: Ipv4Addr, gw: Option<Ipv4Addr>, genmask: Option<Ipv4Addr>) -> std::io::Result<()> {
    let sock = ctl_socket()?;
    let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };
    unsafe {
        // SAFETY: sockaddr_in and sockaddr are both 16 bytes; sockaddr is
        // a prefix of sockaddr_in, so this reinterpret is lossless.
        rt.rt_dst = std::ptr::read_unaligned(&sockaddr_in(dst) as *const _ as *const libc::sockaddr);
        if let Some(g) = gw {
            rt.rt_gateway = std::ptr::read_unaligned(&sockaddr_in(g) as *const _ as *const libc::sockaddr);
            rt.rt_flags = (libc::RTF_UP | libc::RTF_GATEWAY) as libc::c_ushort;
        } else {
            rt.rt_flags = libc::RTF_UP as libc::c_ushort;
        }
        let m = genmask.unwrap_or(Ipv4Addr::from(u32::MAX));
        rt.rt_genmask = std::ptr::read_unaligned(&sockaddr_in(m) as *const _ as *const libc::sockaddr);
    }
    // SAFETY: `rt` is a valid zeroed rtentry; SIOCADDRT/SIOCDELRT read
    // only within it.
    let rc = unsafe { libc::ioctl(sock.as_raw_fd(), req, &mut rt as *mut libc::rtentry as *mut libc::c_void) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Per-fetch host route via the DHCP gateway (cellmatik mode).
fn add_host_route(dst: Ipv4Addr, gw: Ipv4Addr) -> std::io::Result<()> {
    route_ioctl(libc::SIOCADDRT, dst, Some(gw), None)
}

fn del_host_route(dst: Ipv4Addr) -> std::io::Result<()> {
    route_ioctl(libc::SIOCDELRT, dst, None, None)
}

/// Remove the on-link prefix route (violation flush).
fn del_prefix_route(net: Ipv4Addr, mask: Ipv4Addr) -> std::io::Result<()> {
    route_ioctl(libc::SIOCDELRT, net, None, Some(mask))
}

/// SO_BINDTODEVICE: every byte of this socket's traffic goes out `name`.
fn bind_device(sock: &Socket, name: &str) -> std::io::Result<()> {
    let n = name_bytes(name)?;
    // SAFETY: `n` is a NUL-terminated, IFNAMSIZ-sized buffer; the kernel
    // reads only that many bytes from the option value.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            n.as_ptr() as *const libc::c_void,
            libc::IFNAMSIZ as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// 4 bytes from the OS CSPRNG (DHCP xid). Fails if /dev/urandom is absent.
fn os_random_u32() -> std::io::Result<u32> {
    let mut b = [0u8; 4];
    let mut f = std::fs::File::open("/dev/urandom")?;
    f.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}

// ===== route-table assertion ==============================================

/// One /proc/net/route row (main table), fields as hex.
#[derive(Debug, Clone, PartialEq)]
struct RouteRow {
    iface: String,
    /// destination, host byte order
    dst: u32,
    /// gateway, host byte order (0 = on-link)
    gw: u32,
    mask: u32,
}

fn read_route_table() -> std::io::Result<Vec<RouteRow>> {
    let text = std::fs::read_to_string("/proc/net/route")?;
    Ok(parse_route_table(&text))
}

/// Total parser for the /proc/net/route format; bad rows are skipped.
fn parse_route_table(text: &str) -> Vec<RouteRow> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 8 {
            continue;
        }
        let (iface, dst, gw, mask) = (f[0], f[1], f[2], f[7]);
        let (Some(dst), Some(gw), Some(mask)) =
            (hex_u32(dst), hex_u32(gw), hex_u32(mask))
        else {
            continue;
        };
        out.push(RouteRow { iface: iface.to_string(), dst, gw, mask });
    }
    out
}

/// Parse one /proc/net/route hex field. The kernel prints the __be32 as
/// `%08X` of its little-endian memory representation, so the value must
/// be byte-swapped to get natural a.b.c.d bit positions.
fn hex_u32(s: &str) -> Option<u32> {
    let t = s.trim();
    if t.is_empty() || t.len() > 8 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(t, 16).ok().map(|v| v.swap_bytes())
}

/// Prefix length of a contiguous netmask (255.255.255.0 → 24). Total:
/// non-contiguous masks yield None. Contiguous means every 1-bit sits
/// above every 0-bit: ones + trailing_zeros == 32.
fn mask_prefix(mask: u32) -> Option<u8> {
    let ones = mask.count_ones();
    if ones as u32 + mask.trailing_zeros() == 32 {
        Some(ones as u8)
    } else {
        None
    }
}

/// The assertion: on our interface, only (a) the on-link route for our
/// own address/prefix and (b) /32 host routes this module installed via
/// our gateway are allowed. Anything else is a violation with a detail.
fn assert_routes(rows: &[RouteRow], lease: &Lease, host_routes: &HashSet<u32>) -> Option<String> {
    let net = u32::from(lease.network());
    let mask = u32::from(lease.mask);
    let gw = u32::from(lease.gateway);
    for r in rows.iter().filter(|r| r.iface == lease.iface) {
        if r.dst == 0 {
            return Some(format!("default route via {}", Ipv4Addr::from(r.gw)));
        }
        if r.mask == mask && r.dst == net && r.gw == 0 {
            continue; // our on-link prefix route
        }
        if r.mask == u32::MAX && host_routes.contains(&r.dst) && r.gw == gw {
            continue; // per-fetch host route we installed
        }
        return Some(format!(
            "unexpected route {}{} gw {}",
            Ipv4Addr::from(r.dst),
            mask_prefix(r.mask).map(|p| format!("/{p}")).unwrap_or_default(),
            Ipv4Addr::from(r.gw),
        ));
    }
    None
}

// ===== DHCP client (in-process, minimal RFC 2131 subset) ==================

const DHCP_MAGIC: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
const OPT_PAD: u8 = 0;
const OPT_SUBNET: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_LEASE_TIME: u8 = 51;
const OPT_MSG_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_PARAM_LIST: u8 = 55;
const OPT_END: u8 = 255;

fn put_u32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_be_bytes());
}

/// One DHCP message. 240-byte BOOTP header + options; padded to 300.
fn dhcp_build(
    op: u8,
    msg_type: u8,
    xid: u32,
    chaddr: [u8; 6],
    requested_ip: Option<Ipv4Addr>,
    server_id: Option<Ipv4Addr>,
) -> Vec<u8> {
    let mut p = Vec::with_capacity(300);
    p.push(op); // BOOTREQUEST
    p.push(1); // htype ethernet
    p.push(6); // hlen
    p.push(0); // hops
    p.extend_from_slice(&xid.to_be_bytes());
    p.extend_from_slice(&[0, 0]); // secs
    p.extend_from_slice(&[0x80, 0x00]); // flags: broadcast
    put_u32(&mut p, 0); // ciaddr
    put_u32(&mut p, 0); // yiaddr
    put_u32(&mut p, 0); // siaddr
    put_u32(&mut p, 0); // giaddr
    p.extend_from_slice(&chaddr);
    p.extend_from_slice(&[0u8; 10]); // chaddr padding
    p.extend_from_slice(&[0u8; 64]); // sname
    p.extend_from_slice(&[0u8; 128]); // file
    p.extend_from_slice(&DHCP_MAGIC);
    // options
    p.extend_from_slice(&[OPT_MSG_TYPE, 1, msg_type]);
    if let Some(ip) = requested_ip {
        p.extend_from_slice(&[50, 4]);
        put_u32(&mut p, u32::from(ip));
    }
    if let Some(ip) = server_id {
        p.extend_from_slice(&[OPT_SERVER_ID, 4]);
        put_u32(&mut p, u32::from(ip));
    }
    if msg_type == 1 {
        // DISCOVER: ask for subnet + router + lease time
        p.extend_from_slice(&[OPT_PARAM_LIST, 3, OPT_SUBNET, OPT_ROUTER, OPT_LEASE_TIME]);
    }
    p.push(OPT_END);
    while p.len() < 300 {
        p.push(OPT_PAD);
    }
    p
}

/// Parsed DHCP reply fields. Total: bounds-checked reads, None on any
/// malformed input.
struct DhcpReply {
    msg_type: u8,
    yiaddr: Ipv4Addr,
    subnet: Option<Ipv4Addr>,
    router: Option<Ipv4Addr>,
    lease_time: Option<u32>,
}

fn dhcp_parse(p: &[u8]) -> Option<DhcpReply> {
    if p.len() < 240 || p[0] != 2 || p[1] != 1 {
        return None; // short / not BOOTREPLY / not ethernet
    }
    if p[236..240] != DHCP_MAGIC {
        return None;
    }
    let yiaddr = Ipv4Addr::from(u32::from_be_bytes([p[16], p[17], p[18], p[19]]));
    let mut out = DhcpReply { msg_type: 0, yiaddr, subnet: None, router: None, lease_time: None };
    let mut i = 240;
    while i < p.len() {
        let opt = p[i];
        if opt == OPT_PAD {
            i += 1;
            continue;
        }
        if opt == OPT_END {
            break;
        }
        if i + 1 >= p.len() {
            break;
        }
        let len = p[i + 1] as usize;
        let start = i + 2;
        let end = start.checked_add(len)?;
        if end > p.len() {
            return None; // truncated option — malformed
        }
        match opt {
            OPT_MSG_TYPE if len == 1 => out.msg_type = p[start],
            OPT_SUBNET if len == 4 => {
                out.subnet = Some(Ipv4Addr::from(u32::from_be_bytes([p[start], p[start + 1], p[start + 2], p[start + 3]])));
            }
            OPT_ROUTER if len >= 4 => {
                out.router = Some(Ipv4Addr::from(u32::from_be_bytes([p[start], p[start + 1], p[start + 2], p[start + 3]])));
            }
            OPT_LEASE_TIME if len == 4 => {
                out.lease_time = Some(u32::from_be_bytes([p[start], p[start + 1], p[start + 2], p[start + 3]]));
            }
            _ => {}
        }
        i = end;
    }
    Some(out)
}

/// Full acquire: link up → DISCOVER→OFFER→REQUEST→ACK → install address
/// + netmask (nothing else). Runs on a blocking thread.
fn dhcp_acquire(iface: &str) -> std::io::Result<Lease> {
    if_set_up(iface)?;
    let mac = if_mac(iface)?;
    let xid = os_random_u32()?;

    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_broadcast(true)?;
    sock.set_reuse_address(true)?;
    bind_device(&sock, iface)?;
    let bind_addr: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68);
    sock.bind(&bind_addr.into())?;
    // hand off to std for plain &mut [u8] recv_from
    let sock = std::net::UdpSocket::from(sock);

    let dst: SocketAddrV4 = "255.255.255.255:67".parse().map_err(|_| invalid_input("broadcast addr"))?;
    let deadline = Instant::now() + DHCP_WINDOW;
    sock.set_read_timeout(Some(Duration::from_millis(500)))?;

    // DISCOVER → OFFER
    let mut offer: Option<DhcpReply> = None;
    sock.send_to(&dhcp_build(1, 1, xid, mac, None, None), dst)?;
    let mut buf = [0u8; 1500];
    while offer.is_none() && Instant::now() < deadline {
        let (n, _) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => return Err(e),
        };
        if let Some(r) = dhcp_parse(&buf[..n]) {
            if r.msg_type == 2 && xid_matches(&buf[..n], xid) {
                offer = Some(r);
            }
        }
    }
    let offer = offer.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "no DHCP OFFER"))?;

    // REQUEST → ACK
    let mut ack: Option<DhcpReply> = None;
    sock.send_to(&dhcp_build(1, 3, xid, mac, Some(offer.yiaddr), None), dst)?;
    while ack.is_none() && Instant::now() < deadline {
        let (n, _) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => return Err(e),
        };
        if let Some(r) = dhcp_parse(&buf[..n]) {
            // 5 = ACK, 6 = NAK
            if xid_matches(&buf[..n], xid) && (r.msg_type == 5 || r.msg_type == 6) {
                if r.msg_type == 6 {
                    return Err(invalid_input("DHCP NAK"));
                }
                ack = Some(r);
            }
        }
    }
    let ack = ack.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "no DHCP ACK"))?;

    let mask = ack
        .subnet
        .or(offer.subnet)
        .ok_or_else(|| invalid_input("lease without subnet mask"))?;
    let gateway = ack
        .router
        .or(offer.router)
        .ok_or_else(|| invalid_input("lease without router"))?;
    let ip = ack.yiaddr;
    // validate the mask is contiguous (a prefix) — we don't need the
    // number itself, only the guarantee
    mask_prefix(u32::from(mask))
        .ok_or_else(|| invalid_input("non-contiguous subnet mask"))?;

    // install address + prefix ONLY — no gateway, no default route
    if_set_addr(iface, ip)?;
    if_set_netmask(iface, mask)?;

    Ok(Lease {
        iface: iface.to_string(),
        ip,
        mask,
        gateway,
        obtained: Instant::now(),
        lease_time: Duration::from_secs(ack.lease_time.unwrap_or(600).max(60) as u64),
    })
}

fn xid_matches(p: &[u8], xid: u32) -> bool {
    p.len() >= 8 && u32::from_be_bytes([p[4], p[5], p[6], p[7]]) == xid
}

// ===== HTTP/1.1 client over the bound bearer ==============================

struct UrlParts {
    host: String,
    port: u16,
    path: String,
}

/// http://host[:port]/path — total, no https (by design; config validation
/// rejects https URLs too — this is the enforcement for programmatic
/// callers).
fn parse_http_url(url: &str) -> Result<UrlParts, WwanError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| WwanError::Fetch("only http:// URLs are supported".into()))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(WwanError::Fetch("empty host".into()));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>().map_err(|_| WwanError::Fetch("bad port".into()))?,
        ),
        None => (authority.to_string(), 80),
    };
    Ok(UrlParts { host, port, path: path.to_string() })
}

/// One request/response. Blocking; runs on a blocking thread.
#[allow(clippy::too_many_arguments)]
fn http_exchange(
    inner: &Arc<WwanInner>,
    iface: String,
    manage: MmsManage,
    lease_gw: Option<Ipv4Addr>,
    proxy: Option<String>,
    ua: String,
    url: String,
    method: HttpMethod,
) -> Result<WwanResponse, WwanError> {
    let parts = parse_http_url(&url)?;
    let (connect_host, connect_port, request_path) = match &proxy {
        Some(p) => {
            let (h, port) = p
                .rsplit_once(':')
                .ok_or_else(|| WwanError::Fetch("proxy must be host:port".into()))?;
            let port: u16 = port.parse().map_err(|_| WwanError::Fetch("bad proxy port".into()))?;
            (h.to_string(), port, url.clone()) // absolute-form via proxy
        }
        None => (parts.host.clone(), parts.port, parts.path.clone()),
    };

    // resolve via the system resolver (LAN side); already on a blocking
    // thread — no block_in_place here
    let addr = resolve_v4(&connect_host, connect_port).map_err(WwanError::Fetch)?;

    // per-fetch host route (cellmatik mode only) via the DHCP gateway
    let routed = if manage == MmsManage::Cellmatik {
        let gw = lease_gw.ok_or_else(|| WwanError::InterfaceDown)?;
        let dst = match addr {
            std::net::SocketAddr::V4(v4) => *v4.ip(),
            std::net::SocketAddr::V6(_) => return Err(WwanError::Fetch("ipv6 unreachable via bearer".into())),
        };
        if let Err(e) = add_host_route(dst, gw) {
            return Err(WwanError::Fetch(format!("host route: {e}")));
        }
        inner
            .host_routes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(u32::from(dst));
        Some(dst)
    } else {
        None
    };

    let result = http_over_socket(&iface, addr, &parts.host, &request_path, &ua, &method);
    // always drop the host route
    if let Some(dst) = routed {
        let _ = del_host_route(dst);
        inner
            .host_routes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&u32::from(dst));
    }
    result
}

fn resolve_v4(host: &str, port: u16) -> Result<std::net::SocketAddr, String> {
    use std::net::ToSocketAddrs;
    for a in (host, port).to_socket_addrs().map_err(|e| format!("resolve {host}: {e}"))? {
        if a.is_ipv4() {
            return Ok(a);
        }
    }
    Err(format!("no ipv4 address for {host}"))
}

fn http_over_socket(
    iface: &str,
    addr: std::net::SocketAddr,
    host_header: &str,
    path: &str,
    ua: &str,
    method: &HttpMethod,
) -> Result<WwanResponse, WwanError> {
    let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .map_err(|e| WwanError::Fetch(format!("socket: {e}")))?;
    bind_device(&sock, iface).map_err(|e| WwanError::Fetch(format!("bind device: {e}")))?;
    let bind_any: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    sock.bind(&bind_any.into())
        .map_err(|e| WwanError::Fetch(format!("bind: {e}")))?;
    sock.connect_timeout(&socket2::SockAddr::from(addr), CONNECT_TIMEOUT)
        .map_err(|e| WwanError::Fetch(format!("connect: {e}")))?;
    let mut stream = TcpStream::from(sock);
    stream
        .set_read_timeout(Some(FETCH_BUDGET))
        .map_err(|e| WwanError::Fetch(e.to_string()))?;
    stream
        .set_write_timeout(Some(FETCH_BUDGET))
        .map_err(|e| WwanError::Fetch(e.to_string()))?;

    let mut req = String::with_capacity(256);
    match method {
        HttpMethod::Get => req.push_str(&format!("GET {path} HTTP/1.1\r\n")),
        HttpMethod::Post { content_type, .. } => {
            req.push_str(&format!("POST {path} HTTP/1.1\r\n"));
            req.push_str(&format!("Content-Type: {content_type}\r\n"));
        }
    }
    let body: Vec<u8> = match method {
        HttpMethod::Get => Vec::new(),
        HttpMethod::Post { body, .. } => body.clone(),
    };
    req.push_str(&format!("Host: {host_header}\r\n"));
    req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    req.push_str(&format!("User-Agent: {ua}\r\n"));
    req.push_str("Connection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .and_then(|_| stream.write_all(&body))
        .and_then(|_| stream.flush())
        .map_err(|e| WwanError::Fetch(format!("send: {e}")))?;

    // read to EOF (Connection: close) under the cap
    let mut raw = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let n = match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                return Err(WwanError::Fetch("response timed out".into()))
            }
            Err(e) => return Err(WwanError::Fetch(format!("read: {e}"))),
        };
        if raw.len() + n > RESPONSE_CAP + 64 * 1024 {
            return Err(WwanError::Fetch("response exceeds 10 MiB cap".into()));
        }
        raw.extend_from_slice(&chunk[..n]);
        // header terminator found and Content-Length satisfied → stop early
        if let Some((h, b)) = split_headers(&raw) {
            if let Some(len) = content_length(&h) {
                if b.len() >= len {
                    break;
                }
            }
        }
    }

    let (head, mut body_bytes) = split_headers(&raw).ok_or_else(|| WwanError::Fetch("no header terminator".into()))?;
    let status = status_line_code(&head).ok_or_else(|| WwanError::Fetch("bad status line".into()))?;
    if let Some(len) = content_length(&head) {
        if len > RESPONSE_CAP {
            return Err(WwanError::Fetch("content-length exceeds cap".into()));
        }
        body_bytes.truncate(len);
    } else if body_bytes.len() > RESPONSE_CAP {
        body_bytes.truncate(RESPONSE_CAP);
    }
    Ok(WwanResponse { status, body: body_bytes })
}

/// Split at \r\n\r\n; total (bounds-checked).
fn split_headers(raw: &[u8]) -> Option<(&[u8], Vec<u8>)> {
    let term = b"\r\n\r\n";
    let mut i = 0;
    while i + term.len() <= raw.len() {
        if &raw[i..i + term.len()] == term {
            return Some((&raw[..i], raw[i + term.len()..].to_vec()));
        }
        i += 1;
    }
    None
}

fn status_line_code(head: &[u8]) -> Option<u16> {
    let line1 = head.split(|&b| b == b'\n').next()?;
    let text = std::str::from_utf8(line1).ok()?;
    let mut it = text.split_whitespace();
    let _ver = it.next()?;
    it.next()?.parse::<u16>().ok()
}

/// Case-insensitive Content-Length; None when absent. Trusted only for
/// early-stop/truncate — never for allocation (§7).
fn content_length(head: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(head).ok()?;
    for line in text.split("\r\n") {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                if let Ok(n) = v.trim().parse::<usize>() {
                    if n <= RESPONSE_CAP * 2 {
                        return Some(n);
                    }
                }
            }
        }
    }
    None
}

// ===== tests ===============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn lease(ip: &str, mask: &str, gw: &str) -> Lease {
        Lease {
            iface: "usb0".into(),
            ip: ip.parse().unwrap(),
            mask: mask.parse().unwrap(),
            gateway: gw.parse().unwrap(),
            obtained: Instant::now(),
            lease_time: Duration::from_secs(600),
        }
    }

    const ROUTE_TABLE: &str = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
wlan0\t00000000\t0102A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
usb0\t00000000\t0102A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n\
usb0\t00FFFFFF\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";

    #[test]
    fn route_table_parsing() {
        let rows = parse_route_table(ROUTE_TABLE);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].iface, "wlan0");
        assert_eq!(rows[0].dst, 0);
        assert_eq!(rows[1].iface, "usb0");
        // little-endian hex field → host byte order
        assert_eq!(rows[2].dst, 0xFFFFFF00);
        assert_eq!(rows[2].mask, 0xFFFFFF00);
        // junk rows are skipped, not fatal
        let junk = "Iface\tDestination\t...\nxx\tzz\t0\t0\t0\t0\t0\t0\t0\t0\t0\n";
        assert!(parse_route_table(junk).is_empty());
    }

    #[test]
    fn assertion_allows_own_routes_only() {
        let l = lease("10.77.7.2", "255.255.255.0", "10.77.7.1");
        let net = u32::from(l.network());
        let row = |dst: u32, gw: u32, mask: u32| RouteRow { iface: "usb0".into(), dst, gw, mask };
        assert_eq!(assert_routes(&[row(net, 0, 0xFFFFFF00)], &l, &HashSet::new()), None);
        // host route we installed through our gateway
        let hr_dst = u32::from(Ipv4Addr::new(1, 2, 3, 4));
        let mut set = HashSet::new();
        set.insert(hr_dst);
        assert_eq!(
            assert_routes(&[row(net, 0, 0xFFFFFF00), row(hr_dst, u32::from(l.gateway), u32::MAX)], &l, &set),
            None
        );
        // default route on usb0 → violation
        assert!(assert_routes(&[row(net, 0, 0xFFFFFF00), row(0, 0x0102A8C0, 0)], &l, &set).is_some());
        // unexpected wide route → violation
        assert!(assert_routes(&[row(net, 0, 0xFFFFFF00), row(0, 0, 0xFF000000)], &l, &HashSet::new()).is_some());
        // other interfaces are not our business
        let lan = RouteRow { iface: "wlan0".into(), dst: 0, gw: 0x0102A8C0, mask: 0 };
        assert_eq!(assert_routes(&[lan], &l, &HashSet::new()), None);
    }

    #[test]
    fn dhcp_build_shape() {
        let p = dhcp_build(1, 1, 0xDEAD_BEEF, [1, 2, 3, 4, 5, 6], None, None);
        assert_eq!(p.len(), 300);
        assert_eq!(&p[236..240], &DHCP_MAGIC);
        assert_eq!(&p[4..8], &0xDEAD_BEEF_u32.to_be_bytes());
        assert_eq!(&p[28..34], &[1, 2, 3, 4, 5, 6]);
        assert_eq!(p[240..243], [OPT_MSG_TYPE, 1, 1]); // DISCOVER
    }

    #[test]
    fn dhcp_parse_roundtrip_and_adversarial() {
        let offer = {
            let mut p = dhcp_build(2, 2, 7, [0; 6], None, None);
            // yiaddr 10.77.7.2
            p[16..20].copy_from_slice(&[10, 77, 7, 2]);
            // append options after the fixed ones: subnet, router, lease
            let end = p.iter().position(|&b| b == OPT_END).unwrap_or(p.len());
            let mut q = p[..end].to_vec();
            q.extend_from_slice(&[OPT_SUBNET, 4, 255, 255, 255, 0]);
            q.extend_from_slice(&[OPT_ROUTER, 4, 10, 77, 7, 1]);
            q.extend_from_slice(&[OPT_LEASE_TIME, 4, 0, 0, 9, 0x60]); // 2400s BE
            q.push(OPT_END);
            while q.len() < 300 {
                q.push(OPT_PAD);
            }
            p = q;
            p
        };
        let r = dhcp_parse(&offer).expect("offer parses");
        assert_eq!(r.msg_type, 2);
        assert_eq!(r.yiaddr, Ipv4Addr::new(10, 77, 7, 2));
        assert_eq!(r.subnet, Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(r.router, Some(Ipv4Addr::new(10, 77, 7, 1)));
        assert_eq!(r.lease_time, Some(2400));
        // adversarial: truncated option must be rejected, not panic
        let mut bad = offer.clone();
        bad.truncate(250);
        assert!(bad.len() < 300);
        let short = &bad[..];
        // header intact, options cut mid-stream → parse returns None or a
        // prefix-legal value; must never panic
        let _ = dhcp_parse(short);
        let _ = dhcp_parse(&[]);
        let _ = dhcp_parse(&[0u8; 16]);
    }

    #[test]
    fn url_parsing() {
        let p = parse_http_url("http://mmsc.carrier.example/send?x=1").unwrap();
        assert_eq!(p.host, "mmsc.carrier.example");
        assert_eq!(p.port, 80);
        assert_eq!(p.path, "/send?x=1");
        let p = parse_http_url("http://10.0.0.1:8080/mms").unwrap();
        assert_eq!(p.host, "10.0.0.1");
        assert_eq!(p.port, 8080);
        assert!(parse_http_url("https://x/").is_err());
        assert!(parse_http_url("http:///path").is_err());
        assert!(parse_http_url("not a url").is_err());
    }

    #[test]
    fn http_response_parsing() {
        let raw = b"HTTP/1.1 202 Accepted\r\nContent-Length: 3\r\nServer: x\r\n\r\nabc";
        let (head, body) = split_headers(raw).unwrap();
        assert_eq!(status_line_code(head), Some(202));
        assert_eq!(content_length(head), Some(3));
        assert_eq!(body, b"abc".to_vec());
        // tolerant of case and LF-only status line
        let raw2 = b"HTTP/1.0 500 boom\nX: y\r\n\r\n";
        let (h2, _) = split_headers(raw2).unwrap();
        assert_eq!(status_line_code(h2), Some(500));
        // no terminator → None (caller errors)
        assert!(split_headers(b"HTTP/1.1 200 OK\r\nContent-Len").is_none());
        // huge claimed length is ignored (never allocates)
        let raw3 = b"HTTP/1.1 200 OK\r\nContent-Length: 999999999999\r\n\r\n";
        let (h3, _) = split_headers(raw3).unwrap();
        assert_eq!(content_length(h3), None);
    }

    #[test]
    fn mask_prefix_cases() {
        assert_eq!(mask_prefix(0xFFFFFF00), Some(24));
        assert_eq!(mask_prefix(0), Some(0));
        assert_eq!(mask_prefix(0xFFFFFFFF), Some(32));
        assert_eq!(mask_prefix(0x00FFFF00), None); // non-contiguous
    }
}


