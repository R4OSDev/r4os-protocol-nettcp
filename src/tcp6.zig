//! Bounded real TCP over the sole external IPv6 packet owner.
const std = @import("std");
const sdk = @import("r4os");
const t = sdk.network_transport;
const a = sdk.abi;
const Error = t.Error;
const capacity = 8192;
const mss_limit = 1220;
const syn: u8 = 2;
const ack_flag: u8 = 16;
const rst: u8 = 4;
const fin: u8 = 1;
const Phase = enum { free, listen, syn_sent, syn_received, established, terminal };
const Reordered = struct { used: bool = false, sequence: u32 = 0, length: u16 = 0, fin: bool = false, data: [1220]u8 = @splat(0) };
const Socket = struct {
    phase: Phase = .free,
    generation: u64 = 0,
    broker: a.ProgramProcessHandle = .{},
    owner: a.ProgramProcessHandle = .{},
    local: a.NetworkEndpoint = .{},
    remote: a.NetworkEndpoint = .{},
    link_provider: u64 = 0,
    link_generation: u64 = 0,
    clock: a.MonotonicClockInfo = .{},
    connect_deadline: a.NetworkDeadline = .{},
    parent: u64 = 0,
    parent_generation: u64 = 0,
    accepted: bool = true,
    retiring: bool = false,
    error_code: i32 = 0,
    peer_fin: bool = false,
    iss: u32 = 0,
    send_una: u32 = 0,
    receive_next: u32 = 0,
    peer_window: u16 = 0,
    window_sequence: u32 = 0,
    window_ack: u32 = 0,
    mss: u16 = mss_limit,
    syn_transmitted: bool = false,
    ack_pending: bool = false,
    tx_length: u16 = 0,
    tx_sent: u16 = 0,
    tx: [capacity]u8 = @splat(0),
    rx_length: u16 = 0,
    rx: [capacity]u8 = @splat(0),
    reordered: [4]Reordered = @splat(.{}),
    retries: u8 = 0,
    rto_ns: u64 = 1_000_000_000,
    last_transmit_ns: u64 = 0,
    persist_due_ns: u64 = 0,
};
var runtime: ?t.Runtime = null;
// Keep one bounded owner allocation. A nonzero-default global array would
// embed hundreds of KB twice as initialized data and reset constants.
var sockets: *[16]Socket = @ptrFromInt(8);
var next_generation: u64 = 1;
var next_port: u16 = 49152;

pub fn init(raw: *const a.ProtocolApi2) Error!void {
    if (runtime != null) return error.Invalid;
    const r = try t.Runtime.init(raw);
    const memory = r.view.function("alloc").?(@sizeOf([16]Socket), @alignOf(Socket)) orelse return error.Capacity;
    sockets = @ptrCast(@alignCast(memory));
    for (sockets) |*socket| socket.* = .{};
    runtime = r;
    next_generation = 1;
    next_port = 49152;
}
pub fn stop() void {
    if (runtime) |r| r.view.function("free").?(sockets, @sizeOf([16]Socket));
    sockets = @ptrFromInt(8);
    runtime = null;
}
fn before(x: u32, y: u32) bool {
    return @as(i32, @bitCast(x -% y)) < 0;
}
fn read32(bytes: []const u8, offset: usize) u32 {
    var reader = sdk.binary_cursor.Reader.init(bytes) catch unreachable;
    _ = reader.take(offset) catch unreachable;
    return reader.readInt(u32, .big) catch unreachable;
}
fn write32(bytes: []u8, offset: usize, value: u32) void {
    var writer = sdk.binary_cursor.Writer.init(bytes) catch unreachable;
    writer.position = offset;
    writer.writeInt(u32, value, .big) catch unreachable;
}
const Segment = struct {
    source: u16,
    destination: u16,
    sequence: u32,
    ack: u32,
    window: u16,
    flags: u8,
    mss: u16,
    payload: []const u8,
};
fn parse(bytes: []const u8) Error!Segment {
    if (bytes.len < 20) return error.Invalid;
    const header: usize = @as(usize, bytes[12] >> 4) * 4;
    if (header < 20 or header > bytes.len or bytes[12] & 0x0f != 0 or bytes[13] & 0xc0 != 0 or t.read16(bytes, 18) != 0) return error.UnsupportedPolicy;
    var mss: u16 = mss_limit;
    var cursor: usize = 20;
    while (cursor < header) {
        const kind = bytes[cursor];
        if (kind == 0) break;
        if (kind == 1) {
            cursor += 1;
            continue;
        }
        if (cursor + 2 > header) return error.Invalid;
        const length = bytes[cursor + 1];
        if (length < 2 or cursor + length > header) return error.Invalid;
        if (kind == 2) {
            if (length != 4) return error.Invalid;
            if (bytes[13] & syn != 0) {
                const offered = t.read16(bytes, cursor + 2);
                if (offered == 0) return error.Invalid;
                mss = @min(mss, offered);
            }
        }
        cursor += length;
    }
    if (t.read16(bytes, 0) == 0 or t.read16(bytes, 2) == 0) return error.Invalid;
    return .{ .source = t.read16(bytes, 0), .destination = t.read16(bytes, 2), .sequence = read32(bytes, 4), .ack = read32(bytes, 8), .window = t.read16(bytes, 14), .flags = bytes[13], .mss = mss, .payload = bytes[header..] };
}
fn clockSame(x: a.MonotonicClockInfo, y: a.MonotonicClockInfo) bool {
    return x.source == y.source and x.generation == y.generation and x.event_backend == y.event_backend and x.event_requested_hz == y.event_requested_hz and y.instant_ns >= x.instant_ns;
}
fn endpointMatch(bound: a.NetworkEndpoint, actual: a.NetworkEndpoint) bool {
    return bound.port == actual.port and bound.address.interface_id == actual.address.interface_id and (t.zero(bound.address) or t.sameAddress(bound.address, actual.address));
}
fn terminal(socket: *Socket, code: i32) void {
    socket.phase = .terminal;
    socket.error_code = code;
    socket.ack_pending = false;
}
fn allocate(value: a.NetworkTransportRequest) Error!usize {
    if (next_generation == std.math.maxInt(u64)) return error.Capacity;
    for (sockets, 0..) |*socket, index| if (socket.phase == .free) {
        socket.* = .{ .generation = next_generation, .broker = value.broker, .owner = value.owner };
        next_generation += 1;
        return index;
    };
    return error.Capacity;
}
fn initialSequence(r: t.Runtime) Error!u32 {
    var bytes: [4]u8 = undefined;
    try r.random(&bytes);
    return std.mem.readInt(u32, &bytes, .little);
}
fn transmit(r: anytype, socket: *Socket, sequence: u32, flags: u8, bytes: []const u8) Error!void {
    var packet = try r.prepare(socket.local.address, socket.remote.address, 6, .{});
    if (packet.provider != socket.link_provider or packet.generation != socket.link_generation) return error.ProviderChanged;
    const header: u32 = if (flags & syn != 0) 24 else 20;
    if (bytes.len > mss_limit) return error.Capacity;
    packet.bytes = header + @as(u32, @intCast(bytes.len));
    t.write16(&packet.payload, 0, socket.local.port);
    t.write16(&packet.payload, 2, socket.remote.port);
    write32(&packet.payload, 4, sequence);
    write32(&packet.payload, 8, if (flags & ack_flag != 0) socket.receive_next else 0);
    packet.payload[12] = @as(u8, @intCast(header / 4)) << 4;
    packet.payload[13] = flags;
    t.write16(&packet.payload, 14, capacity - socket.rx_length);
    if (flags & syn != 0) {
        packet.payload[20] = 2;
        packet.payload[21] = 4;
        t.write16(&packet.payload, 22, mss_limit);
    }
    @memcpy(packet.payload[header..packet.bytes], bytes);
    try r.checksum(&packet, 16);
    try r.send(packet);
}
fn abortSocket(r: anytype, socket: *Socket) Error!void {
    if (socket.phase == .free) return;
    // An unacknowledged send never exposed this local connection on the wire.
    // There is no outstanding frame/buffer loan and no peer state to reset.
    // Waiting for ND just to abort such a SYN would pin a slot indefinitely.
    if (socket.phase != .listen and socket.syn_transmitted and socket.error_code != a.network_error_provider_changed and socket.error_code != a.network_error_clock_changed and socket.error_code != a.network_error_reset) {
        const flags: u8 = rst | if (socket.phase == .syn_sent) @as(u8, 0) else ack_flag;
        try transmit(r, socket, socket.send_una +% socket.tx_sent, flags, "");
    }
    socket.* = .{};
}
fn acknowledge(socket: *Socket, sequence: u32) bool {
    const next = socket.send_una +% socket.tx_sent;
    if (before(sequence, socket.send_una) or before(next, sequence)) return false;
    const amount = sequence -% socket.send_una;
    if (amount != 0) {
        std.mem.copyForwards(u8, socket.tx[0 .. socket.tx_length - amount], socket.tx[amount..socket.tx_length]);
        socket.tx_length -= @intCast(amount);
        socket.tx_sent -= @intCast(amount);
        socket.send_una = sequence;
        socket.retries = 0;
        socket.rto_ns = 1_000_000_000;
    }
    return true;
}
fn acceptInOrder(socket: *Socket, sequence: u32, payload: []const u8, end: bool) void {
    if (socket.peer_fin or before(socket.receive_next, sequence)) return;
    const duplicate = socket.receive_next -% sequence;
    if (duplicate > payload.len) return;
    const data = payload[duplicate..];
    const amount = @min(data.len, capacity - socket.rx_length);
    @memcpy(socket.rx[socket.rx_length..][0..amount], data[0..amount]);
    socket.rx_length += @intCast(amount);
    socket.receive_next +%= @intCast(amount);
    if (end and amount == data.len and socket.rx_length < capacity) {
        socket.receive_next +%= 1;
        socket.peer_fin = true;
    }
}
fn receiveData(socket: *Socket, segment: Segment) void {
    socket.ack_pending = true;
    if (socket.peer_fin) return;
    const window: u32 = capacity - socket.rx_length;
    if (!before(socket.receive_next, segment.sequence)) {
        acceptInOrder(socket, segment.sequence, segment.payload, segment.flags & fin != 0);
    } else {
        const gap = segment.sequence -% socket.receive_next;
        if (gap >= window or segment.payload.len > window - gap or segment.payload.len > mss_limit) return;
        // Bounded out-of-order storage. Ambiguous overlap is left unacked;
        // the sender retransmits it after the contiguous prefix arrives.
        for (socket.reordered) |entry| if (entry.used) {
            const entry_end = entry.sequence +% entry.length +% @as(u32, if (entry.fin) 1 else 0);
            const new_end = segment.sequence +% @as(u32, @intCast(segment.payload.len)) +% @as(u32, if (segment.flags & fin != 0) 1 else 0);
            if (before(segment.sequence, entry_end) and before(entry.sequence, new_end)) return;
        };
        for (&socket.reordered) |*entry| if (!entry.used) {
            entry.* = .{ .used = true, .sequence = segment.sequence, .length = @intCast(segment.payload.len), .fin = segment.flags & fin != 0 };
            @memcpy(entry.data[0..segment.payload.len], segment.payload);
            break;
        };
    }
    var again = true;
    while (again and !socket.peer_fin) {
        again = false;
        for (&socket.reordered) |*entry| if (entry.used and !before(socket.receive_next, entry.sequence)) {
            acceptInOrder(socket, entry.sequence, entry.data[0..entry.length], entry.fin);
            entry.* = .{};
            again = true;
        };
    }
}
fn acceptable(socket: *const Socket, segment: Segment) bool {
    const length: u32 = @intCast(segment.payload.len + @as(usize, if (segment.flags & (syn | fin) != 0) 1 else 0));
    const window: u32 = capacity - socket.rx_length;
    if (window == 0) return length == 0 and segment.sequence == socket.receive_next;
    if (length == 0) return !before(segment.sequence, socket.receive_next) and before(segment.sequence, socket.receive_next +% window);
    const last = segment.sequence +% length -% 1;
    return (!before(segment.sequence, socket.receive_next) and before(segment.sequence, socket.receive_next +% window)) or (!before(last, socket.receive_next) and before(last, socket.receive_next +% window));
}
fn incoming(r: t.Runtime, info: a.Ipv6InterfaceInfo, packet: *const a.Ipv6Packet) Error!void {
    const segment = parse(packet.payload[0..packet.bytes]) catch return;
    const local: a.NetworkEndpoint = .{ .address = packet.destination, .port = segment.destination };
    const remote: a.NetworkEndpoint = .{ .address = packet.source, .port = segment.source };
    var target: ?*Socket = null;
    var listener: ?usize = null;
    for (sockets, 0..) |*socket, index| {
        if (socket.phase == .free or socket.phase == .terminal or socket.link_provider != packet.provider or socket.link_generation != packet.generation or !endpointMatch(socket.local, local)) continue;
        if (socket.phase == .listen) listener = index else if (socket.remote.port == remote.port and t.sameAddress(socket.remote.address, remote.address)) {
            target = socket;
            break;
        }
    }
    if (target == null) {
        if (listener) |parent_index| {
            if (segment.flags & (syn | rst | ack_flag | fin) == syn and segment.payload.len == 0) {
                const parent = &sockets[parent_index];
                var pending: usize = 0;
                for (sockets) |entry| if (entry.phase != .free and entry.parent == parent_index + 1 and entry.parent_generation == parent.generation and !entry.accepted) {
                    pending += 1;
                };
                if (pending >= 4) return;
                const sequence = try initialSequence(r);
                const index = allocate(.{ .broker = parent.broker, .owner = parent.owner }) catch return;
                const socket = &sockets[index];
                socket.phase = .syn_received;
                socket.accepted = false;
                socket.parent = parent_index + 1;
                socket.parent_generation = parent.generation;
                socket.local = local;
                socket.remote = remote;
                socket.link_provider = packet.provider;
                socket.link_generation = packet.generation;
                socket.clock = info.link.clock;
                socket.iss = sequence;
                socket.send_una = sequence;
                socket.receive_next = segment.sequence +% 1;
                socket.peer_window = segment.window;
                socket.mss = segment.mss;
                return;
            }
        }
        if (segment.flags & rst == 0) {
            var temporary: Socket = .{ .local = local, .remote = remote, .link_provider = packet.provider, .link_generation = packet.generation };
            if (segment.flags & ack_flag != 0) try transmit(r, &temporary, segment.ack, rst, "") else {
                temporary.receive_next = segment.sequence +% @as(u32, @intCast(segment.payload.len)) +% @as(u32, if (segment.flags & syn != 0) 1 else 0) +% @as(u32, if (segment.flags & fin != 0) 1 else 0);
                try transmit(r, &temporary, 0, rst | ack_flag, "");
            }
        }
        return;
    }
    const socket = target.?;
    if (socket.phase == .syn_sent) {
        if (segment.flags & ack_flag == 0 or segment.ack != socket.iss +% 1 or !socket.syn_transmitted) return;
        if (segment.flags & rst != 0) {
            terminal(socket, a.network_error_reset);
            return;
        }
        if (segment.flags & syn == 0 or segment.flags & fin != 0) return;
        socket.send_una = segment.ack;
        socket.receive_next = segment.sequence +% 1;
        socket.peer_window = segment.window;
        socket.window_sequence = segment.sequence;
        socket.window_ack = segment.ack;
        socket.mss = segment.mss;
        socket.phase = .established;
        socket.ack_pending = true;
        socket.retries = 0;
        if (segment.payload.len != 0) {
            var data = segment;
            data.sequence +%= 1;
            receiveData(socket, data);
        }
        return;
    }
    if (socket.phase == .syn_received and segment.flags & syn != 0 and segment.sequence +% 1 == socket.receive_next) {
        socket.syn_transmitted = false;
        return;
    }
    if (!acceptable(socket, segment)) {
        if (segment.flags & rst == 0) socket.ack_pending = true;
        return;
    }
    if (segment.flags & rst != 0) {
        if (segment.sequence == socket.receive_next) terminal(socket, a.network_error_reset) else socket.ack_pending = true;
        return;
    }
    if (segment.flags & syn != 0) {
        socket.ack_pending = true;
        return;
    }
    if (segment.flags & ack_flag == 0) return;
    if (socket.phase == .syn_received) {
        if (segment.ack != socket.iss +% 1 or !socket.syn_transmitted) return;
        socket.send_una = segment.ack;
        socket.phase = .established;
        socket.retries = 0;
    } else {
        if (before(socket.send_una +% socket.tx_sent, segment.ack)) {
            socket.ack_pending = true;
            return;
        }
        if (!before(segment.ack, socket.send_una)) _ = acknowledge(socket, segment.ack);
    }
    if (before(socket.window_sequence, segment.sequence) or socket.window_sequence == segment.sequence and !before(segment.ack, socket.window_ack)) {
        socket.peer_window = segment.window;
        socket.window_sequence = segment.sequence;
        socket.window_ack = segment.ack;
    }
    if (segment.payload.len != 0 or segment.flags & fin != 0) receiveData(socket, segment);
}
fn drive(r: anytype, socket: *Socket, now: u64) Error!void {
    if (socket.phase == .listen or socket.phase == .terminal or socket.phase == .free) return;
    if (socket.phase == .syn_sent) {
        t.common.checkAttempt(r, socket.connect_deadline) catch |err| {
            terminal(socket, t.common.code(err));
            return;
        };
    }
    if (socket.phase == .syn_sent or socket.phase == .syn_received) {
        if (socket.syn_transmitted and now -| socket.last_transmit_ns < socket.rto_ns) return;
        if (socket.retries == 8) {
            terminal(socket, a.network_error_timeout);
            return;
        }
        try transmit(r, socket, socket.iss, syn | if (socket.phase == .syn_received) ack_flag else @as(u8, 0), "");
        if (socket.syn_transmitted) socket.rto_ns = @min(60_000_000_000, socket.rto_ns *| 2);
        socket.syn_transmitted = true;
        socket.last_transmit_ns = now;
        socket.retries += 1;
        return;
    }
    if (socket.ack_pending) {
        try transmit(r, socket, socket.send_una +% socket.tx_sent, ack_flag, "");
        socket.ack_pending = false;
    }
    if (socket.tx_length == 0) return;
    if (socket.peer_window == 0) {
        if (now < socket.persist_due_ns) return;
        // A one-byte probe at SND.UNA-1 solicits the real receive window
        // without treating an unaccepted byte as acknowledged progress.
        try transmit(r, socket, socket.send_una -% 1, ack_flag, socket.tx[0..1]);
        socket.persist_due_ns = now +| 1_000_000_000;
        return;
    }
    const retransmit = socket.tx_sent != 0;
    if (retransmit and now -| socket.last_transmit_ns < socket.rto_ns) return;
    if (socket.retries == 8) {
        terminal(socket, a.network_error_timeout);
        return;
    }
    const amount: u16 = if (retransmit) socket.tx_sent else @min(socket.tx_length, @min(socket.mss, socket.peer_window));
    try transmit(r, socket, socket.send_una, ack_flag | 8, socket.tx[0..amount]);
    socket.tx_sent = amount;
    socket.last_transmit_ns = now;
    if (retransmit) socket.rto_ns = @min(60_000_000_000, socket.rto_ns *| 2);
    socket.retries += 1;
}

fn retire(r: t.Runtime, index: usize) Error!void {
    const socket = &sockets[index];
    if (socket.phase == .listen) {
        for (sockets) |*child| if (child.phase != .free and !child.accepted and child.parent == index + 1 and child.parent_generation == socket.generation) {
            child.retiring = true;
            try abortSocket(r, child);
        };
    }
    try abortSocket(r, socket);
}
fn tick(r: t.Runtime) Error!void {
    var seen: [sockets.len]bool = @splat(false);
    var index: u32 = 0;
    while (index < 8) : (index += 1) {
        const info = r.rpc(a.Ipv6InterfaceQuery, a.Ipv6InterfaceInfo, "net.ipv6", a.ipv6_op_info, .{ .index = index }) catch |err| {
            if (err == error.NotFound) continue;
            return err;
        };
        for (sockets, 0..) |*socket, slot| {
            if (socket.phase == .free or socket.local.address.interface_id != info.link.interface_id) continue;
            seen[slot] = true;
            if (socket.link_provider != info.link.provider or socket.link_generation != info.link.generation or info.capabilities == 0) terminal(socket, a.network_error_provider_changed) else if (!clockSame(socket.clock, info.link.clock)) terminal(socket, a.network_error_clock_changed) else socket.clock = info.link.clock;
        }
        var budget: u32 = 0;
        while (budget < 16 and info.capabilities != 0) : (budget += 1) {
            const packet = r.receive(info, 6) catch |err| {
                if (err == error.WouldBlock or err == error.UnsupportedPolicy) break;
                return err;
            };
            incoming(r, info, &packet) catch |err| {
                if (err != error.WouldBlock and err != error.Capacity and err != error.NotFound) return err;
            };
        }
        // A SYN may create a child during this very receive pass. Its exact
        // link was observed too; it must not be mistaken for a removed link.
        for (sockets, 0..) |socket, slot| if (socket.phase != .free and socket.local.address.interface_id == info.link.interface_id) {
            seen[slot] = true;
        };
    }
    for (sockets, 0..) |*socket, slot| {
        if (socket.phase == .free) continue;
        if (!seen[slot]) terminal(socket, a.network_error_provider_changed);
        if (!socket.accepted) {
            const parent_live = socket.parent != 0 and socket.parent <= sockets.len and sockets[@intCast(socket.parent - 1)].phase == .listen and sockets[@intCast(socket.parent - 1)].generation == socket.parent_generation;
            if (!parent_live or socket.phase == .terminal) socket.retiring = true;
        }
        if (r.gone(socket.broker) or r.gone(socket.owner)) socket.retiring = true;
        if (socket.retiring) {
            retire(r, slot) catch {};
            continue;
        }
        drive(r, socket, socket.clock.instant_ns) catch |err| {
            if (err == error.ProviderChanged or err == error.ClockChanged or err == error.NotFound) terminal(socket, t.common.code(err));
        };
    }
}
fn lookup(value: a.NetworkTransportRequest) Error!usize {
    const req = value.request;
    if (req.socket == 0 or req.socket > sockets.len or req.generation == 0) return error.BadSocket;
    const index: usize = @intCast(req.socket - 1);
    const socket = &sockets[index];
    if (socket.phase == .free or socket.generation != req.generation or socket.retiring or !t.sameProcess(socket.broker, value.broker) or !t.sameProcess(socket.owner, value.owner)) return error.BadSocket;
    return index;
}
fn socketResult(value: a.NetworkTransportRequest, index: usize) a.NetworkSocketResult {
    const socket = &sockets[index];
    return .{ .provider = value.provider, .socket = index + 1, .generation = socket.generation, .endpoint = if (socket.phase == .listen) socket.local else socket.remote, .state = switch (socket.phase) {
        .syn_sent, .syn_received => a.network_state_would_block,
        .terminal => if (socket.error_code == a.network_error_timeout) a.network_state_timeout else a.network_state_reset,
        else => a.network_state_ready,
    } };
}
fn portFree(endpoint: a.NetworkEndpoint) bool {
    for (sockets) |socket| if (socket.phase != .free and endpointMatch(socket.local, endpoint)) return false;
    return true;
}
fn ephemeral(endpoint: *a.NetworkEndpoint) Error!void {
    var attempts: u32 = 0;
    while (attempts < 16384) : (attempts += 1) {
        endpoint.port = next_port;
        next_port = if (next_port == 65535) 49152 else next_port + 1;
        if (portFree(endpoint.*)) return;
    }
    return error.Capacity;
}
fn create(r: t.Runtime, value: a.NetworkTransportRequest, listening: bool) Error!usize {
    const req = value.request;
    if (req.socket != 0 or req.generation != 0 or req.bytes != 0 or req.endpoint.address.family != 6) return error.Invalid;
    if (!t.common.ownerAlive(r, value.owner)) return error.BadSocket;
    var local: a.NetworkEndpoint = .{ .address = .{ .family = 6 } };
    var link: a.Ipv6InterfaceInfo = undefined;
    var remote: a.NetworkEndpoint = .{};
    var sequence: u32 = 0;
    if (listening) {
        local = req.endpoint;
        link = try r.interface(local.address.interface_id);
        local.address.interface_id = link.link.interface_id;
        const ll = local.address.bytes[0] == 0xfe and local.address.bytes[1] & 0xc0 == 0x80;
        if (ll and local.address.scope_id != link.link.interface_id or !ll and local.address.scope_id != 0) return error.UnsupportedScope;
        if (!t.zero(local.address)) _ = try r.prepare(local.address, link.link_local, 6, req.deadline);
        if (local.port == 0) try ephemeral(&local) else if (!portFree(local)) return error.Capacity;
    } else {
        if (req.endpoint.port == 0 or t.zero(req.endpoint.address)) return error.Invalid;
        const packet = try r.prepare(local.address, req.endpoint.address, 6, req.deadline);
        local.address = packet.source;
        remote = .{ .address = packet.destination, .port = req.endpoint.port };
        link = try r.interface(packet.source.interface_id);
        try ephemeral(&local);
        sequence = try initialSequence(r);
    }
    const index = try allocate(value);
    const socket = &sockets[index];
    socket.phase = if (listening) .listen else .syn_sent;
    socket.local = local;
    socket.remote = remote;
    socket.link_provider = link.link.provider;
    socket.link_generation = link.link.generation;
    socket.clock = link.link.clock;
    socket.iss = sequence;
    socket.send_una = sequence;
    socket.connect_deadline = req.deadline;
    drive(r, socket, link.link.clock.instant_ns) catch |err| {
        if (err != error.WouldBlock and err != error.Backend and err != error.Capacity) terminal(socket, t.common.code(err));
    };
    if (socket.phase == .terminal) {
        // A failing initial attempt has never acknowledged a SYN transmit.
        // Preserve its actual error instead of inventing a peer reset.
        std.debug.assert(!socket.syn_transmitted);
        const code = socket.error_code;
        socket.* = .{};
        try t.status(code);
        return error.Backend;
    }
    return index;
}
fn dispatchInner(op: u32, input: *const a.ProtocolBuffer, output: *a.ProtocolBuffer) Error!void {
    const r = runtime orelse return error.Backend;
    if (op == a.network_op_info) {
        if (input.flags != 0 or input.reserved != 0 or input.len != 0 or output.flags != 0 or output.reserved != 0) return error.Invalid;
        var info: a.NetworkProviderInfo = .{ .provider = (try r.identity()).provider };
        if (r.interface(0)) |link| {
            info.capabilities = a.network_cap_ipv6 | a.network_cap_tcp | a.network_cap_listen | a.network_cap_retained_terminal;
            info.max_send = 3968;
            info.max_recv = 4008;
            info.interface_id = link.link.interface_id;
        } else |err| if (err != error.NotFound and err != error.UnsupportedPolicy) return err;
        return t.put(a.NetworkProviderInfo, &info, "", output);
    }
    const native = sdk.native_protocol_view;
    var input_policy = native.Policy.versioned(a.NetworkTransportRequest, 1, .input, .prefix);
    input_policy.alignment = 1; // the existing copied header + payload transport
    _ = native.admit(input, input_policy, .input) catch return error.Invalid;
    const value = try r.decodeRequest(input, output);
    const req = value.request;
    if (req.flags != 0) return error.UnsupportedPolicy;
    const writing = op == a.network_op_write;
    if (input.len != @sizeOf(a.NetworkTransportRequest) + @as(usize, if (writing) req.bytes else 0)) return error.Invalid;
    if (!writing and op != a.network_op_read and req.bytes != 0) return error.Invalid;
    var output_policy = native.Policy.record(a.NetworkSocketResult, .output, .prefix);
    output_policy.alignment = 1;
    _ = native.admit(output, output_policy, .output) catch return error.Capacity;
    if (op == a.network_transport_op_tick) {
        if (req.socket != 0 or req.generation != 0) return error.Invalid;
        try tick(r);
        const reply: a.NetworkSocketResult = .{ .provider = value.provider, .state = a.network_state_ready };
        return t.put(a.NetworkSocketResult, &reply, "", output);
    }
    try tick(r);
    if ((op == a.network_op_connect or op == a.network_op_listen) and req.socket == 0) {
        const index = try create(r, value, op == a.network_op_listen);
        const reply = socketResult(value, index);
        return t.put(a.NetworkSocketResult, &reply, "", output);
    }
    const index = try lookup(value);
    const socket = &sockets[index];
    var reply = socketResult(value, index);
    if (op == a.network_op_close) {
        if (!std.mem.allEqual(u8, std.mem.asBytes(&req.endpoint), 0)) return error.Invalid;
        try retire(r, index);
        reply.state = a.network_state_local_closed;
        return t.put(a.NetworkSocketResult, &reply, "", output);
    }
    if (op == a.network_op_connect) {
        if (socket.phase == .listen) return error.BadSocket;
        if (socket.phase == .terminal) try t.status(socket.error_code);
        return t.put(a.NetworkSocketResult, &reply, "", output);
    }
    if (!std.mem.allEqual(u8, std.mem.asBytes(&req.endpoint), 0)) return error.Invalid;
    if (op == a.network_op_accept) {
        if (socket.phase == .terminal) try t.status(socket.error_code);
        if (socket.phase != .listen) return error.BadSocket;
        for (sockets, 0..) |*child, child_index| if (child.phase == .established and !child.accepted and child.parent == index + 1 and child.parent_generation == socket.generation) {
            const accepted = socketResult(value, child_index);
            try t.put(a.NetworkSocketResult, &accepted, "", output);
            child.accepted = true;
            child.parent = 0;
            child.parent_generation = 0;
            return;
        };
        return error.WouldBlock;
    }
    if (socket.phase == .listen) return error.BadSocket;
    if (op == a.network_op_read) {
        if (socket.phase == .terminal and socket.error_code != a.network_error_reset and socket.error_code != a.network_error_timeout) try t.status(socket.error_code);
        if (req.bytes > 4008) return error.Capacity;
        const amount: u16 = @intCast(@min(req.bytes, socket.rx_length));
        if (amount != 0) {
            reply.bytes = amount;
            reply.original_bytes = amount;
            reply.state = a.network_state_ready;
            try t.put(a.NetworkSocketResult, &reply, socket.rx[0..amount], output);
            std.mem.copyForwards(u8, socket.rx[0 .. socket.rx_length - amount], socket.rx[amount..socket.rx_length]);
            socket.rx_length -= amount;
            socket.ack_pending = true;
            return;
        }
        if (socket.phase == .terminal) {
            if (socket.error_code == a.network_error_reset) reply.state = a.network_state_reset else if (socket.error_code == a.network_error_timeout) reply.state = a.network_state_timeout else try t.status(socket.error_code);
        } else if (socket.peer_fin) reply.state = a.network_state_eof else reply.state = a.network_state_would_block;
        return t.put(a.NetworkSocketResult, &reply, "", output);
    }
    if (writing) {
        if (req.bytes > 3968) return error.Capacity;
        if (socket.phase == .terminal) try t.status(socket.error_code);
        if (socket.phase != .established) return error.WouldBlock;
        const amount = @min(req.bytes, capacity - socket.tx_length);
        const source: [*]const u8 = @ptrCast(input.data.?);
        @memcpy(socket.tx[socket.tx_length..][0..amount], source[@sizeOf(a.NetworkTransportRequest)..][0..amount]);
        socket.tx_length += @intCast(amount);
        reply.bytes = amount;
        reply.original_bytes = amount;
        if (amount == 0 and req.bytes != 0) reply.state = a.network_state_would_block;
        drive(r, socket, socket.clock.instant_ns) catch {};
        return t.put(a.NetworkSocketResult, &reply, "", output);
    }
    return error.UnsupportedPolicy;
}
pub fn dispatch(op: u32, input: *const a.ProtocolBuffer, output: *a.ProtocolBuffer) i32 {
    dispatchInner(op, input, output) catch |err| return t.common.code(err);
    return 0;
}

test "TCP sequence wrap, partial acknowledgements and unacknowledged suffix" {
    var socket: Socket = .{ .phase = .established, .send_una = 0xffff_fffe, .tx_length = 6, .tx_sent = 4 };
    @memcpy(socket.tx[0..6], "abcdef");
    try std.testing.expect(!acknowledge(&socket, 3));
    try std.testing.expectEqual(@as(u16, 6), socket.tx_length);
    try std.testing.expect(acknowledge(&socket, 0));
    try std.testing.expectEqualStrings("cdef", socket.tx[0..socket.tx_length]);
    try std.testing.expectEqual(@as(u16, 2), socket.tx_sent);
    try std.testing.expect(acknowledge(&socket, 2));
    try std.testing.expectEqualStrings("ef", socket.tx[0..socket.tx_length]);
    try std.testing.expectEqual(@as(u16, 0), socket.tx_sent);
}
test "TCP reordered prefix, duplicate FIN and data before terminal reset" {
    var socket: Socket = .{ .phase = .established, .receive_next = 100 };
    var segment: Segment = .{ .source = 1, .destination = 2, .sequence = 103, .ack = 0, .window = 4096, .flags = fin | ack_flag, .mss = 1220, .payload = "def" };
    receiveData(&socket, segment);
    try std.testing.expectEqual(@as(u32, 100), socket.receive_next);
    segment.sequence = 100;
    segment.flags = ack_flag;
    segment.payload = "abc";
    receiveData(&socket, segment);
    try std.testing.expectEqualStrings("abcdef", socket.rx[0..socket.rx_length]);
    try std.testing.expectEqual(@as(u32, 107), socket.receive_next);
    try std.testing.expect(socket.peer_fin);
    receiveData(&socket, segment);
    try std.testing.expectEqual(@as(u32, 107), socket.receive_next);
    terminal(&socket, a.network_error_reset);
    try std.testing.expectEqualStrings("abcdef", socket.rx[0..socket.rx_length]);
}

test "TCP accepts only the receive-window prefix and delays an out-of-window FIN" {
    var socket: Socket = .{ .phase = .established, .receive_next = 250, .rx_length = capacity - 2 };
    acceptInOrder(&socket, 250, "abcd", true);
    try std.testing.expectEqual(@as(u32, 252), socket.receive_next);
    try std.testing.expectEqual(@as(u16, capacity), socket.rx_length);
    try std.testing.expectEqualStrings("ab", socket.rx[capacity - 2 ..]);
    try std.testing.expect(!socket.peer_fin);
    // The caller drains the accepted prefix, then the peer retransmits the
    // unacknowledged suffix and FIN at their actual sequence positions.
    socket.rx_length = 0;
    acceptInOrder(&socket, 252, "cd", true);
    try std.testing.expectEqualStrings("cd", socket.rx[0..socket.rx_length]);
    try std.testing.expectEqual(@as(u32, 255), socket.receive_next);
    try std.testing.expect(socket.peer_fin);
}
test "TCP SYN clock and backpressure preserve sequence until actual transmit acknowledgement" {
    const Trace = struct { count: u32 = 0, blocked: bool = true, sequence: u32 = 0, flags: u8 = 0 };
    const Io = struct {
        trace: *Trace,
        pub fn prepare(_: @This(), source: a.NetworkAddress, destination: a.NetworkAddress, next: u32, budget: a.NetworkDeadline) Error!a.Ipv6Packet {
            return .{ .provider = 7, .generation = 9, .source = source, .destination = destination, .next_header = next, .deadline = budget };
        }
        pub fn checksum(_: @This(), _: *a.Ipv6Packet, _: usize) Error!void {}
        pub fn send(self: @This(), packet: a.Ipv6Packet) Error!void {
            if (self.trace.blocked) return error.WouldBlock;
            self.trace.count += 1;
            self.trace.sequence = read32(&packet.payload, 4);
            self.trace.flags = packet.payload[13];
        }
        pub fn monotonicClock(_: @This(), _: *a.MonotonicClockInfo) i32 {
            return 0; // An explicit poll budget needs no invented clock sample.
        }
    };
    var trace: Trace = .{};
    const io: Io = .{ .trace = &trace };
    var socket: Socket = .{ .phase = .syn_sent, .link_provider = 7, .link_generation = 9, .iss = 0xffff_ffff, .send_una = 0xffff_ffff };
    try std.testing.expectError(error.WouldBlock, drive(io, &socket, 0));
    try std.testing.expect(!socket.syn_transmitted);
    try std.testing.expectEqual(@as(u8, 0), socket.retries);
    trace.blocked = false;
    try drive(io, &socket, 0);
    try std.testing.expectEqual(@as(u32, 1), trace.count);
    try std.testing.expectEqual(@as(u32, 0xffff_ffff), trace.sequence);
    try std.testing.expectEqual(syn, trace.flags);
    try drive(io, &socket, 999_999_999);
    try std.testing.expectEqual(@as(u32, 1), trace.count);
    try drive(io, &socket, 1_000_000_000);
    try std.testing.expectEqual(@as(u32, 2), trace.count);
    try std.testing.expectEqual(@as(u32, 0xffff_ffff), trace.sequence);
    try std.testing.expectEqual(@as(u64, 2_000_000_000), socket.rto_ns);
    // A timed-out incoming handshake releases its backlog slot only after
    // the actual abort transmit acknowledgement. Backpressure retains it.
    socket.phase = .syn_received;
    socket.accepted = false;
    socket.generation = 19;
    socket.retries = 8;
    try drive(io, &socket, 3_000_000_000);
    try std.testing.expectEqual(Phase.terminal, socket.phase);
    try std.testing.expectEqual(a.network_error_timeout, socket.error_code);
    trace.blocked = true;
    try std.testing.expectError(error.WouldBlock, abortSocket(io, &socket));
    try std.testing.expectEqual(@as(u64, 19), socket.generation);
    trace.blocked = false;
    try abortSocket(io, &socket);
    try std.testing.expectEqual(Phase.free, socket.phase);
    try std.testing.expectEqual(@as(u8, rst | ack_flag), trace.flags);
    socket = .{ .phase = .syn_sent, .generation = 20, .link_provider = 7, .link_generation = 9 };
    trace.blocked = true;
    const sent_before = trace.count;
    try abortSocket(io, &socket);
    try std.testing.expectEqual(Phase.free, socket.phase);
    try std.testing.expectEqual(sent_before, trace.count);
}

test "TCP bounded owner allocation fails closed and is released exactly once" {
    const Owner = struct {
        var memory: [@sizeOf([16]Socket)]u8 align(@alignOf(Socket)) = undefined;
        var failing: bool = true;
        var live: bool = false;
        var bad: bool = false;
        var allocations: usize = 0;
        var releases: usize = 0;
        fn alloc(bytes: u32, alignment: u32) callconv(.c) ?*anyopaque {
            allocations += 1;
            if (bytes != memory.len or alignment != @alignOf(Socket) or live) {
                bad = true;
                return null;
            }
            if (failing) return null;
            live = true;
            return &memory;
        }
        fn free(pointer: ?*anyopaque, bytes: u32) callconv(.c) void {
            if (!live or pointer != @as(*anyopaque, @ptrCast(&memory)) or bytes != memory.len) bad = true;
            live = false;
            releases += 1;
        }
    };
    try std.testing.expect(runtime == null);
    var raw: a.ProtocolApi2 = undefined;
    // Use the independent namespace, not the old table's identical slots.
    raw.magic = sdk.platform2.abi.protocol_magic;
    raw.version = sdk.platform2.abi.protocol_version;
    raw.size = @sizeOf(a.ProtocolApi2);
    raw.reserved = 0;
    raw.protocol_dispatch = @ptrFromInt(8);
    raw.link_io = @ptrFromInt(8);
    raw.process_status = @ptrFromInt(8);
    raw.entropy_fill = @ptrFromInt(8);
    raw.alloc = Owner.alloc;
    raw.free = Owner.free;
    defer stop();
    try std.testing.expectError(error.Capacity, init(&raw));
    try std.testing.expect(runtime == null and !Owner.live and Owner.releases == 0);
    Owner.failing = false;
    try init(&raw);
    try std.testing.expect(Owner.live and sockets[0].phase == .free and sockets[15].mss == mss_limit);
    try std.testing.expectError(error.Invalid, init(&raw));
    try std.testing.expectEqual(@as(usize, 2), Owner.allocations);
    stop();
    stop();
    try std.testing.expect(!Owner.live and !Owner.bad);
    try std.testing.expectEqual(@as(usize, 1), Owner.releases);
}

test "copied TCP reads reject changed links and clocks before buffered FIN data; Busy retains owner" {
    const Backend = struct {
        var memory: [@sizeOf([16]Socket)]u8 align(@alignOf(Socket)) = undefined;
        var mode: u8 = 0;
        fn alloc(_: u32, _: u32) callconv(.c) ?*anyopaque {
            return &memory;
        }
        fn free(_: ?*anyopaque, _: u32) callconv(.c) void {}
        fn clock() a.MonotonicClockInfo {
            return .{ .source = 1, .generation = if (mode == 3) 72 else 71, .event_requested_hz = 1000, .instant_ns = 1_000_000 };
        }
        fn identity(_: *const a.NetworkLinkRequest, out: *a.NetworkLinkInfo) callconv(.c) i32 {
            out.* = .{ .provider = 7, .clock = clock() };
            return 0;
        }
        fn status(_: *const a.ProgramProcessHandle, out: *a.ProgramInstanceInfo) callconv(.c) i32 {
            out.* = .{ .state = @intFromEnum(a.ProgramInstanceState.running) };
            return if (mode == 5) a.program_handle_error_would_block else 0;
        }
        fn dispatch(_: [*]const u8, _: u32, op: u32, input: *const a.ProtocolBuffer, output: *a.ProtocolBuffer) callconv(.c) i32 {
            if (op == a.ipv6_op_receive) return a.network_error_would_block;
            if (op != a.ipv6_op_info) return a.network_error_backend;
            const query: *const a.Ipv6InterfaceQuery = @ptrCast(@alignCast(input.data.?));
            if (query.index != 0 or mode == 4) return a.network_error_not_found;
            const info: a.Ipv6InterfaceInfo = .{ .link = .{ .provider = if (mode == 2) 12 else 11, .interface_id = 1, .generation = if (mode == 1) 10 else 9, .clock = clock() }, .capabilities = 1, .max_packet = 1280 };
            t.put(a.Ipv6InterfaceInfo, &info, "", output) catch return a.network_error_capacity;
            return 0;
        }
    };
    var raw: a.ProtocolApi2 = undefined;
    raw.magic = sdk.platform2.abi.protocol_magic;
    raw.version = sdk.platform2.abi.protocol_version;
    raw.size = @sizeOf(a.ProtocolApi2);
    raw.reserved = 0;
    raw.protocol_dispatch = Backend.dispatch;
    raw.link_io = Backend.identity;
    raw.process_status = Backend.status;
    raw.entropy_fill = @ptrFromInt(8); // No entropy operation is requested.
    raw.alloc = Backend.alloc;
    raw.free = Backend.free;
    try init(&raw);
    defer stop();
    const broker: a.ProgramProcessHandle = .{ .instance_id = 10, .generation = 100 };
    const owner: a.ProgramProcessHandle = .{ .instance_id = 20, .generation = 200 };
    for (0..6) |mode| {
        Backend.mode = 0;
        sockets[0] = .{ .phase = .established, .generation = 15, .broker = broker, .owner = owner, .local = .{ .address = .{ .family = 6, .interface_id = 1 } }, .remote = .{ .address = .{ .family = 6, .interface_id = 1 } }, .link_provider = 11, .link_generation = 9, .clock = Backend.clock(), .rx_length = 3, .peer_fin = true };
        @memcpy(sockets[0].rx[0..3], "abc");
        Backend.mode = @intCast(mode);
        var request: a.NetworkTransportRequest = .{ .provider = 7, .broker = broker, .owner = owner, .request = .{ .provider = broker.generation, .socket = 1, .generation = 15, .bytes = 3 } };
        const input: a.ProtocolBuffer = .{ .data = &request, .len = @sizeOf(@TypeOf(request)), .capacity = @sizeOf(@TypeOf(request)) };
        var bytes: [128]u8 = @splat(0xa5);
        var output: a.ProtocolBuffer = .{ .data = &bytes, .len = 91, .capacity = bytes.len };
        const code = dispatch(a.network_op_read, &input, &output);
        if (mode == 0 or mode == 5) {
            try std.testing.expectEqual(@as(i32, 0), code);
            try std.testing.expectEqualStrings("abc", bytes[@sizeOf(a.NetworkSocketResult)..output.len]);
        } else {
            try std.testing.expectEqual(if (mode == 3) a.network_error_clock_changed else a.network_error_provider_changed, code);
            try std.testing.expectEqual(@as(u32, 91), output.len);
            try std.testing.expect(std.mem.allEqual(u8, &bytes, 0xa5));
            try std.testing.expectEqual(@as(u16, 3), sockets[0].rx_length);
        }
    }
}
