const r4os = @import("r4os");
const ipv6 = @import("tcp6.zig");

const IPV4_PROTOCOL: u8 = 6;
const HEADER_SIZE: usize = 20;
const OPTION_MSS_MASK: u32 = 0x0000_FFFF;
const OPTION_WINDOW_SCALE_PRESENT: u32 = 1 << 16;
const OPTION_WINDOW_SCALE_SHIFT: u5 = 17;
const MAX_WINDOW_SCALE: u8 = 14;
const MAX_CONNECTIONS: usize = 4;
const BUFFER_SIZE: usize = 256;

const State = enum(u8) {
    closed = 0,
    syn_sent = 1,
    established = 2,
    fin_wait = 3,
};

const Stats = struct {
    rx_segments: u64 = 0,
    tx_segments: u64 = 0,
    syn_tx: u64 = 0,
    synack_rx: u64 = 0,
    ack_tx: u64 = 0,
    data_tx: u64 = 0,
    data_rx: u64 = 0,
    fin_tx: u64 = 0,
    rst_rx: u64 = 0,
    checksum_errors: u64 = 0,
    timeouts: u64 = 0,
};

const Connection = struct {
    used: bool = false,
    id: u32 = 0,
    state: State = .closed,
    local_port: u16 = 0,
    remote_port: u16 = 0,
    remote_ip: [4]u8 = .{0} ** 4,
    seq: u32 = 0,
    ack: u32 = 0,
    tx_bytes: u64 = 0,
    rx_bytes: u64 = 0,
    rx_len: usize = 0,
    rx: [BUFFER_SIZE]u8 = .{0} ** BUFFER_SIZE,
};

const RuntimeState = struct {
    stats: Stats = .{},
    connections: [MAX_CONNECTIONS]Connection = .{Connection{}} ** MAX_CONNECTIONS,
    next_id: u32 = 1,
    next_port: u16 = 49152,
};

var api_view: ?r4os.technical2.Protocol = null;
var state_addr: usize = 1;

comptime {
    if (!@import("builtin").is_test) asm (r4os.technical2.protocolEntriesAsm("nettcp_init", "nettcp_shutdown", "nettcp_query", "nettcp_dispatch"));
}

export fn nettcp_init(api: *const r4os.abi.ProtocolApi2) callconv(.c) i32 {
    const view = r4os.technical2.Protocol.init(api) orelse return r4os.abi.network_error_backend;
    const allocate = view.function("alloc") orelse return r4os.abi.err_no_fn;
    const release = view.function("free") orelse return r4os.abi.err_no_fn;
    const register = view.function("register_role") orelse return r4os.abi.err_no_fn;
    const status = view.function("set_status") orelse return r4os.abi.err_no_fn;
    ipv6.init(api) catch |err| return r4os.network_transport.common.code(err);
    const memory = allocate(@sizeOf(RuntimeState), @alignOf(RuntimeState)) orelse {
        ipv6.stop();
        return -1;
    };
    var published = false;
    defer if (!published) {
        release(memory, @sizeOf(RuntimeState));
        state_addr = 1;
        api_view = null;
        ipv6.stop();
    };
    state_addr = @intFromPtr(memory);
    api_view = view;
    reset();
    if (register("net.tcp", @intFromEnum(r4os.abi.ProtocolCategory.net), 0) != 0) return -1;
    const result = status(@intFromEnum(r4os.abi.ProtocolState.active), "TCP IPv4 codec and real external IPv6 transport");
    if (result != 0) return result;
    published = true;
    return 0;
}

export fn nettcp_shutdown() callconv(.c) i32 {
    if (api_view) |view| {
        if (state_addr > 1) view.function("free").?(@ptrFromInt(state_addr), @sizeOf(RuntimeState));
    }
    ipv6.stop();
    state_addr = 1;
    api_view = null;
    return 0;
}

export fn nettcp_query(out: *r4os.abi.ProtocolStatus) callconv(.c) i32 {
    out.* = .{
        .state = @intFromEnum(r4os.abi.ProtocolState.active),
        .flags = 0,
        .last_error = 0,
        .reserved = 0,
        .note = note("TCP R4P ready"),
    };
    return 0;
}

export fn nettcp_dispatch(op: u32, in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) callconv(.c) i32 {
    if (op >= r4os.abi.network_op_info) return ipv6.dispatch(op, in_buffer, out_buffer);
    const request = requestFromBuffer(in_buffer) orelse return -2;
    switch (op) {
        r4os.abi.tcp_op_connect => connect(request),
        r4os.abi.tcp_op_write => write(request),
        r4os.abi.tcp_op_read => read(request),
        r4os.abi.tcp_op_close => close(request),
        r4os.abi.tcp_op_summary => summary(request),
        r4os.abi.tcp_op_connection_info => connectionInfo(request),
        r4os.abi.tcp_op_handle_rx => handleRx(request, (in_buffer.flags & r4os.abi.protocol_buffer_flag_rx_l4_checksum_valid) != 0),
        r4os.abi.tcp_op_handle_tx => handleTx(request),
        r4os.abi.tcp_op_build_segment => buildSegmentOp(request),
        else => return -4,
    }
    return request.result;
}

fn reset() void {
    const s = state() orelse return;
    s.* = .{};
}

fn state() ?*RuntimeState {
    if (state_addr <= 1) return null;
    return @ptrFromInt(state_addr);
}

fn connect(op: *r4os.abi.TcpOp) void {
    const s = state() orelse {
        op.result = r4os.abi.tcp_result_bad_state;
        return;
    };
    const idx = allocConnection(s) orelse {
        op.result = r4os.abi.tcp_result_no_connection;
        return;
    };
    const conn = &s.connections[idx];
    conn.* = .{
        .used = true,
        .id = s.next_id,
        .state = .syn_sent,
        .local_port = s.next_port,
        .remote_port = op.remote_port,
        .remote_ip = op.remote_ip,
        .seq = 0x1000 + s.next_id,
    };
    s.next_id +%= 1;
    s.next_port +%= 1;
    s.stats.syn_tx += 1;
    s.stats.synack_rx += 1;
    s.stats.ack_tx += 1;
    conn.ack = 0x2001;
    conn.state = .established;
    op.conn_id = conn.id;
    op.local_port = conn.local_port;
    op.result = @intCast(conn.id);
}

fn write(op: *r4os.abi.TcpOp) void {
    const s = state() orelse {
        op.result = r4os.abi.tcp_result_bad_state;
        return;
    };
    const conn = byId(s, op.conn_id) orelse {
        op.result = r4os.abi.tcp_result_no_connection;
        return;
    };
    if (conn.state != .established or op.payload_len > BUFFER_SIZE or op.payload_len > op.payload.len) {
        op.result = r4os.abi.tcp_result_bad_state;
        return;
    }
    const len: usize = @intCast(op.payload_len);
    conn.tx_bytes += len;
    s.stats.data_tx += 1;
    const copy_len = if (len > conn.rx.len) conn.rx.len else len;
    if (copy_len != 0) @memcpy(conn.rx[0..copy_len], op.payload[0..copy_len]);
    conn.rx_len = copy_len;
    conn.rx_bytes += copy_len;
    s.stats.data_rx += 1;
    op.result = @intCast(len);
}

fn read(op: *r4os.abi.TcpOp) void {
    const s = state() orelse {
        op.result = r4os.abi.tcp_result_bad_state;
        return;
    };
    const conn = byId(s, op.conn_id) orelse {
        op.result = r4os.abi.tcp_result_no_connection;
        return;
    };
    if (conn.state == .closed) {
        op.result = r4os.abi.tcp_result_bad_state;
        return;
    }
    const capacity: usize = @min(op.payload.len, @as(usize, @intCast(op.payload_len)));
    const len = if (capacity < conn.rx_len) capacity else conn.rx_len;
    if (len != 0) @memcpy(op.payload[0..len], conn.rx[0..len]);
    conn.rx_len = 0;
    op.payload_len = @intCast(len);
    op.result = @intCast(len);
}

fn close(op: *r4os.abi.TcpOp) void {
    const s = state() orelse {
        op.result = r4os.abi.tcp_result_bad_state;
        return;
    };
    const conn = byId(s, op.conn_id) orelse {
        op.result = r4os.abi.tcp_result_no_connection;
        return;
    };
    if (conn.state != .closed) {
        conn.state = .fin_wait;
        s.stats.fin_tx += 1;
        conn.state = .closed;
        conn.used = false;
    }
    op.result = r4os.abi.tcp_result_ok;
}

fn summary(op: *r4os.abi.TcpOp) void {
    const s = state() orelse {
        op.result = r4os.abi.tcp_result_bad_state;
        return;
    };
    op.summary = .{
        .max_connections = MAX_CONNECTIONS,
        .active_connections = activeCount(s),
        .buffer_size = BUFFER_SIZE,
        .syn_tx = s.stats.syn_tx,
        .synack_rx = s.stats.synack_rx,
        .ack_tx = s.stats.ack_tx,
        .data_tx = s.stats.data_tx,
        .data_rx = s.stats.data_rx,
        .fin_tx = s.stats.fin_tx,
        .rst_rx = s.stats.rst_rx,
        .checksum_errors = s.stats.checksum_errors,
        .timeouts = s.stats.timeouts,
    };
    op.result = r4os.abi.tcp_result_ok;
}

fn connectionInfo(op: *r4os.abi.TcpOp) void {
    const s = state() orelse {
        op.result = 0;
        return;
    };
    if (op.index >= MAX_CONNECTIONS) {
        op.result = 0;
        return;
    }
    const conn = &s.connections[@intCast(op.index)];
    if (!conn.used) {
        op.result = 0;
        return;
    }
    op.info = .{
        .id = conn.id,
        .state = @intFromEnum(conn.state),
        .local_port = conn.local_port,
        .remote_port = conn.remote_port,
        .remote_ip = conn.remote_ip,
        .tx_bytes = conn.tx_bytes,
        .rx_bytes = conn.rx_bytes,
        .pending_rx = @intCast(conn.rx_len),
    };
    op.result = 1;
}

fn handleRx(op: *r4os.abi.TcpOp, l4_checksum_valid: bool) void {
    const s = state() orelse {
        op.result = r4os.abi.tcp_result_bad_state;
        return;
    };
    inspect(op, l4_checksum_valid);
    if (op.result != r4os.abi.tcp_result_ok) return;
    s.stats.rx_segments += 1;
    if ((op.flags & r4os.abi.tcp_flag_rst) != 0) s.stats.rst_rx += 1;
}

fn handleTx(op: *r4os.abi.TcpOp) void {
    const s = state() orelse {
        op.result = r4os.abi.tcp_result_bad_state;
        return;
    };
    inspect(op, false);
    if (op.result != r4os.abi.tcp_result_ok) return;
    s.stats.tx_segments += 1;
}

fn inspect(op: *r4os.abi.TcpOp, l4_checksum_valid: bool) void {
    op.payload_len = 0;
    op.index = 0;
    if (op.segment_len < HEADER_SIZE or op.segment_len > op.segment.len) {
        op.result = r4os.abi.tcp_result_short;
        return;
    }
    const segment = op.segment[0..@intCast(op.segment_len)];
    const data_offset = segment[12] >> 4;
    const header_len = @as(usize, data_offset) * 4;
    if (data_offset < 5 or segment.len < header_len) {
        op.result = r4os.abi.tcp_result_short;
        return;
    }
    if (!l4_checksum_valid and checksum(op.source_ip, op.dest_ip, segment) != 0) {
        if (state()) |s| s.stats.checksum_errors += 1;
        op.result = r4os.abi.tcp_result_checksum;
        return;
    }
    op.source_port = readBe16(segment, 0);
    op.dest_port = readBe16(segment, 2);
    op.seq = readBe32(segment, 4);
    op.ack = readBe32(segment, 8);
    op.flags = @intCast(segment[13]);
    op.reserved = readBe16(segment, 14);
    op.index = inspectOptions(segment[HEADER_SIZE..header_len]) orelse {
        op.result = r4os.abi.tcp_result_short;
        return;
    };
    const payload = segment[header_len..];
    op.payload_len = @intCast(payload.len);
    if (payload.len > 0) @memcpy(op.payload[0..payload.len], payload);
    op.result = r4os.abi.tcp_result_ok;
}

fn buildSegmentOp(op: *r4os.abi.TcpOp) void {
    if (op.payload_len > op.payload.len) {
        op.result = r4os.abi.tcp_result_buffer_small;
        return;
    }
    const payload_len: usize = @intCast(op.payload_len);
    const option_len: usize = if ((op.flags & r4os.abi.tcp_flag_syn) != 0) optionLength(op.index) else 0;
    const header_len = HEADER_SIZE + option_len;
    const len = header_len + payload_len;
    if (len > 0xFFFF or len > op.segment.len) {
        op.result = r4os.abi.tcp_result_buffer_small;
        return;
    }
    var i: usize = 0;
    while (i < len) : (i += 1) op.segment[i] = 0;
    writeBe16(op.segment[0..], 0, op.source_port);
    writeBe16(op.segment[0..], 2, op.dest_port);
    writeBe32(op.segment[0..], 4, op.seq);
    writeBe32(op.segment[0..], 8, op.ack);
    op.segment[12] = @as(u8, @intCast(header_len / 4)) << 4;
    op.segment[13] = @intCast(op.flags & 0x3F);
    writeBe16(op.segment[0..], 14, op.reserved);
    writeOptions(op.segment[HEADER_SIZE..header_len], op.index);
    i = 0;
    while (i < payload_len) : (i += 1) op.segment[header_len + i] = op.payload[i];
    writeBe16(op.segment[0..], 16, checksum(op.source_ip, op.dest_ip, op.segment[0..len]));
    op.segment_len = @intCast(len);
    op.result = r4os.abi.tcp_result_ok;
}

fn inspectOptions(options: []const u8) ?u32 {
    var metadata: u32 = 0;
    var offset: usize = 0;
    while (offset < options.len) {
        const kind = options[offset];
        if (kind == 0) break; // End of option list.
        if (kind == 1) { // NOP.
            offset += 1;
            continue;
        }
        if (offset + 1 >= options.len) return null;
        const length: usize = options[offset + 1];
        if (length < 2 or offset + length > options.len) return null;
        switch (kind) {
            2 => if (length == 4) {
                const mss = readBe16(options, offset + 2);
                if (mss != 0) metadata = (metadata & ~OPTION_MSS_MASK) | mss;
            },
            3 => if (length == 3) {
                const scale = @min(options[offset + 2], MAX_WINDOW_SCALE);
                metadata |= OPTION_WINDOW_SCALE_PRESENT;
                metadata &= ~(@as(u32, 0x0F) << OPTION_WINDOW_SCALE_SHIFT);
                metadata |= @as(u32, scale) << OPTION_WINDOW_SCALE_SHIFT;
            },
            else => {},
        }
        offset += length;
    }
    return metadata;
}

fn optionLength(metadata: u32) usize {
    var length: usize = 0;
    if ((metadata & OPTION_MSS_MASK) != 0) length += 4;
    if ((metadata & OPTION_WINDOW_SCALE_PRESENT) != 0) length += 4; // NOP + WS(3).
    return length;
}

fn writeOptions(out: []u8, metadata: u32) void {
    var offset: usize = 0;
    const mss: u16 = @truncate(metadata & OPTION_MSS_MASK);
    if (mss != 0) {
        out[offset] = 2;
        out[offset + 1] = 4;
        writeBe16(out, offset + 2, mss);
        offset += 4;
    }
    if ((metadata & OPTION_WINDOW_SCALE_PRESENT) != 0) {
        out[offset] = 1;
        out[offset + 1] = 3;
        out[offset + 2] = 3;
        out[offset + 3] = @truncate((metadata >> OPTION_WINDOW_SCALE_SHIFT) & 0x0F);
    }
}

fn requestFromBuffer(buffer: *const r4os.abi.ProtocolBuffer) ?*r4os.abi.TcpOp {
    const native = r4os.native_protocol_view;
    var policy = native.Policy.record(r4os.abi.TcpOp, .inout, .prefix);
    // This flag only admits the existing trusted RX metadata; the operation
    // still decides whether it may skip its wire checksum. TX never does.
    policy.allowed_flags = r4os.abi.protocol_buffer_flag_rx_l4_checksum_valid;
    var metadata = buffer.*;
    const view = native.InOut(r4os.abi.TcpOp).init(&metadata, policy) catch return null;
    return view.value;
}

fn allocConnection(s: *RuntimeState) ?usize {
    var i: usize = 0;
    while (i < s.connections.len) : (i += 1) {
        if (!s.connections[i].used) return i;
    }
    return null;
}

fn byId(s: *RuntimeState, id: u32) ?*Connection {
    var i: usize = 0;
    while (i < s.connections.len) : (i += 1) {
        if (s.connections[i].used and s.connections[i].id == id) return &s.connections[i];
    }
    return null;
}

fn activeCount(s: *RuntimeState) u32 {
    var count: u32 = 0;
    for (&s.connections) |*conn| {
        if (conn.used) count += 1;
    }
    return count;
}

fn checksum(source_ip: [4]u8, dest_ip: [4]u8, segment: []const u8) u16 {
    // The protocol retains pseudoheader composition and UDP zero policy.
    var header: [4]u8 = .{ 0, IPV4_PROTOCOL, 0, 0 };
    var writer = r4os.binary_cursor.Writer.init(&header) catch unreachable;
    writer.position = 2;
    writer.writeInt(u16, @intCast(segment.len), .big) catch unreachable;
    var value: r4os.internet_checksum.Checksum16 = .{};
    value.add(&source_ip) catch unreachable;
    value.add(&dest_ip) catch unreachable;
    value.add(&header) catch unreachable;
    value.add(segment) catch unreachable;
    return value.finish() catch unreachable;
}

fn readBe16(buf: []const u8, offset: usize) u16 {
    var reader = r4os.binary_cursor.Reader.init(buf) catch unreachable;
    _ = reader.take(offset) catch unreachable;
    return reader.readInt(u16, .big) catch unreachable;
}

fn readBe32(buf: []const u8, offset: usize) u32 {
    var reader = r4os.binary_cursor.Reader.init(buf) catch unreachable;
    _ = reader.take(offset) catch unreachable;
    return reader.readInt(u32, .big) catch unreachable;
}

fn writeBe16(buf: []u8, offset: usize, value: u16) void {
    var writer = r4os.binary_cursor.Writer.init(buf) catch unreachable;
    writer.position = offset;
    writer.writeInt(u16, value, .big) catch unreachable;
}

fn writeBe32(buf: []u8, offset: usize, value: u32) void {
    var writer = r4os.binary_cursor.Writer.init(buf) catch unreachable;
    writer.position = offset;
    writer.writeInt(u32, value, .big) catch unreachable;
}

fn note(comptime text: []const u8) [64]u8 {
    var out: [64]u8 = .{0} ** 64;
    @memcpy(out[0..text.len], text);
    return out;
}

test "TCP provider publication failure retires both exact allocations; original wire flags stay scoped" {
    const std = @import("std");
    const a = r4os.abi;
    const Owner = struct {
        var memory: [2][524288]u8 align(64) = undefined;
        var bytes: [2]u32 = .{ 0, 0 };
        var live: [2]bool = .{ false, false };
        var allocated: usize = 0;
        var released: usize = 0;
        var registered: usize = 0;
        var statuses: usize = 0;
        var mode: u8 = 0;
        var bad: bool = false;
        fn clear(next_mode: u8) void {
            bytes = .{ 0, 0 };
            live = .{ false, false };
            allocated = 0;
            released = 0;
            registered = 0;
            statuses = 0;
            bad = false;
            mode = next_mode;
        }
        fn alloc(length: u32, alignment: u32) callconv(.c) ?*anyopaque {
            const index = allocated;
            allocated += 1;
            if (index >= 2 or length > memory[0].len or alignment > 64) {
                bad = true;
                return null;
            }
            if (mode == 3 and index == 1) return null;
            bytes[index] = length;
            live[index] = true;
            return &memory[index];
        }
        fn free(pointer: ?*anyopaque, length: u32) callconv(.c) void {
            for (0..2) |index| {
                if (pointer != @as(*anyopaque, @ptrCast(&memory[index]))) continue;
                if (!live[index] or bytes[index] != length) bad = true;
                live[index] = false;
                released += 1;
                return;
            }
            bad = true;
        }
        fn register(_: [*:0]const u8, _: u32, _: u32) callconv(.c) i32 {
            registered += 1;
            return if (mode == 1) -42 else 0;
        }
        fn status(_: u32, _: [*:0]const u8) callconv(.c) i32 {
            statuses += 1;
            return if (mode == 2) -43 else 0;
        }
    };
    var raw: a.ProtocolApi2 = undefined;
    @memset(std.mem.asBytes(&raw), 0);
    raw.magic = r4os.technical2.abi.protocol_magic;
    raw.version = r4os.technical2.abi.protocol_version;
    raw.size = @sizeOf(a.ProtocolApi2);
    Owner.clear(0);
    try std.testing.expectEqual(a.err_no_fn, nettcp_init(&raw));
    try std.testing.expectEqual(@as(usize, 0), Owner.allocated);
    raw.alloc = Owner.alloc;
    raw.free = Owner.free;
    raw.register_role = Owner.register;
    raw.set_status = Owner.status;
    raw.protocol_dispatch = @ptrFromInt(8);
    raw.link_io = @ptrFromInt(8);
    raw.process_status = @ptrFromInt(8);
    raw.entropy_fill = @ptrFromInt(8);
    for ([_]u8{ 1, 2, 3, 0 }) |mode| {
        Owner.clear(mode);
        const code = nettcp_init(&raw);
        try std.testing.expectEqual(@as(i32, switch (mode) {
            1, 3 => -1,
            2 => -43,
            else => 0,
        }), code);
        if (mode == 0) {
            try std.testing.expect(state() != null and Owner.live[0] and Owner.live[1]);
            try std.testing.expectEqual(@as(i32, 0), nettcp_shutdown());
            try std.testing.expectEqual(@as(i32, 0), nettcp_shutdown());
        }
        try std.testing.expect(state() == null and !Owner.live[0] and !Owner.live[1] and !Owner.bad);
        try std.testing.expectEqual(@as(usize, if (mode == 3) 1 else 2), Owner.released);
        try std.testing.expectEqual(@as(usize, if (mode == 3) 0 else 1), Owner.registered);
        try std.testing.expectEqual(@as(usize, if (mode == 1 or mode == 3) 0 else 1), Owner.statuses);
    }
    Owner.clear(0);
    try std.testing.expectEqual(@as(i32, 0), nettcp_init(&raw));
    defer _ = nettcp_shutdown();
    var op: a.TcpOp = .{ .segment_len = 20 };
    op.segment[12] = 0x50;
    // Deliberately corrupt wire checksum: only the pre-existing trusted RX
    // flag may bypass verification. No output or TX operation acquires it.
    var input: a.ProtocolBuffer = .{ .data = &op, .len = @sizeOf(a.TcpOp), .capacity = @sizeOf(a.TcpOp) };
    var output: a.ProtocolBuffer = .{};
    try std.testing.expectEqual(a.tcp_result_checksum, nettcp_dispatch(a.tcp_op_handle_rx, &input, &output));
    input.flags = a.protocol_buffer_flag_rx_l4_checksum_valid;
    try std.testing.expectEqual(a.tcp_result_ok, nettcp_dispatch(a.tcp_op_handle_rx, &input, &output));
    try std.testing.expectEqual(a.tcp_result_checksum, nettcp_dispatch(a.tcp_op_handle_tx, &input, &output));
    input.flags |= 0x80000000;
    const before = std.mem.asBytes(&op).*;
    try std.testing.expectEqual(@as(i32, -2), nettcp_dispatch(a.tcp_op_handle_rx, &input, &output));
    try std.testing.expectEqualSlices(u8, &before, std.mem.asBytes(&op));
}
