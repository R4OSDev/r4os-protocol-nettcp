const r4os = @import("r4os");

const IPV4_PROTOCOL: u8 = 6;
const HEADER_SIZE: usize = 20;
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

var api_addr: usize = 1;
var state_addr: usize = 1;

comptime {
    asm (r4os.r4dev.protocolEntriesAsm("nettcp_init", "nettcp_shutdown", "nettcp_query", "nettcp_dispatch"));
}

export fn nettcp_init(api: *const r4os.r4dev.ProtocolApi) callconv(.c) i32 {
    var ctx = r4os.r4dev.ProtocolContext.init(api);
    api_addr = @intFromPtr(api);
    const memory = ctx.alloc(@sizeOf(RuntimeState), @alignOf(RuntimeState)) orelse {
        ctx.logError("NETTCP.R4P state allocation failed");
        return -1;
    };
    state_addr = @intFromPtr(memory);
    reset();
    ctx.logInfo("NETTCP.R4P init");
    _ = ctx.registerRole("net.tcp", .net, 0);
    _ = ctx.setStatus(.active, "TCP R4P active");
    return 0;
}

export fn nettcp_shutdown() callconv(.c) i32 {
    if (context()) |ctx| {
        if (state_addr > 1) ctx.free(@ptrFromInt(state_addr), @sizeOf(RuntimeState));
    }
    state_addr = 1;
    api_addr = 1;
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
    _ = out_buffer;
    const request = requestFromBuffer(in_buffer) orelse return -2;
    switch (op) {
        r4os.abi.tcp_op_connect => connect(request),
        r4os.abi.tcp_op_write => write(request),
        r4os.abi.tcp_op_read => read(request),
        r4os.abi.tcp_op_close => close(request),
        r4os.abi.tcp_op_summary => summary(request),
        r4os.abi.tcp_op_connection_info => connectionInfo(request),
        r4os.abi.tcp_op_handle_rx => handleRx(request),
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

fn context() ?r4os.r4dev.ProtocolContext {
    if (api_addr <= 1) return null;
    return r4os.r4dev.ProtocolContext.init(@ptrFromInt(api_addr));
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

fn handleRx(op: *r4os.abi.TcpOp) void {
    const s = state() orelse {
        op.result = r4os.abi.tcp_result_bad_state;
        return;
    };
    inspect(op);
    if (op.result != r4os.abi.tcp_result_ok) return;
    s.stats.rx_segments += 1;
    if ((op.flags & r4os.abi.tcp_flag_rst) != 0) s.stats.rst_rx += 1;
}

fn handleTx(op: *r4os.abi.TcpOp) void {
    const s = state() orelse {
        op.result = r4os.abi.tcp_result_bad_state;
        return;
    };
    inspect(op);
    if (op.result != r4os.abi.tcp_result_ok) return;
    s.stats.tx_segments += 1;
}

fn inspect(op: *r4os.abi.TcpOp) void {
    op.payload_len = 0;
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
    if (checksum(op.source_ip, op.dest_ip, segment) != 0) {
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
    const len = HEADER_SIZE + payload_len;
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
    op.segment[12] = 5 << 4;
    op.segment[13] = @intCast(op.flags & 0x3F);
    writeBe16(op.segment[0..], 14, op.reserved);
    i = 0;
    while (i < payload_len) : (i += 1) op.segment[HEADER_SIZE + i] = op.payload[i];
    writeBe16(op.segment[0..], 16, checksum(op.source_ip, op.dest_ip, op.segment[0..len]));
    op.segment_len = @intCast(len);
    op.result = r4os.abi.tcp_result_ok;
}

fn requestFromBuffer(buffer: *const r4os.abi.ProtocolBuffer) ?*r4os.abi.TcpOp {
    if (buffer.data == null) return null;
    if (buffer.len < @sizeOf(r4os.abi.TcpOp)) return null;
    return @ptrCast(@alignCast(buffer.data.?));
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
    var sum: u32 = 0;
    sum = addIp(sum, source_ip);
    sum = addIp(sum, dest_ip);
    sum += IPV4_PROTOCOL;
    sum += @intCast(segment.len);
    var i: usize = 0;
    while (i + 1 < segment.len) : (i += 2) {
        sum += (@as(u32, segment[i]) << 8) | segment[i + 1];
    }
    if (i < segment.len) sum += @as(u32, segment[i]) << 8;
    while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
    return @intCast(~sum & 0xFFFF);
}

fn addIp(sum_in: u32, ip: [4]u8) u32 {
    return sum_in + (@as(u32, ip[0]) << 8 | ip[1]) + (@as(u32, ip[2]) << 8 | ip[3]);
}

fn readBe16(buf: []const u8, offset: usize) u16 {
    return (@as(u16, buf[offset]) << 8) | buf[offset + 1];
}

fn readBe32(buf: []const u8, offset: usize) u32 {
    return (@as(u32, buf[offset]) << 24) | (@as(u32, buf[offset + 1]) << 16) | (@as(u32, buf[offset + 2]) << 8) | buf[offset + 3];
}

fn writeBe16(buf: []u8, offset: usize, value: u16) void {
    buf[offset] = @intCast(value >> 8);
    buf[offset + 1] = @intCast(value & 0xFF);
}

fn writeBe32(buf: []u8, offset: usize, value: u32) void {
    buf[offset] = @intCast(value >> 24);
    buf[offset + 1] = @intCast((value >> 16) & 0xFF);
    buf[offset + 2] = @intCast((value >> 8) & 0xFF);
    buf[offset + 3] = @intCast(value & 0xFF);
}

fn note(comptime text: []const u8) [64]u8 {
    var out: [64]u8 = .{0} ** 64;
    @memcpy(out[0..text.len], text);
    return out;
}
