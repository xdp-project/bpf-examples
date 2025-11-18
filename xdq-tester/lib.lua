-- SPDX-License-Identifier: GPL-2.0
-- Copyright (c) 2022 Freysteinn Alfredsson <freysteinn@freysteinn.com>

xdq = {
  total_queued = 0,
  total_dequeued = 0,
  currently_queued = 0,
}

function table_has_key(table, key)
  return table[key] ~= nil
end

function hex_dump(buf)
  return buf:gsub('.', function (c) return string.format('%02x ', string.byte(c)) end)
end

function trim_hex(hex)
  local result = hex
  local max_length = 16 * 3 -- Each byte is two hex characters followed by a space
  local length = #hex
  result = result:gsub(' +$', '')
  if (#result > max_length) then
    result = result:sub(1, max_length)
    result = result .. '... (' .. string.format('%d', length) .. ' bytes)'
  end
  return result
end

function compare_eth(cmp_eth, eth)
  if type(cmp_eth.proto) ~= "number" then
    fail("comparison eth.proto must be a number")
  end
  if type(eth.proto) ~= "number" then
    fail("dequeued eth.proto must be a number")
  end
  if cmp_eth.proto ~= eth.proto then
    fail(string.format("expected eth.proto: 0x%x, but found 0x%x", cmp_eth.proto, eth.proto));
  end

  if type(cmp_eth.source) ~= "string" then
    fail("comparison eth.source must be a string")
  end
  if type(eth.source) ~= "string" then
    fail("dequeued eth.source must be a string")
  end
  if cmp_eth.source ~= eth.source then
    fail(string.format("expected eth.source: %s, but found %s", cmp_eth.source, eth.source));
  end

  if type(cmp_eth.dest) ~= "string" then
    fail("comparison eth.dest must be a string")
  end
  if type(eth.dest) ~= "string" then
    fail("dequeued eth.dest must be a string")
  end
  if cmp_eth.dest ~= eth.dest then
    fail(string.format("expected eth.dest: %s, but found %s", cmp_eth.dest, eth.dest));
  end
end

function compare_ip(cmp_ip, ip)
  local cmp_ip_saddr
  local ip_saddr
  local cmp_ip_daddr
  local ip_daddr

  if type(cmp_ip.priority) ~= "number" then
    fail("comparison ip.priority must be a number")
  end
  if type(ip.priority) ~= "number" then
    fail("dequeued ip.priority must be a number")
  end
  if cmp_ip.priority ~= ip.priority then
    fail(string.format("expected ip.priority: %d, but found %d", cmp_ip.priority, ip.priority));
  end

  if type(cmp_ip.version) ~= "number" then
    fail("comparison ip.version must be a number")
  end
  if type(ip.version) ~= "number" then
    fail("dequeued ip.version must be a number")
  end
  if cmp_ip.version ~= ip.version then
    fail(string.format("expected ip.version: %d, but found %d", cmp_ip.version, ip.version));
  end

  if type(cmp_ip.flow_lbl) ~= "table" then
    fail("comparison ip.flow_lbl not a table")
  end
  if type(ip.flow_lbl) ~= "table" then
    fail("dequeue ip.flow_lbl not a table")
  end
  for i = 1, 3, 1 do
    if type(cmp_ip.flow_lbl[i]) ~= "number" then
      fail(string.format("comparison ip.flow_lbl[%d] must be a number", i))
    end
    if type(ip.flow_lbl[i]) ~= "number" then
      fail(string.format("dequeued ip.flow_lbl[%d] must be a number", i))
    end
    if cmp_ip.flow_lbl[i] ~= ip.flow_lbl[i] then
      fail(string.format("expected ip.flow_lbl[%d]: %d, but found %d", i, cmp_ip.flow_lbl[i], ip.flow_lbl[i]));
    end
  end

  -- TODO: Add function that calculates the payload_len in lua
  -- if type(cmp_ip.payload_len) ~= "number" then
  --   fail("comparison ip.payload_len must be a number")
  -- end
  -- if type(ip.payload_len) ~= "number" then
  --   fail("dequeued ip.payload_len must be a number")
  -- end
  -- if cmp_ip.payload_len ~= ip.payload_len then
  --   fail(string.format("expected ip.payload_len: %s, but found %s", cmp_ip.payload_len, ip.payload_len));
  -- end

  if type(cmp_ip.nexthdr) ~= "number" then
    fail("comparison ip.nexthdr must be a number")
  end
  if type(ip.nexthdr) ~= "number" then
    fail("dequeued ip.nexthdr must be a number")
  end
  if cmp_ip.nexthdr ~= ip.nexthdr then
    fail(string.format("expected ip.nexthdr: %d, but found %d", cmp_ip.nexthdr, ip.nexthdr));
  end

  if type(cmp_ip.hop_limit) ~= "number" then
    fail("comparison ip.hop_limit must be a number")
  end
  if type(ip.hop_limit) ~= "number" then
    fail("dequeued ip.hop_limit must be a number")
  end
  if cmp_ip.hop_limit ~= ip.hop_limit then
    fail(string.format("expected ip.hop_limit: %d, but found %d", cmp_ip.hop_limit, ip.hop_limit));
  end

  if type(cmp_ip.saddr) ~= "string" then
    fail("comparison ip.saddr must be a string")
  end
  if type(ip.saddr) ~= "string" then
    fail("dequeued ip.saddr must be a string")
  end
  cmp_ip_saddr = normalize_ipv6_address(cmp_ip.saddr)
  ip_saddr = normalize_ipv6_address(ip.saddr)
  if cmp_ip_saddr ~= ip_saddr then
    fail(string.format("expected ip.saddr: %s, but found %s", cmp_ip_saddr, ip_saddr));
  end

  if type(cmp_ip.daddr) ~= "string" then
    fail("comparison ip.daddr must be a string")
  end
  if type(ip.daddr) ~= "string" then
    fail("dequeued ip.daddr must be a string")
  end
  cmp_ip_daddr = normalize_ipv6_address(cmp_ip.daddr)
  ip_daddr = normalize_ipv6_address(ip.daddr)
  if cmp_ip_daddr ~= ip_daddr then
    fail(string.format("expected ip.daddr: %s, but found %s", cmp_ip_daddr, ip_daddr));
  end
end

function compare_udp(cmp_udp, udp)
  if type(cmp_udp.source) ~= "number" then
    fail("comparison udp.source must be a number")
  end
  if type(udp.source) ~= "number" then
    fail("dequeued udp.source must be a number")
  end
  if cmp_udp.source ~= udp.source then
    fail(string.format("expected udp.source: %d, but found %d", cmp_udp.source, udp.source));
  end

  if type(cmp_udp.dest) ~= "number" then
    fail("comparison udp.dest must be a number")
  end
  if type(udp.dest) ~= "number" then
    fail("dequeued udp.dest must be a number")
  end
  if cmp_udp.dest ~= udp.dest then
    fail(string.format("expected udp.dest: %d, but found %d", cmp_udp.dest, udp.dest));
  end

    -- TODO: Add len when missing
  -- if type(cmp_udp.len) ~= "number" then
  --   fail("comparison udp.len must be a number")
  -- end
  -- if type(udp.len) ~= "number" then
  --   fail("dequeued udp.len must be a number")
  -- end
  -- if cmp_udp.len ~= udp.len then
  --   fail(string.format("expected udp.len: %d, but found %d", cmp_udp.sourc, udp.len));

    -- TODO: Add lua function that creates UDP checksum
  -- if type(cmp_udp.check) ~= "number" then
  --   fail("comparison udp.check must be a number")
  -- end
  -- if type(udp.check) ~= "number" then
  --   fail("dequeued udp.check must be a number")
  -- end
  -- if cmp_udp.check ~= udp.check then
  --   fail(string.format("expected udp.check: %d, but found %d", cmp_udp.sourc, udp.check));

  if type(cmp_udp.payload) ~= "string" then
    fail("comparison udp.payload must be a string")
  end
  if type(udp.payload) ~= "string" then
    fail("dequeued udp.payload must be a string")
  end
  if cmp_udp.payload ~= udp.payload then
    local cmp_payload, _ = trim_hex(hex_dump(cmp_udp.payload))
    local payload, _ = trim_hex(hex_dump(udp.payload))
    fail(string.format("expected udp.payload: %s,\n" ..
                       "                    but found: %s", cmp_payload, payload));
  end
end

function update_sequence(packet, packet_nr)
  for _, v in pairs(packet) do
    if type(v) == "table" then
      if type(v.next_sequence) == "function" then
        v.next_sequence(packet, packet_nr)
      end
    end
  end
end

function enqueue(packet, packet_nr)
  update_sequence(packet, packet_nr)
  return xdq_enqueue(packet)
end

function dequeue()
  return xdq_dequeue()
end

function cmp(packet, cmp_packet, packet_nr)
  if type(cmp_packet) ~= "table" then
    fail("parameter not a table")
  end
  if type(packet) ~= "table" then
    fail("dequeue failed")
  end

  if type(packet.eth) ~= "table" then
    fail("comparision packet missing eth table")
  end
  if type(packet.eth) ~= "table" then
    fail("dequeued packet missing eth table")
  end
  compare_eth(cmp_packet.eth, packet.eth)
  if cmp_packet.eth.proto == ETH_P_IPV6 then
    if type(cmp_packet.ip) ~= "table" then
      fail("comparision packet missing ip table")
    end
    if type(packet.ip) ~= "table" then
      fail("dequeued packet missing ip table")
    end
    compare_ip(cmp_packet.ip, packet.ip)
    protocol = cmp_packet.ip.nexthdr
  end
  if protocol == IPPROTO_UDP then
    if type(cmp_packet.udp) ~= "table" then
      fail("comparision packet missing udp table")
    end
    if type(packet.udp) ~= "table" then
      fail("dequeued packet missing udp table")
    end
    update_sequence(cmp_packet, packet_nr)
    compare_udp(cmp_packet.udp, packet.udp)
  end
end

function dequeue_cmp(cmp_packet, packet_nr)
  local packet, retval = dequeue()
  cmp(packet, cmp_packet, packet_nr)
  return packet, retval
end

function udp_payload_enumerator(packet, packet_nr)
  local payload
  local nr_str
  if type(packet_nr) ~= "number" then
    fail("The packet sequence number must be a number")
  end
  if type(packet.udp.payload) ~= 'string' then
    fail("'packet.udp.payload' must be a string")
  end
  payload = packet.udp.payload
  nr_str = string.pack("L", packet_nr)
  if (#payload > 0 and #payload < #nr_str) then
    print("Warning: payload is smaller than the udp enumerator")
  end
  packet.udp.payload = nr_str .. payload:sub(#nr_str + 1)
end

function create_payload(len)
  if type(len) ~= 'number' then
    fail("parameter must be a number")
  end
  if len < 0 then
    fail("length parameter can't be a negative value")
  end
  return string.rep("A", len)
end

function dump_rep(o, rep)
  if type(o) == 'table' then
    local indent = string.rep("    ", rep)
    local s = '{\n'
    for k, v in pairs(o) do
      if k == 'payload' then
        v = trim_hex(hex_dump(v))
      end
      k = '"' .. k .. '"'
      s = s .. indent ..  k .. ': ' .. dump_rep(v, rep + 1) .. ',\n'
    end
    indent = string.rep('    ', rep - 1)
    s = s:gsub(',\n$', '\n')
    return s .. indent .. '}'
  else
    if type(o) ~= 'number' then
      o = '"' .. tostring(o) .. '"'
    end
    return tostring(o)
  end
end

function dump(o)
  return dump_rep(o, 1)
end

function copy(obj)
  if type(obj) ~= 'table' then
    return obj
  end
  local res = {}
  for k, v in pairs(obj) do
    res[copy(k)] = copy(v)
  end
  return res
end

Udp = {
}

function Udp:new()
  return copy(config.defaultUdp)
end
