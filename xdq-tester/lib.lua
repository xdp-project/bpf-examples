-- SPDX-License-Identifier: GPL-2.0
-- Copyright (c) 2022 Freysteinn Alfredsson <freysteinn@freysteinn.com>

IPPROTO_UDP = 17
ETH_P_IPV6 = 0x86dd

XDP_ABORTED = 0
XDP_DROP = 1
XDP_PASS = 2
XDP_TX = 3
XDP_REDIRECT = 4

config = {
  bpf = {
    file = "./sched_fifo.bpf.o",
    xdp_func = "enqueue_prog",
    dequeue_func = "dequeue_prog",
  },

  defaultUdp = {
    eth = {
      proto = ETH_P_IPV6,
      source = "01:00:00:00:00:01",
      dest = "01:00:00:00:00:02",
    },

    ip = {
      priority = 0,
      version = 6,
      flow_lbl = { 0, 0, 0 },
      -- payload_len = <set by framework if not set>,
      nexthdr = IPPROTO_UDP,
      hop_limit = 1,
      saddr = "fe80::1",
      daddr = "fe80::2",
    },

    udp = {
      source = 1,
      dest = 1,
      -- len = <set by the framework if not set>,
      -- check = <set by the framework if not set>,
      payload = ""
    }
  }
}

xdq = {
  total_queued = 0,
  total_dequeued = 0,
  currently_queued = 0,
}

-- Monitor config.bpf for changes
local _config_bpf = config.bpf
config.bpf = {} -- create proxy table
local config_bpf_mt = {
  __index = function (t,k)
    if k == "file" then
      load_xdq_file(_config_bpf[k])
    end
    return _config_bpf[k]
  end,

  __newindex = function (t,k,v)
    if k == "file" then
      load_xdq_file(v)
    end
    _config_bpf[k] = v
  end
}
setmetatable(config.bpf, config_bpf_mt)

function table_has_key(table,key)
    return table[key] ~= nil
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
  local cmp_ip_saddr = nil
  local ip_saddr = nil
  local cmp_ip_daddr = nil
  local ip_daddr = nil

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
    fail(string.format("expected udp.payload: %s, but found %s", cmp_udp.payload, udp.payload));
  end
end

function dequeue_cmp(cmp)
  local packet, retval = dequeue()
  local protocol = nil

  if type(cmp) ~= "table" then
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
  compare_eth(cmp.eth, packet.eth)
  if cmp.eth.proto == ETH_P_IPV6 then
    if type(cmp.ip) ~= "table" then
      fail("comparision packet missing ip table")
    end
    if type(packet.ip) ~= "table" then
      fail("dequeued packet missing ip table")
    end
    compare_ip(cmp.ip, packet.ip)
    protocol = cmp.ip.nexthdr
  end
  if protocol == IPPROTO_UDP then
    if type(cmp.udp) ~= "table" then
      fail("comparision packet missing udp table")
    end
    if type(packet.udp) ~= "table" then
      fail("dequeued packet missing udp table")
    end
    compare_udp(cmp.udp, packet.udp)
  end
  return packet, retval
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

function dump(o)
    if type(o) == 'table' then
        local s = '{\n'
        for k,v in pairs(o) do
                if type(k) ~= 'number' then k = '"'..k..'"' end
                s = s .. '\t['..k..'] = ' .. dump(v) .. ',\n'
        end
        return s .. '}\n'
    else
        return tostring(o)
    end
end

function copy(obj)
    if type(obj) ~= 'table' then return obj end
    local res = {}
    for k, v in pairs(obj) do res[copy(k)] = copy(v) end
    return res
end

Udp = {
}

function Udp:new()
  -- meta = {}
  -- meta.__index = function (table, key)
  --   return config.defaultUdp[key]
  -- end
  obj = copy(config.defaultUdp)
  -- setmetatable(obj, meta)
  return obj
end
