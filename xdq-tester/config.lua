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
      next_sequence = nil
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
      next_sequence = nil,
    },

    udp = {
      source = 1,
      dest = 1,
      -- len = <set by the framework if not set>,
      -- check = <set by the framework if not set>,
      payload = "",
      next_sequence = udp_payload_enumerator,
    }
  }
}

-- Monitor config.bpf for changes
local _config_bpf = config.bpf
config.bpf = {} -- create proxy table
local config_bpf_mt = {
  __index = function (_, k)
    if k == "file" then
      load_xdq_file(_config_bpf[k])
    end
    return _config_bpf[k]
  end,

  __newindex = function (_, k, v)
    if k == "file" then
      load_xdq_file(v)
    end
    _config_bpf[k] = v
  end
}
setmetatable(config.bpf, config_bpf_mt)
