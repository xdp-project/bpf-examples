-- SPDX-License-Identifier: GPL-2.0
-- Copyright (c) 2022 Freysteinn Alfredsson <freysteinn@freysteinn.com>

-- Test metadata
config.bpf.file = "./sched_test.bpf.o"

-- Setup flows
adjust_meta(8)
flow1 = Udp:new()
flow1.udp.dest = 8080
flow1.udp.payload = create_payload(4)

flow2 = Udp:new()
flow2.udp.dest = 8081
flow2.udp.payload = create_payload(10)

-- Test scheduler
function test()
  enqueue(flow1, 1)
  dequeue_cmp(flow1, 1)

  set_time_ns(100)
  enqueue(flow2, 1)
  packet = dequeue()
  cmp(packet, flow2, 1)
  print(dump(packet))
  cmp(packet, flow1, 1)
end

test()
