-- SPDX-License-Identifier: GPL-2.0
-- Copyright (c) 2022 Freysteinn Alfredsson <freysteinn@freysteinn.com>

-- Hierarchical Packet Fair Queueing (HPFQ)
config.bpf.file = "./sched_hpfq.bpf.o"

-- Create flows
packet_flow1 = Udp:new()
packet_flow1.udp.dest = 4000

packet_flow2 = Udp:new()
packet_flow2.udp.dest = 8001

packet_flow3 = Udp:new()
packet_flow3.udp.dest = 8002


function hpfq_test1()
  enqueue(packet_flow1)
  enqueue(packet_flow2)
  enqueue(packet_flow3)

  dequeue_cmp(packet_flow3)
  dequeue_cmp(packet_flow2)
  dequeue_cmp(packet_flow1)
end

function hpfq_debug()
  enqueue(packet_flow1)
  enqueue(packet_flow1)
  dequeue_cmp(packet_flow1)
  dequeue_cmp(packet_flow1)

  enqueue(packet_flow1)
  enqueue(packet_flow1)
  dequeue_cmp(packet_flow1)
  dequeue_cmp(packet_flow1)
end

-- hpfq_test1()

hpfq_debug()
