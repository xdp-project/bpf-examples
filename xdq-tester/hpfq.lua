-- SPDX-License-Identifier: GPL-2.0
-- Copyright (c) 2022 Freysteinn Alfredsson <freysteinn@freysteinn.com>

-- Hierarchical Packet Fair Queueing (HPFQ)
config.bpf.file = "./sched_hpfq.bpf.o"

-- Create flows
flow1 = Udp:new()
flow1.udp.dest = 4000

flow2 = Udp:new()
flow2.udp.dest = 8001

flow3 = Udp:new()
flow3.udp.dest = 8002


function hpfq_test1()
  enqueue(flow1, 1)
  enqueue(flow2, 1)
  enqueue(flow3, 1)

  dequeue_cmp(flow3, 1)
  dequeue_cmp(flow2, 1)
  dequeue_cmp(flow1, 1)
end

function hpfq_debug()
  enqueue(flow1, 1)
  enqueue(flow1, 2)
  dequeue_cmp(flow1, 1)
  dequeue_cmp(flow1, 2)

  enqueue(flow1, 2)
  enqueue(flow1, 3)
  dequeue_cmp(flow1, 2)
  dequeue_cmp(flow1, 3)
end

-- hpfq_test1()

hpfq_debug()
