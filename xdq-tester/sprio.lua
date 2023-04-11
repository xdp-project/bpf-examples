-- SPDX-License-Identifier: GPL-2.0
-- Copyright (c) 2022 Freysteinn Alfredsson <freysteinn@freysteinn.com>

-- Strict Priority scheduler (SPRIO)
config.bpf.file = "./sched_sprio.bpf.o"

-- Create flows
flow1 = Udp:new()
flow1.udp.dest = 8080
set_flow_weight(flow1, 2)

flow2 = Udp:new()
flow2.udp.dest = 8081
set_flow_weight(flow2, 1)

flow3 = Udp:new()
flow3.udp.dest = 8082
set_flow_weight(flow3, 0)

-- Test scheduler
enqueue(flow1, 1)
enqueue(flow2, 1)
enqueue(flow3, 1)

dequeue_cmp(flow3, 1)
dequeue_cmp(flow2, 1)
dequeue_cmp(flow1, 1)
