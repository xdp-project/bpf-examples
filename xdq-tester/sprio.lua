-- SPDX-License-Identifier: GPL-2.0
-- Copyright (c) 2022 Freysteinn Alfredsson <freysteinn@freysteinn.com>

-- Strict Priority scheduler (SPRIO)
config.bpf.file = "./sched_sprio.bpf.o"

-- Create flows
packet_flow1 = Udp:new()
packet_flow1.udp.dest = 8080
set_flow_weight(packet_flow1, 2)

packet_flow2 = Udp:new()
packet_flow2.udp.dest = 8081
set_flow_weight(packet_flow2, 1)

packet_flow3 = Udp:new()
packet_flow3.udp.dest = 8082
set_flow_weight(packet_flow3, 0)

-- Test scheduler
enqueue(packet_flow1)
enqueue(packet_flow2)
enqueue(packet_flow3)

dequeue_cmp(packet_flow3)
dequeue_cmp(packet_flow2)
dequeue_cmp(packet_flow1)
