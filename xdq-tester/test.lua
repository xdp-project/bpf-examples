-- SPDX-License-Identifier: GPL-2.0
-- Copyright (c) 2022 Freysteinn Alfredsson <freysteinn@freysteinn.com>

-- FIFO scheduler
config.bpf.file = "./sched_test.bpf.o"

-- Setup flows
packet_flow1 = Udp:new()
packet_flow1.udp.dest = 8080

packet_flow2 = Udp:new()
packet_flow2.udp.dest = 8081

packet_flow3 = Udp:new()
packet_flow3.udp.dest = 8082


-- Test scheduler

enqueue(packet_flow1)
dequeue_cmp(packet_flow1)

-- enqueue(packet_flow1)
-- enqueue(packet_flow2)
-- enqueue(packet_flow3)
--
-- dequeue_cmp(packet_flow1)
-- dequeue_cmp(packet_flow2)
-- dequeue_cmp(packet_flow3)
