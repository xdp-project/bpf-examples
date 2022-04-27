-- SPDX-License-Identifier: GPL-2.0
-- Copyright (c) 2022 Freysteinn Alfredsson <freysteinn@freysteinn.com>

-- Weighted Fair Queueing  (WFQ)
config.bpf.file = "./sched_wfq.bpf.o"


-- Setup flows
packet_flow1 = Udp:new()
packet_flow1.udp.dest = 8000
packet_flow1.udp.payload = create_payload(38)

packet_flow2 = Udp:new()
packet_flow2.udp.dest = 8001
packet_flow2.udp.payload = create_payload(138)

packet_flow3 = Udp:new()
packet_flow3.udp.dest = 8002
packet_flow3.udp.payload = create_payload(38)

-- Test scheduler

-- 1. Enqueue two packets using the same flow.
-- Tests that no flows remain after the PIFO is empty.
function wfq_test1()
  enqueue(packet_flow1)
  dequeue_cmp(packet_flow1)
end


-- 2. Enqueue two flows
function wfq_test2()
  enqueue(packet_flow1)
  enqueue(packet_flow1)
  enqueue(packet_flow3)

  dequeue_cmp(packet_flow1)
  dequeue_cmp(packet_flow3)
  dequeue_cmp(packet_flow1)
end


-- 3. Enqueue three flows where one flow has a larger packet size.
function wfq_test3()
  -- priority: flow(packet_number, flow_end_byte), flow(...), ...
  enqueue(packet_flow1)
  --   0: *f1(1, 100)

  enqueue(packet_flow2)
  --   0: *f2(1, 200), f1(1, 100)

  enqueue(packet_flow1)
  --   0: f2(1, 200), f1(1, 100)
  -- 100: *f1(2, 100)

  enqueue(packet_flow2)
  --   0: f2(1, 200), f1(1, 100)
  -- 100: f1(2, 100)
  -- 200: *f2(2, 400)

  dequeue_cmp(packet_flow1)
  --   0: f2(1, 200)    ---> *f1(1, 100)
  -- 100: f1(2, 100)
  -- 200: f2(2, 400)

  enqueue(packet_flow1)
  --   0: f2(1, 200)
  -- 100: f1(2, 100)
  -- 200: *f1(3, 300), f2(2, 400)

  dequeue_cmp(packet_flow2)
  --   0:    ---> *f2(1, 200)
  -- 100: f1(2, 100)
  -- 200: f1(3, 300), f2(2, 400)

  dequeue_cmp(packet_flow1)
  -- 100:    ---> *f1(2, 100)
  -- 200: f1(3, 300), f2(2, 400)

  enqueue(packet_flow3)
  -- 100: *f3(1, 200)
  -- 200: f1(3, 300), f2(2, 400)

  enqueue(packet_flow3)
  -- 100: f3(1, 200)
  -- 200: *f3(2, 300), f1(3, 300), f2(2, 400)

  dequeue_cmp(packet_flow3)
  -- 100:    ---> *f3(1, 200)
  -- 200: f3(2, 300), f1(3, 300), f2(2, 400)

  dequeue_cmp(packet_flow2)
  -- 200: f3(2, 300), f1(3, 300)    ---> *f2(2, 400)

  dequeue_cmp(packet_flow1)
  -- 200: f3(2, 300)    ---> *f1(3, 300)

  dequeue_cmp(packet_flow3)
  -- 200:    ---> *f3(2, 300)
end


-- 4. Enqueue multiple packets
function wfq_test4()
  for i = 0, 4095, 1
  do
    enqueue(packet_flow1)
  end
  for i = 0, 4095, 1
  do
    dequeue_cmp(packet_flow1)
  end
end


-- 5. Enqueue packets with weights
function wfq_test5()
  set_flow_weight(packet_flow1, 1024)
  enqueue(packet_flow1)
  enqueue(packet_flow1)
  enqueue(packet_flow2)
  enqueue(packet_flow2)

  dequeue_cmp(packet_flow1)
  dequeue_cmp(packet_flow2)
  dequeue_cmp(packet_flow2)
  dequeue_cmp(packet_flow1)

  set_flow_weight(packet_flow1, 256)
  set_flow_weight(packet_flow2, 32)
  enqueue(packet_flow1)
  enqueue(packet_flow1)
  enqueue(packet_flow2)
  enqueue(packet_flow2)

  dequeue_cmp(packet_flow1)
  dequeue_cmp(packet_flow2)
  dequeue_cmp(packet_flow2)
  dequeue_cmp(packet_flow1)
end


-- Run tests
wfq_test1()
wfq_test2()
wfq_test3()
wfq_test4()
wfq_test5()
