-- SPDX-License-Identifier: GPL-2.0
-- Copyright (c) 2022 Freysteinn Alfredsson <freysteinn@freysteinn.com>

-- Weighted Fair Queueing  (WFQ)
config.bpf.file = "./sched_wfq.bpf.o"


-- Setup flows
flow1 = Udp:new()
flow1.udp.dest = 8000
flow1.udp.payload = create_payload(38)

flow2 = Udp:new()
flow2.udp.dest = 8001
flow2.udp.payload = create_payload(138)

flow3 = Udp:new()
flow3.udp.dest = 8002
flow3.udp.payload = create_payload(38)

-- Test scheduler

-- 1. Enqueue two packets using the same flow.
-- Tests that no flows remain after the PIFO is empty.
function wfq_test1()
  enqueue(flow1, 1)
  dequeue_cmp(flow1, 1)
end


-- 2. Enqueue two flows
function wfq_test2()
  enqueue(flow1, 1)
  enqueue(flow1, 2)
  enqueue(flow3, 1)

  dequeue_cmp(flow1, 1)
  dequeue_cmp(flow3, 1)
  dequeue_cmp(flow1, 2)
end


-- 3. Enqueue three flows where one flow has a larger packet size.
function wfq_test3()
  -- priority: flow(number, flow_end_byte), flow(...), ...
  enqueue(flow1, 1)
  --   0: *f1(1, 100)

  enqueue(flow2, 1)
  --   0: *f2(1, 200), f1(1, 100)

  enqueue(flow1, 2)
  --   0: f2(1, 200), f1(1, 100)
  -- 100: *f1(2, 100)

  enqueue(flow2, 2)
  --   0: f2(1, 200), f1(1, 100)
  -- 100: f1(2, 100)
  -- 200: *f2(2, 400)

  dequeue_cmp(flow1, 1)
  --   0: f2(1, 200)    ---> *f1(1, 100)
  -- 100: f1(2, 100)
  -- 200: f2(2, 400)

  enqueue(flow1, 3)
  --   0: f2(1, 200)
  -- 100: f1(2, 100)
  -- 200: *f1(3, 300), f2(2, 400)

  dequeue_cmp(flow2, 1)
  --   0:    ---> *f2(1, 200)
  -- 100: f1(2, 100)
  -- 200: f1(3, 300), f2(2, 400)

  dequeue_cmp(flow1, 2)
  -- 100:    ---> *f1(2, 100)
  -- 200: f1(3, 300), f2(2, 400)

  enqueue(flow3, 1)
  -- 100: *f3(1, 200)
  -- 200: f1(3, 300), f2(2, 400)

  enqueue(flow3, 2)
  -- 100: f3(1, 200)
  -- 200: *f3(2, 300), f1(3, 300), f2(2, 400)

  dequeue_cmp(flow3, 1)
  -- 100:    ---> *f3(1, 200)
  -- 200: f3(2, 300), f1(3, 300), f2(2, 400)

  dequeue_cmp(flow2, 2)
  -- 200: f3(2, 300), f1(3, 300)    ---> *f2(2, 400)

  dequeue_cmp(flow1, 3)
  -- 200: f3(2, 300)    ---> *f1(3, 300)

  dequeue_cmp(flow3, 2)
  -- 200:    ---> *f3(2, 300)
end


-- 4. Enqueue multiple packets
function wfq_test4()
  for i = 0, 4095, 1
  do
    enqueue(flow1, i + 1)
  end
  for i = 0, 4095, 1
  do
    dequeue_cmp(flow1, i + 1)
  end
end


-- 5. Enqueue packets with weights
function wfq_test5()
  set_flow_weight(flow1, 1024)
  enqueue(flow1, 1)
  enqueue(flow1, 2)
  enqueue(flow2, 1)
  enqueue(flow2, 2)

  dequeue_cmp(flow1, 1)
  dequeue_cmp(flow2, 1)
  dequeue_cmp(flow2, 2)
  dequeue_cmp(flow1, 2)

  set_flow_weight(flow1, 256)
  set_flow_weight(flow2, 32)

  enqueue(flow1, 3)
  enqueue(flow1, 4)
  enqueue(flow2, 3)
  enqueue(flow2, 4)

  dequeue_cmp(flow1, 3)
  dequeue_cmp(flow2, 3)
  dequeue_cmp(flow2, 4)
  dequeue_cmp(flow1, 4)
end


-- Run tests
wfq_test1()
wfq_test2()
wfq_test3()
wfq_test4()
wfq_test5()
