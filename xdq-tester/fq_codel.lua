-- SPDX-License-Identifier: GPL-2.0
-- Copyright (c) 2022 Freysteinn Alfredsson <freysteinn@freysteinn.com>

--  Fair Queuing with Controlled Delay (FQ_CoDel)
config.bpf.file = "./sched_fq_codel.bpf.o"


-- Setup flows
-- We use this flow to test sparse flow handling
adjust_meta(8)

flow = Udp:new()
flow.udp.dest = 8000

-- The background stream flow increments the time bytes
-- so that we can test our sparse flow tester when time has passed
bg_flow = Udp:new()
bg_flow.udp.dest = 8001
-- Make the packet the size of full a quantom (1514 - 62) -- 1514
bg_flow.udp.payload = create_payload(1452)

set_time_ns(1000)

-- Test scheduler

--
-- 1. Sparse flow tests
--
-- In our implementation of FQ-CoDel, the time_bytes variable is the only thing
-- that connects sparse flows. Therefore, we can test all possible scenarios
-- using only two flows. One background flow that we only use to advance time.
-- And the flow that we use for testing.

function make_sparse(flow)
  -- The background flow needs two packets to be a stream:
  -- * The first packet will be sparse.
  -- * The second packet exceeds the sparse quantom.
  flow.udp.payload = create_payload(1444)
  enqueue(flow, 10001) -- Sparse
  enqueue(flow, 10002) -- Stream
  dequeue_cmp(flow, 10001) -- Dequeue sparse
  dequeue_cmp(flow, 10002) -- Dequeue sparse
  -- Note that the time_bytes has not advanced at this point but will after the
  -- next dequeued packet.
end

-- 1.1 Test when a sparse flow ends while sparse
function fq_codel_sparse_test1()
  -- This test does the following:
  -- 1. Creates a sparse flow with a couple of packets.
  -- 2. Advance time_bytes and expire the sparse flow.
  -- 3. Creates a new sparse flow with a couple of packets.
  -- 4. Advance time_bytes and expire the new sparse flow.
  -- In steps two and four the test confirms that the sparse flows
  -- were still sparse.
  make_sparse(bg_flow)

  -- Prime the background stream so it can update the time_bytes variable later.
  enqueue(bg_flow, 11) -- Prime for updating time_bytes
  enqueue(bg_flow, 12) -- Make sure the flow is not recycled after update

  -- Make the packet the size of half a quantom (1522/2 - 62)
  -- The flow will cease being a sparse flow after two packets.
  flow.udp.payload = create_payload(695)

  -- The sparse flow gets a full quantom of packets.
  enqueue(flow, 11) -- Sparse 1
  enqueue(flow, 12) -- Sparse 2

  -- Remove all sparse packets.
  dequeue_cmp(flow, 11) -- Dequeue sparse
  dequeue_cmp(flow, 12) -- Dequeue sparse

  -- Advance time_bytes
  dequeue_cmp(bg_flow, 11) -- Advances time_bytes one quantom
  -- Our FQ-CoDel algorithm should have expired the flow
  -- flow at this point, but not the background stream.

  -- Test that the flow is indeed expired.
  enqueue(flow, 13) -- Add sparse packet with a higher priority
  dequeue_cmp(flow, 13) -- Dequeue the sparse packet
  dequeue_cmp(bg_flow, 12) -- Advances time_bytes one quantom
  -- Our FQ-CoDel algorithm should have expired both the flow
  -- flow and the background stream at this point.
end

-- 1.2 Test a sparse flow when the time_bytes advances while the flow is sparse
function fq_codel_sparse_test2()
  -- This test does the following:
  -- 1. Creates a sparse flow with a couple of packets.
  -- 2. Advances time_bytes by a half a quantom
  -- 3. Adds a couple of packets to the sparse flow.
  -- In steps one and three the test confirms that the sparse flow
  -- is still sparse.
  make_sparse(bg_flow)

  -- Make the packet the size of half a quantom (1522/2 - 62)
  bg_flow.udp.payload = create_payload(691)

  -- Make each packet 50 bytes for our sparse flow
  flow.udp.payload = create_payload(30)

  -- Keep in mind that the last background packet ends at a full quantom. Therefore,
  -- if we want to update the time_bytes by a half a quantom, we will need to enqueue
  -- and deqeueu a half a quantom packet.
  enqueue(bg_flow, 21) -- Used to advance time_bytes by half a quantom
  enqueue(bg_flow, 22) -- Used to advance time_bytes by half a quantom
  enqueue(bg_flow, 23) -- Make sure the flow is not recycled after update
  dequeue_cmp(bg_flow, 21) -- Advances time_bytes by a half a quantom

  -- Confirm that the sparse flow has a higher priority than the background stream.
  enqueue(flow, 21) -- Add a sparse packet
  enqueue(flow, 22) -- Add a sparse packet
  dequeue_cmp(flow, 21) -- Dequeue the sparse packet
  dequeue_cmp(flow, 22) -- Dequeue the sparse packet

  dequeue_cmp(bg_flow, 22) -- Advances time_bytes by a half a quantom

  -- Confirm that the sparse flow has a higher priority than the stream.
  enqueue(flow, 23) -- Add a sparse packet
  enqueue(flow, 24) -- Add a sparse packet
  dequeue_cmp(flow, 23) -- Dequeue the sparse packet
  dequeue_cmp(flow, 24) -- Dequeue the sparse packet

  -- Recycle both flows.
  dequeue_cmp(bg_flow, 23) -- Recycle both flows
end

-- 1.3 Test a flow that becomes a stream.
function fq_codel_sparse_test3()
  -- This test does the following:
  -- 1. Creates a sparse flow and adds a full quantom to it.
  -- 2. Adds packets to the flow to make it a stream.
  -- 3. Advances time_bytes by a half a quantom.
  -- 4. Adds packets to the stream
  -- In steps two and four the test confirms that the flow is a stream.
  make_sparse(bg_flow)

  -- Make the packet the size of half a quantom (1514/2 - 62)
  flow.udp.payload = create_payload(695)

  -- Make the packet the size of half a quantom (1514/2 - 62)
  bg_flow.udp.payload = create_payload(695)

  -- Keep in mind that the last background packet ends at a full quantom. Therefore,
  -- if we want to update the time_bytes by a half a quantom, we will need to enqueue
  -- and deqeueu a half a quantom packet.
  enqueue(bg_flow, 31) -- Used to advance time_bytes by half a quantom
  enqueue(bg_flow, 32) -- Used to advance time_bytes by half a quantom
  enqueue(bg_flow, 33) -- Make sure the flow is not recycled after update
  dequeue_cmp(bg_flow, 31) -- Advances time_bytes by a half a quantom

  -- Make the flow flow a stream.
  enqueue(flow, 31) -- Add sparse packet
  enqueue(flow, 32) -- Add sparse packet
  enqueue(flow, 33) -- Make the flow a stream
  enqueue(flow, 34) -- Add stream packet

  --  Dequeue the sparse flow packets.
  dequeue_cmp(flow, 31)
  dequeue_cmp(flow, 32)

  -- Confirm that both flows are streams with equal priority.
  dequeue_cmp(flow, 33)
  dequeue_cmp(bg_flow, 32)
  dequeue_cmp(flow, 34)
  dequeue_cmp(bg_flow, 33)
end

--
function fq_codel_codel_test1()
  -- Not inplemented
end


-- Run tests
-- fq_codel_sparse_test1()
-- fq_codel_sparse_test2()
fq_codel_sparse_test3()
--
-- fq_codel_codel_test1()
