-- SPDX-License-Identifier: GPL-2.0
-- Copyright (c) 2022 Freysteinn Alfredsson <freysteinn@freysteinn.com>

--  Fair Queuing with Controlled Delay (FQ_CoDel)
config.bpf.file = "./sched_fq_codel.bpf.o"


-- Setup flows
-- We use this flow to test sparse flow handling
packet_sparse_flow_tester = Udp:new()
packet_sparse_flow_tester.udp.dest = 8000

-- The background stream flow increments the time bytes
-- so that we can test our sparse flow tester when time has passed
packet_flow_background_stream = Udp:new()
packet_flow_background_stream.udp.dest = 8001
-- Make the packet the size of full a quantom (1522 - 62)
packet_flow_background_stream.udp.payload = create_payload(1460)

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
  flow.udp.payload = create_payload(1460)
  enqueue(flow) -- Sparse
  enqueue(flow) -- Stream
  dequeue_cmp(flow) -- Dequeue sparse
  dequeue_cmp(flow) -- Dequeue sparse
  -- Note that the type_bytes has not advanced at this point but will after the
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
  make_sparse(packet_flow_background_stream)

  -- Prime the background stream so it can update the time_bytes variable later.
  enqueue(packet_flow_background_stream) -- Prime for updating time_bytes
  enqueue(packet_flow_background_stream) -- Make sure the flow is not recycled after update

  -- Make the packet the size of half a quantom (1522/2 - 62)
  -- The flow will cease being a sparse flow after two packets.
  packet_sparse_flow_tester.udp.payload = create_payload(699)

  -- The sparse flow gets a full quantom of packets.
  enqueue(packet_sparse_flow_tester) -- Sparse 1
  enqueue(packet_sparse_flow_tester) -- Sparse 2

  -- Remove all sparse packets.
  dequeue_cmp(packet_sparse_flow_tester) -- Dequeue sparse
  dequeue_cmp(packet_sparse_flow_tester) -- Dequeue sparse

  -- Advance time_bytes
  dequeue_cmp(packet_flow_background_stream) -- Advances time_bytes one quantom
  -- Our FQ-CoDel algorithm should have expired the sparse_flow_tester
  -- flow at this point, but not the background stream.

  -- Test that the sparse_flow_tester is indeed expired.
  enqueue(packet_sparse_flow_tester) -- Add sparse packet with a higher priority
  dequeue_cmp(packet_sparse_flow_tester) -- Dequeue the sparse packet
  dequeue_cmp(packet_flow_background_stream) -- Advances time_bytes one quantom
  -- Our FQ-CoDel algorithm should have expired both the sparse_flow_tester
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
  make_sparse(packet_flow_background_stream)

  -- Make the packet the size of half a quantom (1522/2 - 62)
  packet_flow_background_stream.udp.payload = create_payload(699)

  -- Make each packet 50 bytes for our sparse flow
  packet_sparse_flow_tester.udp.payload = create_payload(38)

  -- Keep in mind that the last background packet ends at a full quantom. Therefore,
  -- if we want to update the time_bytes by a half a quantom, we will need to enqueue
  -- and deqeueu a half a quantom packet.
  enqueue(packet_flow_background_stream) -- Used to advance time_bytes by half a quantom
  enqueue(packet_flow_background_stream) -- Used to advance time_bytes by half a quantom
  enqueue(packet_flow_background_stream) -- Make sure the flow is not recycled after update
  dequeue_cmp(packet_flow_background_stream) -- Advances time_bytes by a half a quantom

  -- Confirm that the sparse flow has a higher priority than the background stream.
  enqueue(packet_sparse_flow_tester) -- Add a sparse packet
  enqueue(packet_sparse_flow_tester) -- Add a sparse packet
  dequeue_cmp(packet_sparse_flow_tester) -- Dequeue the sparse packet
  dequeue_cmp(packet_sparse_flow_tester) -- Dequeue the sparse packet

  dequeue_cmp(packet_flow_background_stream) -- Advances time_bytes by a half a quantom

  -- Confirm that the sparse flow has a higher priority than the stream.
  enqueue(packet_sparse_flow_tester) -- Add a sparse packet
  enqueue(packet_sparse_flow_tester) -- Add a sparse packet
  dequeue_cmp(packet_sparse_flow_tester) -- Dequeue the sparse packet
  dequeue_cmp(packet_sparse_flow_tester) -- Dequeue the sparse packet

  -- Recycle both flows.
  dequeue_cmp(packet_flow_background_stream) -- Recycle both flows
end

-- 1.3 Test a flow that becomes a stream.
function fq_codel_sparse_test3()
  -- This test does the following:
  -- 1. Creates a sparse flow and adds a full quantom to it.
  -- 2. Adds packets to the flow to make it a stream.
  -- 3. Advances time_bytes by a half a quantom.
  -- 4. Adds packets to the stream
  -- In steps two and four the test confirms that the flow is a stream.
  make_sparse(packet_flow_background_stream)

  -- Make the packet the size of half a quantom (1522/2 - 62)
  packet_sparse_flow_tester.udp.payload = create_payload(699)

  -- Make the packet the size of half a quantom (1522/2 - 62)
  packet_flow_background_stream.udp.payload = create_payload(699)

  -- Keep in mind that the last background packet ends at a full quantom. Therefore,
  -- if we want to update the time_bytes by a half a quantom, we will need to enqueue
  -- and deqeueu a half a quantom packet.
  enqueue(packet_flow_background_stream) -- Used to advance time_bytes by half a quantom
  enqueue(packet_flow_background_stream) -- Used to advance time_bytes by half a quantom
  enqueue(packet_flow_background_stream) -- Make sure the flow is not recycled after update
  dequeue_cmp(packet_flow_background_stream) -- Advances time_bytes by a half a quantom

  -- Make the sparse_flow_tester flow a stream.
  enqueue(packet_sparse_flow_tester) -- Add sparse packet
  enqueue(packet_sparse_flow_tester) -- Add sparse packet
  enqueue(packet_sparse_flow_tester) -- Make the flow a stream
  enqueue(packet_sparse_flow_tester) -- Add stream packet

  --  Dequeue the sparse flow packets.
  dequeue_cmp(packet_sparse_flow_tester)
  dequeue_cmp(packet_sparse_flow_tester)

  -- Confirm that both flows are streams with equal priority.
  dequeue_cmp(packet_sparse_flow_tester)
  dequeue_cmp(packet_flow_background_stream)
  dequeue_cmp(packet_sparse_flow_tester)
  dequeue_cmp(packet_flow_background_stream)
end

--
function fq_codel_codel_test1()
  -- Not inplemented
end


-- Run tests
fq_codel_sparse_test1()
--fq_codel_sparse_test2()
--fq_codel_sparse_test3()
--
--fq_codel_codel_test1()
