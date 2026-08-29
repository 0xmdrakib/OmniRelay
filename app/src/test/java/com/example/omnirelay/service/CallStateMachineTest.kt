package com.example.omnirelay.service

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CallStateMachineTest {
    private val peerA = ByteArray(32) { (it + 1).toByte() }
    private val peerB = ByteArray(32) { (it + 2).toByte() }

    @Test
    fun outgoingAcceptCannotBeAppliedAfterTimeout() {
        val machine = CallStateMachine()
        assertNotNull(machine.beginOutgoing("call-a", peerA))
        assertNotNull(machine.expire("call-a", CallStateMachine.Phase.OUTGOING_RINGING))
        assertNull(machine.acceptRemote("call-a", peerA))
        assertNull(machine.snapshot())
    }

    @Test
    fun staleRemoteEndCannotClearANewerCall() {
        val machine = CallStateMachine()
        machine.beginOutgoing("old", peerA)
        assertNotNull(machine.terminateLocal())
        assertNotNull(machine.beginOutgoing("new", peerB))

        assertNull(machine.terminateRemote("old", peerA))
        assertTrue(machine.matches("new", peerB, CallStateMachine.Phase.OUTGOING_RINGING))
    }

    @Test
    fun acceptAndTimeoutRaceHasExactlyOneWinner() {
        repeat(200) {
            val machine = CallStateMachine()
            machine.beginOutgoing("race-$it", peerA)
            val ready = CountDownLatch(2)
            val go = CountDownLatch(1)
            val winners = AtomicInteger(0)
            val pool = Executors.newFixedThreadPool(2)
            pool.execute {
                ready.countDown()
                go.await()
                if (machine.acceptRemote("race-$it", peerA) != null) winners.incrementAndGet()
            }
            pool.execute {
                ready.countDown()
                go.await()
                if (machine.expire("race-$it", CallStateMachine.Phase.OUTGOING_RINGING) != null) {
                    winners.incrementAndGet()
                }
            }
            assertTrue(ready.await(2, TimeUnit.SECONDS))
            go.countDown()
            pool.shutdown()
            assertTrue(pool.awaitTermination(2, TimeUnit.SECONDS))
            assertEquals(1, winners.get())
            val snapshot = machine.snapshot()
            assertTrue(snapshot == null || snapshot.phase == CallStateMachine.Phase.CONNECTING)
        }
    }

    @Test
    fun incomingCallMustTransitionBeforeActivation() {
        val machine = CallStateMachine()
        assertEquals(
            CallStateMachine.RingResult.NEW,
            machine.receiveIncomingRing("incoming", peerA)
        )
        assertFalse(machine.matches("incoming", peerB))
        assertNull(machine.activate("incoming", peerA))
        val connecting = machine.beginLocalAccept()
        assertNotNull(connecting)
        assertNotNull(machine.activate("incoming", peerA))
        assertTrue(machine.matches("incoming", peerA, CallStateMachine.Phase.ACTIVE))
    }
}
