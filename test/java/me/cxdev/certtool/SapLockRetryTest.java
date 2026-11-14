package me.cxdev.certtool;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

class SapLockRetryTest {
    private static final String PROCESS_ID = "ea97b0e5-e06e-11f1-88f8-5608a044ef9f";
    private static final String LOCK = "This environment cannot be edited because another process is modifying it. "
            + "Please wait and try again later. Process ID: " + PROCESS_ID;

    private final ByteArrayOutputStream output = new ByteArrayOutputStream();
    private final ConsolePrinter printer = new ConsolePrinter(new PrintStream(output, true, UTF_8), true, false);

    @Test
    void retriesAnInitialLockAndStopsOnSuccess() throws Exception {
        var attempts = new AtomicInteger();
        List<Integer> delays = new ArrayList<>();

        String result = SapCcm.runWithLockRetry(() -> {
            if (attempts.incrementAndGet() < 3) throw new SapCcm.SapException("Locked", LOCK, 10);
            return "Updated";
        }, delays::add, printer);

        assertEquals("Updated", result);
        assertEquals(3, attempts.get());
        assertEquals(List.of(15, 15), delays);
        assertTrue(output.toString(UTF_8).contains(PROCESS_ID + "). Try 3/20 in 15s."));
    }

    @Test
    void makesExactlyTwentyAttemptsAndPreservesTheLastError() {
        var attempts = new AtomicInteger();
        List<Integer> delays = new ArrayList<>();
        var lock = new SapCcm.SapException("Locked", LOCK, 10);

        var error = assertThrows(SapCcm.SapException.class, () -> SapCcm.runWithLockRetry(() -> {
            attempts.incrementAndGet();
            throw lock;
        }, delays::add, printer));

        assertSame(lock, error);
        assertEquals(20, attempts.get());
        assertEquals(java.util.Collections.nCopies(19, 15), delays);
        assertTrue(output.toString(UTF_8).contains("Environment still locked after 20 attempts."));
    }

    @Test
    void doesNotRetryUnrelatedFailures() {
        for (var error : List.of(new SapCcm.SapException("Other error", "Authorization Failed", 10),
                new SapCcm.SapException("Other code", LOCK, 1))) {
            var actual = assertThrows(SapCcm.SapException.class, () -> SapCcm.runWithLockRetry(
                    () -> { throw error; }, seconds -> fail("Unexpected retry"), printer));
            assertSame(error, actual);
        }
    }

    @Test
    void interruptionStopsTheRetryDuringTheWait() {
        var attempts = new AtomicInteger();
        assertThrows(InterruptedException.class, () -> SapCcm.runWithLockRetry(() -> {
            attempts.incrementAndGet();
            throw new SapCcm.SapException("Locked", LOCK, 10);
        }, seconds -> { throw new InterruptedException(); }, printer));
        assertEquals(1, attempts.get());
    }
}
