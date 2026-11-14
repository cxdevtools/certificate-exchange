package me.cxdev.certtool;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import me.cxdev.certtool.CommandReport.Cell;
import me.cxdev.certtool.CommandReport.Table;
import org.junit.jupiter.api.Test;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

class LiveRolloutTest {
    private final ByteArrayOutputStream output = new ByteArrayOutputStream();
    private final PrintStream stream = new PrintStream(output, true, UTF_8);
    private final TablePrinter printer = new TablePrinter(stream, false, false);
    private final Table table = new Table("Rollout", List.of("Endpoint", "Domain", "Certificate", "Action"),
            List.of(row("api"), row("web")));

    private static List<Cell> row(String endpoint) {
        return List.of(Cell.text(endpoint), Cell.text("Current: old.example.com\nTarget: new.example.com"),
                Cell.text("Current: old\nTarget: new"), Cell.text("change domain and certificate"));
    }

    @Test
    void updatesRetryAndResultInTheSameTerminalTable() {
        var clock = new AtomicLong();
        try (var rollout = new LiveRollout(stream, printer, table, new LiveRollout.TerminalSize(30, 100), clock::get)) {
            rollout.begin(0);
            rollout.retry(2, 20, 15);
            clock.set(1_250_000_000);
            rollout.tick();
            rollout.end("Successful", true);
            rollout.begin(1);
            rollout.end("Failed", false);
        }
        String rendered = output.toString(UTF_8);
        assertTrue(rendered.contains("Status: Try 1/20"));
        assertTrue(rendered.contains("Status: Try 2/20 (wait: 15s)"));
        assertTrue(rendered.contains("Status: Try 2/20 (wait: 14s)"));
        assertTrue(rendered.contains("◓ 1s"));
        assertTrue(rendered.contains("\u001b["));
        assertFalse(rendered.contains("%"));
        String finalFrame = rendered.substring(rendered.lastIndexOf("\u001b[J") + 3);
        assertTrue(finalFrame.contains("Status: Successful"));
        assertTrue(finalFrame.contains("Status: Failed"));
        assertFalse(finalFrame.contains("Status: Try"));
        assertTrue(finalFrame.lines().allMatch(line -> line.length() < 100));
        var lines = finalFrame.lines().toList();
        int web = finalFrame.lines().filter(line -> line.startsWith("  | web")).mapToInt(lines::indexOf).findFirst().orElseThrow();
        assertTrue(lines.get(web - 1).startsWith("  +---"));
    }

    @Test
    void printsPlanAndFinalStatusWithoutCursorCodesWhenRedirected() {
        try (var rollout = new LiveRollout(stream, printer, table, null)) {
            rollout.begin(0);
            rollout.end("Successful", true);
        }
        String rendered = output.toString(UTF_8);
        assertTrue(rendered.contains("Rollout result"));
        assertTrue(rendered.contains("Status: Successful"));
        assertFalse(rendered.contains("\u001b"));
    }
}
