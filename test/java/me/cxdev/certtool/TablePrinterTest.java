package me.cxdev.certtool;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import me.cxdev.certtool.CommandReport.Cell;
import me.cxdev.certtool.CommandReport.Tone;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TablePrinterTest {
    @Test
    void separatesEntriesWithoutSplittingMultilineCells() {
        var output = new ByteArrayOutputStream();
        var printer = new TablePrinter(new PrintStream(output, true, StandardCharsets.UTF_8), true, false);
        printer.print(List.of("Certificate"), List.of(
                List.of(Cell.text("first\ncontinued")),
                List.of(Cell.text("second"))));

        var lines = output.toString(StandardCharsets.UTF_8).lines().toList();
        assertEquals(2, lines.stream().filter(line -> line.startsWith("  ├")).count());
        assertTrue(lines.get(4).contains("continued"));
        assertTrue(lines.get(5).startsWith("  ├"));
        assertTrue(lines.get(6).contains("second"));
    }

    @Test
    void alignsMultilineCellsWithTheHeaderAndBorders() {
        var output = new ByteArrayOutputStream();
        var printer = new TablePrinter(new PrintStream(output, true, StandardCharsets.UTF_8), true, false);
        printer.print(List.of("Endpoint", "Target"), List.of(List.of(
                Cell.text("web"), new Cell("SAP-managed\nnew certificate [c123]", Tone.INFO))));
        var lines = output.toString(StandardCharsets.UTF_8).lines().toList();
        assertEquals(6, lines.size());
        assertTrue(lines.getFirst().startsWith("  ┌"));
        assertTrue(lines.getLast().startsWith("  └"));
        assertTrue(lines.get(4).contains("│          │ new certificate [c123]"));
        assertTrue(lines.stream().allMatch(line -> line.length() == lines.getFirst().length()));
        assertFalse(output.toString(StandardCharsets.UTF_8).contains("\u001b"));
    }

    @Test
    void rendersAnEmptyTableWithAsciiBorders() {
        var output = new ByteArrayOutputStream();
        var printer = new TablePrinter(new PrintStream(output, true, StandardCharsets.US_ASCII), false, false);
        printer.print(List.of("A", "B"), List.of());
        var lines = output.toString(StandardCharsets.US_ASCII).lines().toList();
        assertEquals("  +--------+---+", lines.getFirst());
        assertEquals("  | (none) |   |", lines.get(3));
    }
}
