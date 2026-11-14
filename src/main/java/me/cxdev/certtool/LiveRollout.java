package me.cxdev.certtool;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

import me.cxdev.certtool.CommandReport.Cell;
import me.cxdev.certtool.CommandReport.Table;
import me.cxdev.certtool.CommandReport.Tone;

final class LiveRollout implements AutoCloseable {
    private static final int ACTION_COLUMN = 3;
    private static final int FRAME_MILLIS = 250;

    record TerminalSize(int rows, int columns) {
        static TerminalSize detect() {
            try {
                Process process = new ProcessBuilder("stty", "size").redirectInput(ProcessBuilder.Redirect.INHERIT)
                        .redirectError(ProcessBuilder.Redirect.DISCARD).start();
                String[] size = new String(process.getInputStream().readAllBytes(), StandardCharsets.US_ASCII)
                        .strip().split("\\s+");
                if (process.waitFor() == 0 && size.length == 2) {
                    return new TerminalSize(Integer.parseInt(size[0]), Integer.parseInt(size[1]));
                }
            } catch (IOException | NumberFormatException ignored) {
                // A static plan and result work without terminal dimensions.
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
            return null;
        }
    }

    private final PrintStream out;
    private final TablePrinter printer;
    private final TerminalSize size;
    private final List<String> headers;
    private final List<List<Cell>> rows;
    private final ScheduledExecutorService timer;
    private final LongSupplier nanoTime;
    private final String spinner;
    private int previousLines;
    private int activeRow = -1;
    private String action;
    private int attempt;
    private int maxAttempts;
    private long started;
    private long waitUntil;
    private boolean waiting;
    private boolean closed;

    LiveRollout(PrintStream out, TablePrinter printer, Table table, TerminalSize size) {
        this(out, printer, table, size, System::nanoTime);
    }

    LiveRollout(PrintStream out, TablePrinter printer, Table table, TerminalSize size, LongSupplier nanoTime) {
        this.out = out;
        this.printer = printer;
        this.nanoTime = nanoTime;
        spinner = out.charset().newEncoder().canEncode("◐◓◑◒") ? "◐◓◑◒" : "|/-\\";
        this.size = size != null && size.columns() >= 58 ? size : null;
        headers = table.headers();
        rows = new ArrayList<>(table.rows());
        List<String> initial = frame();
        if (fits(initial)) previousLines = initial.size();
        write(initial);
        timer = previousLines == 0 ? null
                : Executors.newSingleThreadScheduledExecutor(Thread.ofVirtual().factory());
        if (timer != null) timer.scheduleAtFixedRate(this::tick, FRAME_MILLIS, FRAME_MILLIS, TimeUnit.MILLISECONDS);
    }

    synchronized void begin(int row) {
        activeRow = row;
        action = rows.get(row).get(ACTION_COLUMN).text();
        attempt = 1;
        maxAttempts = SapCcm.MAX_LOCK_ATTEMPTS;
        started = nanoTime.getAsLong();
        waiting = false;
        update();
    }

    synchronized void retry(int attempt, int max, int seconds) {
        this.attempt = attempt;
        maxAttempts = max;
        waiting = seconds > 0;
        waitUntil = nanoTime.getAsLong() + TimeUnit.SECONDS.toNanos(seconds);
        update();
    }

    synchronized void end(String result, boolean success) {
        long elapsed = TimeUnit.NANOSECONDS.toSeconds(nanoTime.getAsLong() - started);
        replaceAction(action + "\nElapsed: " + elapsed + "s\nStatus: " + result, success ? Tone.SUCCESS : Tone.ERROR);
        activeRow = -1;
    }

    synchronized void tick() {
        if (!closed && activeRow >= 0) update();
    }

    private void update() {
        long now = nanoTime.getAsLong();
        long elapsed = now - started;
        int frame = (int) (TimeUnit.NANOSECONDS.toMillis(elapsed) / FRAME_MILLIS % spinner.length());
        String status = "Try " + attempt + "/" + maxAttempts;
        if (waiting) {
            long nanosLeft = Math.max(0, waitUntil - now);
            long remaining = TimeUnit.NANOSECONDS.toSeconds(nanosLeft + 999_999_999);
            status += " (wait: " + remaining + "s)";
        }
        replaceAction(action + "\n" + spinner.charAt(frame) + " " + TimeUnit.NANOSECONDS.toSeconds(elapsed)
                + "s\nStatus: " + status, Tone.WARNING);
    }

    private void replaceAction(String text, Tone tone) {
        List<Cell> row = new ArrayList<>(rows.get(activeRow));
        row.set(ACTION_COLUMN, new Cell(text, tone));
        rows.set(activeRow, row);
        List<String> frame = previousLines == 0 ? List.of() : frame();
        if (previousLines > 0 && fits(frame)) redraw(frame);
    }

    private List<String> frame() {
        return printer.render(headers, rows, size == null ? Integer.MAX_VALUE : size.columns() - 1);
    }

    private boolean fits(List<String> frame) {
        return size != null && frame.size() < size.rows();
    }

    private void redraw(List<String> frame) {
        if (previousLines > 0) out.print("\u001b[" + previousLines + "A\r\u001b[J");
        write(frame);
        previousLines = fits(frame) ? frame.size() : 0;
    }

    private void write(List<String> frame) {
        out.print(String.join(System.lineSeparator(), frame) + System.lineSeparator());
        out.flush();
    }

    @Override
    public synchronized void close() {
        closed = true;
        if (timer != null) timer.shutdownNow();
        if (previousLines == 0) out.println("\nRollout result");
        redraw(frame());
    }
}
