package me.cxdev.certtool;

import java.io.Console;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import me.cxdev.certtool.CommandReport.Table;
import me.cxdev.certtool.CommandReport.Tone;

final class ConsolePrinter {
    private final PrintStream out;
    private final TablePrinter tables;
    private final boolean inlineRetry;
    private final boolean liveTerminal;
    private final boolean verbose;
    private final List<String> rolloutTrace = new ArrayList<>();
    private LiveRollout rollout;
    private int step;
    private int retryWidth;
    private String loadingMessage;
    private boolean sectionGap;

    ConsolePrinter(PrintStream out, boolean unicode, boolean color) {
        this(out, unicode, color, false);
    }

    ConsolePrinter(PrintStream out, boolean unicode, boolean color, boolean inlineRetry) {
        this(out, unicode, color, inlineRetry, false, false);
    }

    private ConsolePrinter(PrintStream out, boolean unicode, boolean color, boolean inlineRetry,
                           boolean liveTerminal, boolean verbose) {
        this.out = out;
        this.inlineRetry = inlineRetry;
        this.liveTerminal = liveTerminal;
        this.verbose = verbose;
        this.tables = new TablePrinter(out, unicode, color);
    }

    static ConsolePrinter standard(boolean verbose) {
        String term = System.getenv("TERM");
        boolean interactive = isTerminal(System.console()) && !"dumb".equals(term);
        boolean color = interactive && !System.getenv().containsKey("NO_COLOR");
        boolean liveTerminal = interactive && term != null && !term.isBlank();
        return new ConsolePrinter(System.out, System.out.charset().newEncoder().canEncode("┌─┐│"),
                color, liveTerminal && !verbose, liveTerminal, verbose);
    }

    private static boolean isTerminal(Console console) {
        if (console == null) return false;
        try {
            // Newer JDKs may provide a Console even when output is redirected.
            return (boolean) Console.class.getMethod("isTerminal").invoke(console);
        } catch (NoSuchMethodException ignored) {
            return true;
        } catch (ReflectiveOperationException ignored) {
            return false;
        }
    }

    void context(String title, List<Map.Entry<String, String>> fields) {
        out.println(tables.style(title, Tone.INFO));
        int width = fields.stream().mapToInt(field -> field.getKey().length()).max().orElse(0);
        for (var field : fields) {
            String label = field.getKey();
            out.println("  " + tables.style(label, Tone.DIM)
                    + " ".repeat(width - label.length() + 2) + field.getValue());
        }
    }

    void table(Table table) {
        heading(table.title());
        tables.print(table.headers(), table.rows());
    }

    void heading(String title) {
        if (!sectionGap) out.println();
        sectionGap = false;
        out.println(tables.style(title, Tone.BOLD));
    }

    void step(String message) {
        out.printf("  [%d] %s%n", ++step, message);
        out.flush();
    }

    void sapCall(List<String> args) {
        if (rollout != null) {
            if (verbose) rolloutTrace.add("  [" + ++step + "] $ sapccm " + String.join(" ", args));
            return;
        }
        step("$ sapccm " + String.join(" ", args));
    }

    void startLoading(String message, boolean afterContext) {
        if (!liveTerminal || verbose) return;
        if (afterContext) {
            out.println();
            sectionGap = true;
        }
        printLoading(message);
    }

    void loading(String message) {
        if (loadingMessage == null) return;
        printLoading(message);
    }

    private void printLoading(String message) {
        out.print("\r\u001b[2K" + message);
        out.flush();
        loadingMessage = message;
    }

    void loadingSapCall(List<String> args) {
        if (loadingMessage == null) return;
        String message = switch (args.get(0) + " " + args.get(1)) {
            case "certificate list" -> "Reading uploaded certificates...";
            case "certificate show" -> "Checking uploaded certificate domains...";
            case "environment list" -> "Reading subscription environments...";
            case "endpoint list" -> "Reading environment endpoints...";
            case "endpoint show" -> "Reading endpoint settings...";
            default -> "Reading SAP configuration...";
        };
        loading(message);
    }

    void clearLoading() {
        if (loadingMessage == null) return;
        out.print("\r\u001b[2K");
        out.flush();
        loadingMessage = null;
    }

    void warning(String message) {
        String currentLoading = loadingMessage;
        clearLoading();
        System.err.println(message);
        if (currentLoading != null) printLoading(currentLoading);
    }

    void startRollout(Table table) {
        heading(table.title());
        rollout = new LiveRollout(out, tables, table, liveTerminal ? LiveRollout.TerminalSize.detect() : null);
    }

    void beginRolloutStep(int row) {
        rollout.begin(row);
    }

    void endRolloutStep(boolean success) {
        rollout.end(success ? "Successful" : "Failed", success);
    }

    void finishRollout() {
        rollout.close();
        rollout = null;
        if (!rolloutTrace.isEmpty()) {
            heading("Executing");
            rolloutTrace.forEach(out::println);
            rolloutTrace.clear();
        }
    }

    void retrying(int attempt, int max, int seconds, String processId) {
        if (rollout != null) {
            rollout.retry(attempt, max, seconds);
            if (!verbose) return;
        }
        String process = inlineRetry || processId == null ? "" : " (" + processId + ")";
        String message = "      Environment locked" + process + ". Try " + attempt + "/" + max + " in " + seconds + "s.";
        if (rollout != null) {
            rolloutTrace.add(message);
        } else if (inlineRetry) {
            out.print("\r" + message + " ".repeat(Math.max(0, retryWidth - message.length())) + "\r");
            retryWidth = message.length();
        } else {
            out.println(message);
        }
        out.flush();
    }

    void retryStarted(int attempt, int max) {
        if (rollout != null) rollout.retry(attempt, max, 0);
    }

    void clearRetry() {
        if (retryWidth == 0) return;
        out.print("\r" + " ".repeat(retryWidth) + "\r");
        out.flush();
        retryWidth = 0;
    }

    void retryLimitReached(int max) {
        clearRetry();
        String message = "      Environment still locked after " + max + " attempts.";
        if (rollout == null) out.println(message);
        else if (verbose) rolloutTrace.add(message);
    }

    void sapOutput(String output) {
        if (rollout == null) output.strip().lines().forEach(line -> out.println("      " + line));
        else if (verbose) output.strip().lines().forEach(line -> rolloutTrace.add("      " + line));
    }

    void stepResult(boolean success) {
        String message = "      " + tables.style(success ? "OK" : "Failed", success ? Tone.SUCCESS : Tone.ERROR);
        if (rollout == null) out.println(message);
        else if (verbose) rolloutTrace.add(message);
        out.flush();
    }

    void finish(List<String> problems, String summary, boolean success) {
        if (!problems.isEmpty()) {
            heading("Details");
            for (String problem : problems) {
                String[] lines = problem.strip().split("\\R");
                out.println("  " + tables.style("!", Tone.ERROR) + " " + lines[0]);
                for (int i = 1; i < lines.length; i++) {
                    out.println("    " + lines[i].strip());
                }
            }
        }
        out.println();
        out.println(tables.style(summary, success ? Tone.SUCCESS : Tone.ERROR));
    }
}
