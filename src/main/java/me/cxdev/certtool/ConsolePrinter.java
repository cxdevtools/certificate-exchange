package me.cxdev.certtool;

import java.io.PrintStream;
import java.util.List;
import java.util.Map;

import me.cxdev.certtool.CommandReport.Cell;
import me.cxdev.certtool.CommandReport.Tone;

final class ConsolePrinter {
    private final PrintStream out;
    private final TablePrinter tables;
    private int step;

    ConsolePrinter(PrintStream out, boolean unicode, boolean color) {
        this.out = out;
        this.tables = new TablePrinter(out, unicode, color);
    }

    static ConsolePrinter standard() {
        boolean color = System.console() != null && !System.getenv().containsKey("NO_COLOR")
                && !"dumb".equals(System.getenv("TERM"));
        return new ConsolePrinter(System.out, System.out.charset().newEncoder().canEncode("┌─┐│"), color);
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

    void table(String title, List<String> headers, List<List<Cell>> rows) {
        heading(title);
        tables.print(headers, rows);
    }

    void heading(String title) {
        out.println();
        out.println(tables.style(title, Tone.BOLD));
    }

    void plan(String command, boolean apply) {
        List<String> steps = switch (command) {
            case "upload" -> List.of("Read uploaded certificates and check local certificate files.",
                    "Show which certificates are ready to upload.");
            case "rollout" -> List.of("Read certificates and endpoint settings. Verify target domain coverage.",
                    "Show changes to endpoint domains and certificates.");
            case "cleanup" -> List.of("Read certificates and check which ones are in use or protected.",
                    "Show which certificates can be removed.");
            case "fetch" -> List.of("Read environments and endpoints from the portal.",
                    "Show which entries are missing from the configuration.");
            case "status" -> List.of("Read uploaded certificates and check local certificate files.",
                    "Read endpoint assignments and show the comparison.");
            default -> throw new IllegalArgumentException("Unknown command: " + command);
        };
        heading("Plan");
        for (int index = 0; index < steps.size(); index++) {
            out.printf("  %d. %s%n", index + 1, steps.get(index));
        }
        if (!command.equals("status")) {
            String end = apply ? "Apply the changes listed in the table." : "Finish without making changes (preview).";
            out.printf("  %d. %s%n", steps.size() + 1, end);
        }
        heading("Checking");
        out.flush();
    }

    void step(String message) {
        out.printf("  [%d] %s%n", ++step, message);
        out.flush();
    }

    void sapCall(List<String> args, boolean full) {
        if (full) {
            step("$ sapccm " + String.join(" ", args));
            return;
        }
        List<String> scope = args.stream().skip(2)
                .filter(arg -> arg.startsWith("--environment-code=") || arg.startsWith("--code=")
                        || arg.startsWith("--certificate-code="))
                .map(arg -> arg.substring(arg.indexOf('=') + 1)).toList();
        step("sapccm " + String.join(" ", args.subList(0, 2))
                + (scope.isEmpty() ? "" : " (" + String.join(" / ", scope) + ")"));
    }

    void sapOutput(String output) {
        output.strip().lines().forEach(line -> out.println("      " + line));
    }

    void stepResult(boolean success) {
        out.println("      " + tables.style(success ? "OK" : "Failed", success ? Tone.SUCCESS : Tone.ERROR));
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
