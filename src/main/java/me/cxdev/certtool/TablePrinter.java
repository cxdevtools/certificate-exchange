package me.cxdev.certtool;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import me.cxdev.certtool.CommandReport.Cell;
import me.cxdev.certtool.CommandReport.Tone;

final class TablePrinter {
    private final PrintStream out;
    private final boolean unicode;
    private final boolean color;

    TablePrinter(PrintStream out, boolean unicode, boolean color) {
        this.out = out;
        this.unicode = unicode;
        this.color = color;
    }

    String style(String text, Tone tone) {
        return color && tone != Tone.PLAIN && !text.isEmpty()
                ? "\u001b[" + tone.ansi + "m" + text + "\u001b[0m"
                : text;
    }

    void print(List<String> headers, List<List<Cell>> rows) {
        render(headers, rows, Integer.MAX_VALUE).forEach(out::println);
    }

    List<String> render(List<String> headers, List<List<Cell>> rows, int maxWidth) {
        List<String> output = new ArrayList<>();
        int[] widths = headers.stream().mapToInt(header -> Math.max(1, width(header))).toArray();
        if (rows.isEmpty()) {
            var empty = new Cell[headers.size()];
            Arrays.fill(empty, Cell.text(""));
            empty[0] = new Cell("(none)", Tone.DIM);
            rows = List.of(List.of(empty));
        }
        for (List<Cell> row : rows) {
            for (int col = 0; col < widths.length; col++) {
                for (String line : lines(row.get(col).text())) {
                    widths[col] = Math.max(widths[col], width(line));
                }
            }
        }

        int padding = 3 + 3 * widths.length;
        int minimum = headers.stream().mapToInt(header -> Math.max(1, width(header))).sum() + padding;
        while (Arrays.stream(widths).sum() + padding > Math.max(maxWidth, minimum)) {
            int widest = -1;
            for (int col = 0; col < widths.length; col++) {
                if (widths[col] > Math.max(1, width(headers.get(col))) && (widest < 0 || widths[col] > widths[widest])) widest = col;
            }
            widths[widest]--;
        }

        output.add(border(widths, "┌┬┐"));
        row(output, widths, headers.stream().map(header -> new Cell(header, Tone.BOLD)).toList());
        String divider = border(widths, "├┼┤");
        output.add(divider);
        for (int index = 0; index < rows.size(); index++) {
            if (index > 0) output.add(divider);
            row(output, widths, rows.get(index));
        }
        output.add(border(widths, "└┴┘"));
        return output;
    }

    private String border(int[] widths, String corners) {
        String joints = unicode ? corners : "+++";
        StringBuilder line = new StringBuilder("  ").append(joints.charAt(0));
        for (int col = 0; col < widths.length; col++) {
            line.append((unicode ? "─" : "-").repeat(widths[col] + 2))
                    .append(joints.charAt(col == widths.length - 1 ? 2 : 1));
        }
        return line.toString();
    }

    private void row(List<String> output, int[] widths, List<Cell> cells) {
        List<List<String>> wrapped = new ArrayList<>();
        for (int col = 0; col < widths.length; col++) wrapped.add(wrap(cells.get(col).text(), widths[col]));
        int height = wrapped.stream().mapToInt(List::size).max().orElse(1);
        char wall = unicode ? '│' : '|';
        for (int index = 0; index < height; index++) {
            StringBuilder line = new StringBuilder("  ").append(wall);
            for (int col = 0; col < widths.length; col++) {
                List<String> parts = wrapped.get(col);
                String text = index < parts.size() ? parts.get(index) : "";
                line.append(' ').append(style(text, cells.get(col).tone()))
                        .append(" ".repeat(widths[col] - width(text) + 1)).append(wall);
            }
            output.add(line.toString());
        }
    }

    private static String[] lines(String text) {
        return text.split("\\R", -1);
    }

    private static List<String> wrap(String text, int width) {
        List<String> wrapped = new ArrayList<>();
        for (String line : lines(text)) {
            while (width(line) > width) {
                int end = line.offsetByCodePoints(0, width);
                int space = line.lastIndexOf(' ', end);
                if (space > 0) end = space;
                wrapped.add(line.substring(0, end));
                line = line.substring(end).stripLeading();
            }
            wrapped.add(line);
        }
        return wrapped;
    }

    private static int width(String text) {
        return text.codePointCount(0, text.length());
    }
}
