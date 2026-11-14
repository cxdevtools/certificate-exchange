package me.cxdev.certtool;

import java.io.PrintStream;
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
        int[] widths = headers.stream().mapToInt(TablePrinter::width).toArray();
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

        border(widths, "┌┬┐");
        row(widths, headers.stream().map(header -> new Cell(header, Tone.BOLD)).toList());
        border(widths, "├┼┤");
        rows.forEach(cells -> row(widths, cells));
        border(widths, "└┴┘");
    }

    private void border(int[] widths, String corners) {
        String joints = unicode ? corners : "+++";
        StringBuilder line = new StringBuilder("  ").append(joints.charAt(0));
        for (int col = 0; col < widths.length; col++) {
            line.append((unicode ? "─" : "-").repeat(widths[col] + 2))
                    .append(joints.charAt(col == widths.length - 1 ? 2 : 1));
        }
        out.println(line);
    }

    private void row(int[] widths, List<Cell> cells) {
        List<String[]> wrapped = cells.stream().map(cell -> lines(cell.text())).toList();
        int height = wrapped.stream().mapToInt(lines -> lines.length).max().orElse(1);
        char wall = unicode ? '│' : '|';
        for (int index = 0; index < height; index++) {
            StringBuilder line = new StringBuilder("  ").append(wall);
            for (int col = 0; col < widths.length; col++) {
                String[] parts = wrapped.get(col);
                String text = index < parts.length ? parts[index] : "";
                line.append(' ').append(style(text, cells.get(col).tone()))
                        .append(" ".repeat(widths[col] - width(text) + 1)).append(wall);
            }
            out.println(line);
        }
    }

    private static String[] lines(String text) {
        return text.split("\\R", -1);
    }

    private static int width(String text) {
        return text.codePointCount(0, text.length());
    }
}
