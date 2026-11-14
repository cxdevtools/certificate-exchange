package me.cxdev.certtool;

import java.util.List;

record CommandReport(List<Table> tables, Outcome outcome, Apply apply) {
    enum Tone {
        PLAIN(""), BOLD("1"), DIM("2"), SUCCESS("32"), WARNING("33"), ERROR("31"), INFO("36");

        final String ansi;

        Tone(String ansi) {
            this.ansi = ansi;
        }
    }

    record Cell(String text, Tone tone) {
        static Cell text(String text) {
            return new Cell(text, Tone.PLAIN);
        }
    }

    record Table(String title, List<String> headers, List<List<Cell>> rows) {}

    record Outcome(int exitCode, List<String> problems, String summary) {}

    @FunctionalInterface
    interface Apply {
        Outcome execute(ConsolePrinter printer) throws Exception;
    }

    static CommandReport finished(List<Table> tables, List<String> problems, String summary) {
        return new CommandReport(tables, new Outcome(problems.isEmpty() ? 0 : 1, problems, summary), null);
    }
}
