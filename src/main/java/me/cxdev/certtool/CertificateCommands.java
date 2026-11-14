package me.cxdev.certtool;

import com.google.gson.JsonObject;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import static me.cxdev.certtool.CertTool.*;
import static me.cxdev.certtool.CertificateFiles.*;
import static me.cxdev.certtool.SapCcm.*;
import static me.cxdev.certtool.CommandReport.*;
import static me.cxdev.certtool.CommandReport.Tone.*;

final class CertificateCommands {
    private CertificateCommands() {}

    static CommandReport upload(Config config, Sap sap, Args args, ConsolePrinter printer) throws Exception {
        List<String> names = args.certificates.isEmpty()
                ? List.copyOf(config.certificates().keySet()) : args.certificates;
        List<String> unknown = names.stream().filter(name -> !config.certificates().containsKey(name)).toList();
        if (!unknown.isEmpty()) {
            throw new ConfigException("Certificates not configured: " + String.join(", ", unknown));
        }
        List<RemoteCert> remote = names.isEmpty() ? List.of() : remote(sap);
        List<List<Cell>> rows = new ArrayList<>();
        List<Certificate> pending = new ArrayList<>();
        List<String> problems = new ArrayList<>();
        int blocked = 0;

        if (!names.isEmpty()) printer.loading("Checking local certificates...");
        for (String name : new LinkedHashSet<>(names)) {
            Certificate cert = config.certificates().get(name);
            List<RemoteCert> matches = named(remote, name);
            CertificateCheck check = checkCertificate(cert, printer::warning);
            Cell action;
            if (!matches.isEmpty()) {
                String codes = String.join(", ", matches.stream().map(RemoteCert::code).toList());
                action = new Cell("skip - already uploaded [" + codes + "]", SUCCESS);
            } else if (!check.errors().isEmpty()) {
                blocked++;
                action = new Cell("blocked - local check failed", ERROR);
                check.errors().forEach(error -> problems.add(name + ": " + error));
            } else {
                pending.add(cert);
                action = new Cell(args.apply ? "upload" : "would upload", WARNING);
            }
            rows.add(List.of(Cell.text(name), Cell.text(date(check.expires())), action));
        }

        Table table = new Table("Upload plan" + preview(args), List.of("Certificate", "Valid until", "Action"), rows);
        if (args.apply && !pending.isEmpty()) {
            return new CommandReport(List.of(table), null, ignored -> {
                int uploaded = 0;
                for (Certificate cert : pending) {
                    try {
                        uploadCertificate(sap, cert);
                        uploaded++;
                    } catch (IOException | SapException error) {
                        problems.add(cert.name() + ": upload failed\n" + error.getMessage());
                    }
                }
                return withErrorCount(problems, "Upload finished: " + uploaded + " certificate(s) uploaded");
            });
        }
        String summary = args.apply ? "Upload finished: 0 certificate(s) uploaded"
                : pending.size() + " certificate(s) would be uploaded";
        if (blocked > 0) summary += ", " + blocked + " blocked";
        summary += ".";
        if (!args.apply && !pending.isEmpty()) summary += " Use 'upload --apply' to upload them.";
        return finished(List.of(table), problems, summary);
    }

    private static void uploadCertificate(Sap sap, Certificate cert) throws Exception {
        List<String> blocks = pemBlocks(Files.readString(cert.certificate()));
        boolean bundled = blocks.size() > 1;
        Path leaf = bundled ? sap.tempFile("upload-certificate.pem", blocks.getFirst()) : cert.certificate();
        Path chain = cert.chain();
        if (bundled || !Files.exists(chain)) {
            String contents = bundled ? String.join("", blocks.subList(1, blocks.size())) : "";
            if (Files.exists(chain)) contents += Files.readString(chain);
            chain = sap.tempFile("upload-ca-chain.pem", contents.isEmpty() ? "\n" : contents);
        }
        sap.run(List.of("certificate", "create", "--subscription-code=" + sap.subscription, "--name=" + cert.name(),
                "--certificate-path=" + leaf, "--certificate-key-path=" + cert.key(), "--ca-certificate-path=" + chain), true);
    }

    private record Switch(int row, String endpoint, String code, String domain) {
        List<String> arguments(String subscription, String environment) {
            List<String> args = new ArrayList<>(List.of("endpoint", "update", "--subscription-code=" + subscription,
                    "--environment-code=" + environment, "--code=" + endpoint, "--ssl-certificate=" + code));
            if (domain != null) args.add("--domain-name=" + domain);
            return args;
        }
    }

    static CommandReport rollout(Config config, Sap sap, Environment env, Args args) throws Exception {
        Map<String, String> mapping = new LinkedHashMap<>(env.endpoints());
        if (!args.endpoints.isEmpty()) {
            for (String endpoint : args.endpoints) {
                if (!mapping.containsKey(endpoint)) {
                    throw new ConfigException("Endpoint '" + endpoint + "' not configured for environment '" + env.key() + "'.");
                }
            }
            mapping.keySet().retainAll(args.endpoints);
        }
        List<RemoteCert> all = mapping.isEmpty() ? List.of() : remote(sap);
        Map<String, String> live = mapping.isEmpty() ? Map.of() : endpoints(sap, env.code());
        List<List<Cell>> rows = new ArrayList<>();
        List<Switch> pending = new ArrayList<>();
        List<String> problems = new ArrayList<>();
        boolean readFailed = false;
        Map<String, List<String>> uploadedDomains = new HashMap<>();

        for (var entry : mapping.entrySet()) {
            String endpoint = entry.getKey();
            String name = entry.getValue();
            String currentDomain = live.getOrDefault(endpoint, "");
            String configuredDomain = env.domains().get(endpoint);
            String targetDomain = configuredDomain == null ? currentDomain : configuredDomain;
            boolean domainChanged = configuredDomain != null && !configuredDomain.equals(currentDomain);
            if (name.equals(UNMANAGED)) {
                rows.add(endpointRow(endpoint, currentDomain, targetDomain, "-", name, new Cell("skip - unmanaged", DIM)));
                continue;
            }
            Target target = target(name, env, all);
            String problem = rolloutProblem(config, live, endpoint, name, target, targetDomain, domainChanged);
            String certificateCode = target.candidates().isEmpty() ? "" : target.candidates().getFirst().code();
            if (problem == null && domainChanged) {
                try {
                    if (!uploadedDomains.containsKey(certificateCode)) {
                        uploadedDomains.put(certificateCode, certificateDomains(sap, certificateCode));
                    }
                    problem = coverageProblem(targetDomain, uploadedDomains.get(certificateCode), "uploaded");
                } catch (IOException | SapException error) {
                    problem = "Could not verify the uploaded certificate's domains: " + error.getMessage();
                }
            }
            String current = "-";
            Cell action;
            if (problem != null) {
                problems.add(endpoint + ": " + problem);
                action = new Cell("blocked - see Details", ERROR);
            } else {
                String value;
                try {
                    value = showEndpoint(sap, env.code(), endpoint).getOrDefault("SSL CERTIFICATE", "");
                } catch (IOException | SapException error) {
                    problems.add(endpoint + ": " + error.getMessage());
                    readFailed = true;
                    rows.add(endpointRow(endpoint, currentDomain, targetDomain, "?", target.text(),
                            new Cell("could not read endpoint", ERROR)));
                    continue;
                }
                current = describe(value, all);
                if (!domainChanged && target.accepted().contains(value)) {
                    action = new Cell("unchanged - already in place", SUCCESS);
                } else {
                    pending.add(new Switch(rows.size(), endpoint, certificateCode, domainChanged ? targetDomain : null));
                    String change = domainChanged
                            ? (value.equals(certificateCode) || value.equals(target.candidates().getFirst().name())
                            ? "change domain" : "change domain and certificate")
                            : "switch certificate";
                    action = new Cell(args.apply ? change : "would " + change, WARNING);
                }
            }
            rows.add(endpointRow(endpoint, currentDomain, targetDomain, current, target.text(), action));
        }
        Table table = new Table("Rollout plan - " + environmentTitle(env) + preview(args),
                endpointHeaders("Action"), rows);
        if (readFailed) {
            return finished(List.of(table), problems, "Rollout blocked: one or more endpoints could not be read.");
        }
        if (args.apply && !pending.isEmpty()) {
            return new CommandReport(List.of(table), null, printer -> {
                int switched = 0;
                int failed = 0;
                for (Switch item : pending) {
                    boolean success = false;
                    printer.beginRolloutStep(item.row());
                    try {
                        sap.run(item.arguments(sap.subscription, env.code()), true);
                        success = true;
                        switched++;
                    } catch (IOException | SapException error) {
                        failed++;
                        if (args.verbose) problems.add(item.endpoint() + ": update failed\n" + error.getMessage());
                    } finally {
                        printer.endRolloutStep(success);
                    }
                }
                String summary = "Rollout finished: " + switched + " endpoint(s) switched"
                        + (failed == 0 ? "." : ", " + failed + " failed (use --verbose for details).");
                return new Outcome(failed == 0 && problems.isEmpty() ? 0 : 1, problems, summary);
            });
        }
        String summary = args.apply ? "Rollout finished: 0 endpoint(s) switched."
                : pending.size() + " endpoint(s) would be switched.";
        if (!args.apply && !pending.isEmpty()) summary += " Use 'rollout " + env.key() + " --apply' to switch them.";
        return finished(List.of(table), problems, summary);
    }

    private static String rolloutProblem(Config config, Map<String, String> live, String endpoint,
                                         String name, Target target, String domain, boolean domainChanged) {
        if (!live.containsKey(endpoint)) return "endpoint does not exist in the portal";
        if (target.candidates().isEmpty()) return target.missing() + (name.equals(SAP_MANAGED) ? "" : " - run 'upload' first");
        if (target.candidates().size() > 1) return "target name exists more than once";
        if (!domainChanged) return domainMismatch(config, name, domain);
        if (target.candidates().getFirst().code().isBlank()) return "The target certificate has no portal code.";
        if (live.get(endpoint).isBlank()) return "The current domain could not be read from the portal.";
        if (!isDnsName(domain)) return "Invalid configured domain '" + domain + "'. Use a hostname without protocol or path.";
        if (name.equals(SAP_MANAGED)) return null;
        try {
            return coverageProblem(domain, dnsNames(config.certificates().get(name).certificate()), "local");
        } catch (IOException | java.security.cert.CertificateException error) {
            return "Could not verify the local certificate: " + error.getMessage();
        }
    }

    static String coverageProblem(String domain, List<String> names, String source) {
        if (names.isEmpty()) return "No DNS names could be verified for the " + source + " certificate.";
        return domainCovered(domain, names) ? null : "The " + source + " certificate does not cover '" + domain
                + "' (DNS names: " + String.join(", ", names) + ").";
    }

    private static boolean isDnsName(String domain) {
        String label = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
        return domain.length() <= 253 && domain.matches(label + "(?:\\." + label + ")+");
    }

    private static List<String> endpointHeaders(String lastColumn) {
        return List.of("Endpoint", "Domain", "Certificate", lastColumn);
    }

    private static List<Cell> endpointRow(String endpoint, String currentDomain, String targetDomain,
                                          String current, String target, Cell action) {
        return List.of(Cell.text(endpoint), Cell.text(currentAndTarget(currentDomain, targetDomain)),
                Cell.text(currentAndTarget(current, target)), action);
    }

    private static String currentAndTarget(String current, String target) {
        return "Current: " + (current.isBlank() ? "-" : current)
                + "\nTarget: " + (target.isBlank() ? "-" : target);
    }

    static CommandReport cleanup(Config config, Sap sap, Args args) throws Exception {
        List<List<Cell>> rows = new ArrayList<>();
        List<RemoteCert> pending = new ArrayList<>();
        for (RemoteCert cert : remote(sap)) {
            String state = classify(config, cert, args.includeUnused);
            boolean deletable = state.equals("deletable") || state.equals("configured, unused");
            if (deletable) pending.add(cert);
            Cell action = deletable ? new Cell(args.apply ? "delete" : "would delete", args.apply ? ERROR : WARNING)
                    : new Cell(state.equals("in use") ? "keep - still assigned" : "keep", DIM);
            List<Cell> row = new ArrayList<>(remoteRow(cert, state));
            row.add(action);
            rows.add(row);
        }
        String title = "Cleanup plan" + (args.includeUnused ? " - including unused configured certificates" : "") + preview(args);
        Table table = new Table(title, List.of("Certificate", "Code", "Status", "Endpoints", "Expires", "Action"), rows);
        if (pending.isEmpty()) return finished(List.of(table), List.of(), "Cleanup finished: no deletable certificates found.");
        if (!args.apply) {
            String command = args.includeUnused ? "cleanup --include-unused --apply" : "cleanup --apply";
            return finished(List.of(table), List.of(), pending.size() + " certificate(s) would be deleted. Use '" + command + "' to delete them.");
        }
        return new CommandReport(List.of(table), null, printer -> {
            List<String> problems = new ArrayList<>();
            for (RemoteCert cert : pending) {
                try {
                    sap.run(List.of("certificate", "delete", "--subscription-code=" + sap.subscription,
                            "--certificate-code=" + cert.code()), true);
                } catch (IOException | SapException error) {
                    problems.add(cert.name() + ": deletion failed\n" + error.getMessage());
                }
            }
            return withErrorCount(problems, "Cleanup finished: " + (pending.size() - problems.size()) + " certificate(s) deleted");
        });
    }

    static CommandReport status(Config config, Sap sap, Environment only, ConsolePrinter printer) throws Exception {
        List<RemoteCert> all = remote(sap);
        List<Table> tables = new ArrayList<>();
        List<String> problems = new ArrayList<>();
        List<List<Cell>> local = new ArrayList<>();
        int issues = 0;
        if (!config.certificates().isEmpty()) printer.loading("Checking local certificates...");
        for (Certificate cert : config.certificates().values()) {
            CertificateCheck check = checkCertificate(cert, printer::warning);
            List<RemoteCert> matches = named(all, cert.name());
            boolean ok = check.errors().isEmpty();
            if (!ok) {
                issues++;
                check.errors().forEach(error -> problems.add(cert.name() + ": " + error));
            }
            String uploaded = String.join(", ", matches.stream().map(match -> "[" + match.code() + "]").toList());
            local.add(List.of(Cell.text(cert.name()), new Cell(ok ? "OK" : "check failed", ok ? SUCCESS : ERROR),
                    Cell.text(date(check.expires())), new Cell(matches.isEmpty() ? "not uploaded" : "uploaded " + uploaded,
                    matches.isEmpty() ? DIM : SUCCESS)));
        }
        tables.add(new Table("Configured certificates (local)", List.of("Certificate", "Local check", "Valid until", "Portal"), local));
        tables.add(new Table("Certificates in subscription " + config.subscription(),
                List.of("Certificate", "Code", "Status", "Endpoints", "Expires"),
                all.stream().map(cert -> remoteRow(cert, classify(config, cert, false))).toList()));

        Collection<Environment> environments = only == null ? config.environments().values() : List.of(only);
        for (Environment env : environments) {
            List<List<Cell>> rows = new ArrayList<>();
            String title = environmentTitle(env);
            try (SapLease lease = lease(config, sap, env)) {
                Sap session = lease.sap();
                Map<String, String> live = endpoints(session, env.code());
                Set<String> codes = new LinkedHashSet<>(env.endpoints().keySet());
                codes.addAll(live.keySet());
                for (String endpoint : codes) {
                    EndpointStatus status = endpointStatus(config, session, env, all, live, endpoint, problems);
                    if (status.problem()) issues++;
                    rows.add(status.cells());
                }
            } catch (IOException | SapException | ConfigException error) {
                issues++;
                problems.add(env.code() + ": " + error.getMessage());
                rows.add(endpointRow("-", "-", "-", "-", "-", new Cell("could not read environment", ERROR)));
            }
            tables.add(new Table(title, endpointHeaders("Status"), rows));
        }
        String summary = issues == 0 ? "Status: no problems found." : "Status: " + issues + " problem(s) found.";
        return new CommandReport(tables, new Outcome(issues == 0 ? 0 : 1, problems, summary), null);
    }

    private record EndpointStatus(List<Cell> cells, boolean problem) {}

    private static EndpointStatus endpointStatus(Config config, Sap sap, Environment env, List<RemoteCert> all,
                                             Map<String, String> live, String endpoint, List<String> problems) throws Exception {
        String name = env.endpoints().get(endpoint);
        String domain = live.getOrDefault(endpoint, "");
        String targetDomain = env.domains().getOrDefault(endpoint, name == null ? "" : domain);
        String targetText = name == null ? "-" : name;
        Target target = name == null || name.equals(UNMANAGED) ? null : target(name, env, all);
        if (target != null) targetText = target.text();
        if (!live.containsKey(endpoint)) {
            return new EndpointStatus(
                    endpointRow(endpoint, domain, targetDomain, "-", targetText, new Cell("endpoint does not exist", ERROR)), true);
        }

        String value;
        try {
            value = showEndpoint(sap, env.code(), endpoint).getOrDefault("SSL CERTIFICATE", "");
        } catch (IOException | SapException error) {
            problems.add(env.code() + "/" + endpoint + ": " + error.getMessage());
            return new EndpointStatus(
                    endpointRow(endpoint, domain, targetDomain, "?", targetText, new Cell("could not read endpoint", ERROR)), true);
        }
        Cell state = new Cell("not configured", DIM);
        boolean problem = false;
        if (name != null) {
            String drift = domainDrift(env, endpoint, domain);
            if (drift != null) {
                problems.add(env.code() + "/" + endpoint + ": " + drift);
                state = new Cell("domain differs from configuration", ERROR);
                problem = true;
            } else if (target == null) {
                state = new Cell("unmanaged", DIM);
            } else if (target.candidates().isEmpty()) {
                state = new Cell(target.missing(), ERROR);
                problem = true;
            } else if (target.accepted().contains(value)) {
                state = new Cell("OK - target in place", SUCCESS);
            } else {
                problem = true;
                String mismatch = domainMismatch(config, name, effectiveDomain(env, endpoint, domain));
                if (mismatch != null) {
                    problems.add(env.code() + "/" + endpoint + ": " + mismatch);
                    state = new Cell("domain not covered", ERROR);
                } else {
                    state = new Cell("rollout pending", WARNING);
                }
            }
        }
        return new EndpointStatus(endpointRow(endpoint, domain, targetDomain, describe(value, all), targetText, state), problem);
    }

    static CommandReport fetch(Config config, Sap sap, Args args) throws Exception {
        var environments = parseTable(run(sap, "environment", "list", "--subscription-code=" + sap.subscription), "CODE");
        List<RemoteCert> all = remote(sap);
        JsonObject raw = config.raw().deepCopy();
        JsonObject configuredEnvironments = obj(raw, "environments");
        List<List<Cell>> rows = new ArrayList<>();
        int added = 0;

        String requested = args.environment;
        if (requested != null && config.environments().containsKey(requested)) {
            requested = config.environments().get(requested).code();
        }
        if (environments == null) environments = List.of();
        for (var item : environments) {
            String code = item.get("CODE");
            if (code == null || code.isBlank() || requested != null && !requested.equals(code)) continue;

            Environment existing = config.environments().values().stream()
                    .filter(env -> env.code().equals(code)).findFirst().orElse(null);
            String key = existing == null ? code : existing.key();
            String description = item.getOrDefault("NAME", "");
            Environment env = existing == null
                    ? new Environment(key, code, description, Map.of(), Map.of(), Map.of()) : existing;
            JsonObject target = obj(configuredEnvironments, key);
            JsonObject configured = obj(target, "endpoints");

            try (SapLease lease = lease(config, sap, env)) {
                for (var endpoint : endpoints(lease.sap(), code).entrySet()) {
                    String endpointCode = endpoint.getKey();
                    String domain = endpoint.getValue();
                    String shownDomain = domain.isBlank() ? "-" : domain;
                    if (configured.has(endpointCode)) {
                        rows.add(List.of(Cell.text(key), Cell.text(endpointCode), Cell.text(shownDomain),
                                Cell.text(env.endpoints().getOrDefault(endpointCode, "-")),
                                new Cell("keep - already configured", DIM)));
                        continue;
                    }

                    String assigned = showEndpoint(lease.sap(), code, endpointCode).getOrDefault("SSL CERTIFICATE", "");
                    String name = fetchedTarget(config, all, assigned);
                    JsonObject entry = new JsonObject();
                    if (!domain.isBlank()) entry.addProperty("domain", domain);
                    entry.addProperty("certificate", name);
                    configured.add(endpointCode, entry);
                    rows.add(List.of(Cell.text(key), Cell.text(endpointCode), Cell.text(shownDomain), Cell.text(name),
                            new Cell(args.apply ? "add" : "would add", WARNING)));
                    added++;
                }
            }
            if (!configured.isEmpty()) {
                if (existing == null && !description.isBlank()) target.addProperty("description", description);
                target.add("endpoints", configured);
                configuredEnvironments.add(key, target);
            }
        }

        Table table = new Table("Fetch plan - " + display(config.path()) + preview(args),
                List.of("Environment", "Endpoint", "Domain", "Certificate", "Action"), rows);
        if (!args.apply) {
            String summary = added + " endpoint(s) would be added to the configuration.";
            if (added > 0) summary += " Use 'fetch --apply' to write them.";
            return finished(List.of(table), List.of(), summary);
        }
        String summary = added + " endpoint(s) added to " + display(config.path()) + ".";
        if (added == 0) return finished(List.of(table), List.of(), summary);
        raw.add("environments", configuredEnvironments);
        return new CommandReport(List.of(table), null, printer -> {
            printer.step("Write " + display(config.path()));
            try {
                writeConfig(config.path(), raw);
                printer.stepResult(true);
            } catch (IOException error) {
                printer.stepResult(false);
                return new Outcome(1, List.of(error.getMessage()), "Fetch failed: configuration could not be written.");
            }
            return new Outcome(0, List.of(), summary);
        });
    }

    private static String fetchedTarget(Config config, List<RemoteCert> all, String assigned) {
        for (RemoteCert cert : all) {
            if (cert.code().equals(assigned) || cert.name().equals(assigned)) {
                if (sapManaged(cert.name())) return SAP_MANAGED;
                if (config.certificates().containsKey(cert.name())) return cert.name();
                break;
            }
        }
        return UNMANAGED;
    }

    private static List<RemoteCert> named(List<RemoteCert> all, String name) {
        return all.stream().filter(cert -> cert.name().equals(name)).toList();
    }

    private static List<Cell> remoteRow(RemoteCert cert, String state) {
        Tone tone = switch (state) {
            case "SAP-managed", "protected" -> INFO;
            case "configured" -> SUCCESS;
            default -> WARNING;
        };
        return List.of(Cell.text(cert.name()), Cell.text(cert.code()), new Cell(state, tone),
                Cell.text(cert.endpoints() < 0 ? "?" : Integer.toString(cert.endpoints())),
                Cell.text(date(cert.expiration())));
    }

    private static String date(String value) {
        if (value == null || value.isBlank()) return "-";
        if (value.length() >= 16 && value.charAt(10) == 'T') {
            return value.substring(0, 10) + " " + value.substring(11, 16);
        }
        return value;
    }

    private static String environmentTitle(Environment env) {
        return "Environment " + env.code() + (env.description().isBlank() ? "" : " (" + env.description() + ")");
    }

    private static String preview(Args args) {
        return args.apply ? "" : " (preview)";
    }

    private static Outcome withErrorCount(List<String> problems, String summary) {
        return new Outcome(problems.isEmpty() ? 0 : 1, problems,
                summary + (problems.isEmpty() ? "." : ", " + problems.size() + " error(s)."));
    }
}
