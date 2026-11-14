package me.cxdev.certtool;

import com.google.gson.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.time.*;
import java.time.format.*;
import java.util.*;
import java.util.function.Consumer;
import java.util.regex.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static me.cxdev.certtool.SapCcm.*;

/** SAP Commerce Cloud certificate exchange command line tool. */
public final class CertTool {
    private static final String VERSION = Optional.ofNullable(CertTool.class.getPackage().getImplementationVersion())
            .orElse("development");
    static final String SAP_MANAGED = "sap-managed", UNMANAGED = "unmanaged";
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    private CertTool() {}

    record Certificate(String name, Path certificate, Path key, Path chain) {}
    record Environment(String key, String code, String description, Map<String,String> endpoints,
                               Map<String,String> domains, Map<String,String> credentials) {}
    record Config(Path path, String subscription, Path sapccmHome, Path zipDir,
                          Map<String,Certificate> certificates, Map<String,Environment> environments,
                          List<String> protectedCertificates, String expiryFormat,
                          Map<String,String> credentials, JsonObject raw) {
        Environment environment(String name) {
            Environment found = environments.get(name);
            if (found == null) found = environments.values().stream().filter(e -> e.code.equals(name)).findFirst().orElse(null);
            if (found == null) throw new ConfigException("Environment '" + name + "' is not configured. Known environments: " + String.join(", ", environments.keySet()));
            return found;
        }
        boolean protectedCert(String code, String name) {
            return protectedCertificates.stream().anyMatch(p -> glob(p, code) || glob(p, name));
        }
    }
    record Credentials(String id, String secret, String tokenUrl, LocalDateTime expires, String source) {}
    record Target(List<RemoteCert> candidates, Set<String> accepted, String text, String missing) {}
    static final class ConfigException extends RuntimeException { ConfigException(String m) { super(m); } }
    public static void main(String[] argv) { System.exit(run(argv)); }
    static int run(String[] argv) {
        String prog = System.getenv().getOrDefault("CERTTOOL_PROG", "cxdev-certificates");
        if (argv.length == 1 && argv[0].equals("--version")) { System.out.println("certtool " + VERSION); return 0; }
        if (argv.length == 0 || argv[0].equals("--help") || argv[0].equals("-h") || argv[0].equals("help")) { overview(prog); return 0; }
        try {
            Args a = Args.parse(argv);
            if (a.help) { help(prog, a.command); return 0; }
            boolean rollout = a.command.equals("rollout");
            ConsolePrinter printer = ConsolePrinter.standard(a.verbose);
            Config c;
            Environment env;
            printer.startLoading("Loading configuration...", false);
            try {
                c = loadConfig(a.config);
                env = a.environment == null || a.command.equals("fetch") ? null : c.environment(a.environment);
            } finally {
                printer.clearLoading();
            }
            Credentials credentials = credentials(c, rollout ? env : null);
            warnFileMode(c.path);
            printContext(printer, a, c, env, credentials);
            List<String> sapccm = locateSapccm(c.sapccmHome, c.zipDir);
            try (Sap session = new Sap(sapccm, credentials, c.subscription, a.verbose, printer)) {
                CommandReport report;
                printer.startLoading("Preparing " + a.command + "...", true);
                try {
                    report = switch (a.command) {
                        case "upload" -> CertificateCommands.upload(c, session, a, printer);
                        case "rollout" -> CertificateCommands.rollout(c, session, env, a);
                        case "cleanup" -> CertificateCommands.cleanup(c, session, a);
                        case "status" -> CertificateCommands.status(c, session, env, printer);
                        case "fetch" -> CertificateCommands.fetch(c, session, a);
                        default -> throw new ConfigException("Unknown command: " + a.command);
                    };
                } finally {
                    printer.clearLoading();
                }
                var outcome = report.outcome();
                if (rollout && report.apply() != null) {
                    printer.startRollout(report.tables().getFirst());
                    try {
                        outcome = report.apply().execute(printer);
                    } finally {
                        printer.finishRollout();
                    }
                } else {
                    for (var table : report.tables()) {
                        printer.table(table);
                    }
                    if (report.apply() != null) {
                        printer.heading("Executing");
                        outcome = report.apply().execute(printer);
                    }
                }
                printer.finish(outcome.problems(), outcome.summary(), outcome.exitCode() == 0);
                return outcome.exitCode();
            }
        } catch (ConfigException e) { System.err.println("ERROR: " + e.getMessage()); return 2; }
          catch (SapException e) { System.err.println("ERROR: " + e.getMessage()); return 1; }
          catch (InterruptedException e) { Thread.currentThread().interrupt(); System.err.println("Aborted."); return 130; }
          catch (Exception e) { System.err.println("ERROR: " + e.getMessage()); return 1; }
    }

    static final class Args {
        String command, environment, config; boolean apply, verbose, includeUnused, help;
        List<String> certificates = new ArrayList<>(), endpoints = new ArrayList<>();
        static Args parse(String[] args) {
            Args a = new Args(); int i = 0;
            while (i < args.length && (args[i].startsWith("-") || args[i].equals("help"))) {
                if (args[i].equals("-h") || args[i].equals("--help")) { a.help = true; i++; continue; }
                if ((args[i].equals("-c") || args[i].equals("--config")) && i + 1 < args.length) { a.config = args[i+1]; i+=2; continue; }
                if (args[i].equals("-v") || args[i].equals("--verbose")) { a.verbose=true; i++; continue; }
                break;
            }
            if (i >= args.length) throw new ConfigException("A command is required.");
            a.command = args[i++];
            while (i < args.length) {
                String s=args[i++];
                if (s.equals("--help") || s.equals("-h")) a.help=true;
                else if (s.equals("--apply")) a.apply=true;
                else if (s.equals("--include-unused")) a.includeUnused=true;
                else if (s.equals("-v") || s.equals("--verbose")) a.verbose=true;
                else if ((s.equals("-c") || s.equals("--config")) && i<args.length) a.config=args[i++];
                else if (s.equals("--certificate") && i<args.length) a.certificates.add(args[i++]);
                else if (s.startsWith("--certificate=")) a.certificates.add(s.substring(14));
                else if (s.equals("--endpoint") && i<args.length) a.endpoints.add(args[i++]);
                else if (s.startsWith("--endpoint=")) a.endpoints.add(s.substring(11));
                else if (!s.startsWith("-") && a.environment==null && List.of("rollout","status","fetch").contains(a.command)) a.environment=s;
                else throw new ConfigException("Unrecognized argument: " + s);
            }
            if (!List.of("upload","rollout","cleanup","status","fetch").contains(a.command)) throw new ConfigException("Unknown command: " + a.command);
            if (a.command.equals("rollout") && a.environment==null) throw new ConfigException("rollout requires an environment.");
            return a;
        }
    }

    static Config loadConfig(String filename) throws IOException {
        Path path=(filename==null?Path.of("certtool.json"):Path.of(filename)).toAbsolutePath().normalize();
        if (!Files.isRegularFile(path)) throw new ConfigException("Configuration file not found: " + path + "\nRun certtool in the project directory that contains certtool.json, or pass --config <file>.\nA template is available at " + installRoot().resolve("certtool.example.json"));
        JsonObject raw;
        try (Reader r=Files.newBufferedReader(path, StandardCharsets.UTF_8)) { raw=JsonParser.parseReader(r).getAsJsonObject(); }
        catch (JsonParseException e) { throw new ConfigException("Invalid JSON in " + path + ": " + e.getMessage()); }
        if (raw.has("certificatesDir")) throw new ConfigException("'certificatesDir' was renamed to 'certificatesPath' (relative to the configuration file).");
        String subscription=str(raw,"subscriptionCode","").trim();
        if (subscription.isBlank() || subscription.startsWith("<")) throw new ConfigException("'subscriptionCode' is missing in the configuration.");
        Path certRoot=resolve(path.getParent(), str(raw,"certificatesPath","./certificates"));
        Map<String,Certificate> certs=new LinkedHashMap<>();
        JsonObject specs=obj(raw,"certificates");
        for (String name: specs.keySet()) { JsonObject s=asObj(specs.get(name)); Path d=resolve(certRoot,str(s,"directory",name)); certs.put(name,new Certificate(name,resolve(d,str(s,"certificate","certificate.pem")),resolve(d,str(s,"privateKey","private-key.pem")),resolve(d,str(s,"caChain","ca-chain.pem")))); }
        Map<String,String> subCred=readCredentials(raw.get("credentials"),"credentials");
        Map<String,Environment> envs=new LinkedHashMap<>(); JsonObject environments=obj(raw,"environments");
        for (String key: environments.keySet()) {
            JsonObject spec=asObj(environments.get(key)); Map<String,String> endpoints=new LinkedHashMap<>(),domains=new LinkedHashMap<>();
            JsonObject eps=obj(spec,"endpoints");
            for (String ep:eps.keySet()) {
                JsonElement value=eps.get(ep); String target;
                if (value.isJsonObject()) { JsonObject v=value.getAsJsonObject(); target=str(v,"certificate",UNMANAGED); if (!str(v,"domain","").isBlank()) domains.put(ep,str(v,"domain","").trim().toLowerCase(Locale.ROOT).replaceAll("\\.$","")); }
                else if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()) target=value.getAsString();
                else throw new ConfigException("Environment '"+key+"', endpoint '"+ep+"': expected a certificate name or an object with domain and certificate.");
                if (!List.of(SAP_MANAGED,UNMANAGED).contains(target) && !certs.containsKey(target)) throw new ConfigException("Environment '"+key+"', endpoint '"+ep+"': certificate '"+target+"' is not configured.");
                endpoints.put(ep,target);
            }
            Map<String,String> ec=readCredentials(spec.get("credentials"),"environments."+key+".credentials");
            envs.put(key,new Environment(key,str(spec,"code",key),str(spec,"description",""),endpoints,domains,ec));
        }
        for (String reserved:List.of(SAP_MANAGED,UNMANAGED)) if(certs.containsKey(reserved)) throw new ConfigException("'"+reserved+"' is a reserved endpoint target and cannot be used as certificate name.");
        JsonObject clean=obj(raw,"cleanup"); List<String> protect=new ArrayList<>(); if(clean.has("protectedCertificates")) clean.getAsJsonArray("protectedCertificates").forEach(x->protect.add(x.getAsString()));
        Path root=installRoot();
        return new Config(path,subscription,resolve(root,str(raw,"sapccmHome","tools/sapccm")),resolve(root,str(raw,"sapccmZipDir","tools")),certs,envs,protect,str(raw,"credentialsExpiresFormat",null),subCred,raw);
    }
    private static Map<String,String> readCredentials(JsonElement e,String where) {
        Map<String,String> out=new LinkedHashMap<>(); if(e==null||e.isJsonNull()) return out;
        if(!e.isJsonObject()) throw new ConfigException(where+": expected an object with tokenEndpoint, clientId, clientSecret.");
        Set<String> allowed=Set.of("tokenEndpoint","clientId","clientSecret","clientResource","clientExpires");
        for(String k:e.getAsJsonObject().keySet()) { if(!allowed.contains(k)) throw new ConfigException(where+": unknown field "+k); String v=e.getAsJsonObject().get(k).getAsString().trim(); if(!v.isEmpty())out.put(k,v); }
        return out;
    }
    static Credentials credentials(Config c, Environment env) {
        return credentials(c, env, System.err::println);
    }
    static Credentials credentials(Config c, Environment env, Consumer<String> warning) {
        Map<String,String> block=env!=null && env.credentials.containsKey("clientId")?env.credentials:c.credentials;
        String source=block==envCredentials(env)?"environments."+env.key+".credentials":"credentials";
        if (env!=null && !env.credentials.containsKey("clientId") && (env.credentials.containsKey("clientSecret")||env.credentials.containsKey("clientExpires"))) throw new ConfigException("environments."+env.key+".credentials defines clientSecret/clientExpires but no clientId; credentials of different technical users are never mixed.");
        String token=env!=null?env.credentials.getOrDefault("tokenEndpoint",c.credentials.getOrDefault("tokenEndpoint","")):c.credentials.getOrDefault("tokenEndpoint","");
        for(String f:List.of("clientId","clientSecret")) if(!block.containsKey(f)) throw new ConfigException("Technical user credentials are missing in "+c.path.getFileName()+": "+source+"."+f);
        if(token.isBlank()) throw new ConfigException("Technical user credentials are missing in "+c.path.getFileName()+": tokenEndpoint");
        LocalDateTime expiry=null; String raw=block.get("clientExpires");
        if(raw!=null&&!raw.isBlank()) { expiry=parseExpiry(raw,c.expiryFormat); if(!expiry.isAfter(LocalDateTime.now())) throw new ConfigException("The client secret has expired ("+source+".clientExpires). Create a new secret and update the configuration."); if(Duration.between(LocalDateTime.now(),expiry).toDays()<14) warning.accept("WARNING: The client secret expires soon ("+expiry.toLocalDate()+")."); }
        return new Credentials(block.get("clientId"),block.get("clientSecret"),token,expiry,source);
    }
    private static Map<String,String> envCredentials(Environment e){return e==null?Map.of():e.credentials;}
    private static LocalDateTime parseExpiry(String value,String explicit) {
        String s=value.trim().replaceAll("\\s+"," ");
        try { return LocalDateTime.parse(s); } catch(DateTimeParseException ignored){}
        try { return LocalDate.parse(s).atStartOfDay(); } catch(DateTimeParseException ignored){}
        List<DateTimeFormatter> formats=explicit==null?List.of(DateTimeFormatter.ofPattern("d/M/uuuu h:mm:ss a",Locale.US),DateTimeFormatter.ofPattern("d/M/uuuu h:mm a",Locale.US),DateTimeFormatter.ofPattern("d/M/uuuu H:mm:ss"),DateTimeFormatter.ofPattern("d/M/uuuu")):List.of(DateTimeFormatter.ofPattern(explicit,Locale.US));
        for(DateTimeFormatter f:formats) try { return LocalDateTime.parse(s,f); } catch(DateTimeParseException ignored){}
        throw new ConfigException("Cannot interpret expiration date '"+s+"'.");
    }
    private static Path installRoot() {
        String configured=System.getenv("CERTTOOL_HOME"); if(configured!=null&&!configured.isBlank()) return Path.of(configured).toAbsolutePath().normalize();
        Path here=Path.of(".").toAbsolutePath().normalize();
        for(Path p=here;p!=null;p=p.getParent()) if(Files.exists(p.resolve("build.gradle.kts"))) return p;
        try { Path p=Path.of(CertTool.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toAbsolutePath();
            while(p!=null&&!Files.isDirectory(p.resolve("bin")))p=p.getParent(); return p==null?here:p;
        } catch(Exception e){return here;}
    }
    private static Path resolve(Path base,String v){ Path p=Path.of(v.replace("~",System.getProperty("user.home"))); return p.isAbsolute()?p.normalize():base.resolve(p).normalize(); }
    static JsonObject obj(JsonObject o,String k){return o.has(k)&&o.get(k).isJsonObject()?o.getAsJsonObject(k):new JsonObject();}
    private static JsonObject asObj(JsonElement e){return e!=null&&e.isJsonObject()?e.getAsJsonObject():new JsonObject();}
    private static String str(JsonObject o,String k,String d){return o.has(k)&&!o.get(k).isJsonNull()?o.get(k).getAsString():d;}
    static boolean glob(String pattern,String value){
        StringBuilder regex=new StringBuilder("^");
        for(int i=0;i<pattern.length();i++){
            char c=pattern.charAt(i);
            if(c=='*')regex.append(".*");else if(c=='?')regex.append('.');
            else if(c=='['){int end=pattern.indexOf(']',i+1);if(end<0)regex.append("\\[");else{String chars=pattern.substring(i+1,end);regex.append('[');if(chars.startsWith("!")||chars.startsWith("^")){regex.append('^');chars=chars.substring(1);}for(char x:chars.toCharArray()){if(x=='\\')regex.append("\\\\");else regex.append(x);}regex.append(']');i=end;}}
            else {if("\\.()+|^$@%{}".indexOf(c)>=0)regex.append('\\');regex.append(c);}
        }
        return value.matches(regex.append('$').toString());
    }

    static Path findSapccmArchive(Path zipDir, Path cxdevHome) throws IOException {
        if (Files.isDirectory(zipDir)) {
            try (var files = Files.list(zipDir)) {
                Path local = files.filter(CertTool::isSapccmArchive).max(Comparator.naturalOrder()).orElse(null);
                if (local != null) return local;
            }
        }
        if (cxdevHome == null) return null;
        Path dependencies = cxdevHome.resolve("dependencies");
        if (!Files.isDirectory(dependencies)) return null;

        Comparator<Path> archiveOrder = Comparator.comparing((Path path) -> path.getFileName().toString())
                .thenComparing(Comparator.naturalOrder());
        Path archive = null;
        try (var directories = Files.list(dependencies)) {
            for (Path directory : directories.filter(Files::isDirectory)
                    .filter(path -> path.getFileName().toString().startsWith("sapccm")).toList()) {
                try (var files = Files.walk(directory.toRealPath())) {
                    Path candidate = files.filter(CertTool::isSapccmArchive).max(archiveOrder).orElse(null);
                    if (candidate != null && (archive == null || archiveOrder.compare(candidate, archive) > 0)) {
                        archive = candidate;
                    }
                }
            }
        }
        return archive;
    }

    private static boolean isSapccmArchive(Path path) {
        String name = path.getFileName().toString().toUpperCase(Locale.ROOT);
        return name.startsWith("CXCOMMCLI") && name.endsWith(".ZIP") && Files.isRegularFile(path);
    }

    private static List<String> locateSapccm(Path home,Path zipDir) throws IOException {
        String override=System.getenv("CERTTOOL_SAPCCM");
        if(override!=null&&!override.isBlank()) return Arrays.asList(override.split("\\s+"));
        boolean win=System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win");
        Path script=home.resolve("bin").resolve(win?"sapccm.bat":"sapccm");
        if(!Files.isRegularFile(script)) {
            String environmentHome = System.getenv("CXDEVHOME");
            Path cxdevHome = environmentHome == null || environmentHome.isBlank() ? null : Path.of(environmentHome);
            Path archive = findSapccmArchive(zipDir, cxdevHome);
            if (archive == null) {
                String fallback = cxdevHome == null ? "" : " or under " + cxdevHome.resolve("dependencies/sapccm*");
                throw new ConfigException("sapccm not found (" + script + ") and no CXCOMMCLI*.ZIP in " + zipDir
                        + fallback + ". Download it from SAP Software Downloads.");
            }
            System.err.println("Extracting "+archive+" to "+home+" ..."); Files.createDirectories(home);
            try(ZipInputStream in=new ZipInputStream(Files.newInputStream(archive))){ ZipEntry e; while((e=in.getNextEntry())!=null){Path target=home.resolve(e.getName()).normalize(); if(!target.startsWith(home.normalize()))throw new ConfigException("Unsafe path in SAP CLI archive."); if(e.isDirectory())Files.createDirectories(target);else{Files.createDirectories(target.getParent());Files.copy(in,target,StandardCopyOption.REPLACE_EXISTING);} }}
            if(!Files.isRegularFile(script))throw new ConfigException(script+" not found after extracting the archive.");
        }
        if(!win)script.toFile().setExecutable(true,true);
        return win?List.of("cmd","/c",script.toString()):List.of(script.toString());
    }

    static boolean sapManaged(String n){String v=n.toLowerCase(Locale.ROOT).replace('’','\'').replace('´','\'').replace('`','\'');return v.contains("let's encrypt");}
    private static List<RemoteCert> managed(Environment e,List<RemoteCert> all){String p=e.code.toLowerCase(Locale.ROOT)+"-public";return all.stream().filter(c->sapManaged(c.name())&&c.name().toLowerCase(Locale.ROOT).startsWith(p)).sorted(Comparator.comparing(RemoteCert::expiration).thenComparing(RemoteCert::name).reversed()).toList();}
    static Target target(String name,Environment e,List<RemoteCert> all){if(name.equals(SAP_MANAGED)){List<RemoteCert> list=managed(e,all);RemoteCert first=list.isEmpty()?null:list.get(0);Set<String> accepted=new HashSet<>();list.forEach(c->{accepted.add(c.code());accepted.add(c.name());});return new Target(first==null?List.of():List.of(first),accepted,SAP_MANAGED+(first==null?"":"\n"+first.name()+" ["+first.code()+"]"),"no SAP-managed certificate for '"+e.code+"' found");}List<RemoteCert> list=all.stream().filter(c->c.name().equals(name)).toList();Set<String> accepted=list.size()==1?Set.of(list.get(0).code(),list.get(0).name()):Set.of();return new Target(list,accepted,list.size()==1?name+" ["+list.get(0).code()+"]":name,"target not uploaded");}
    static String describe(String value,List<RemoteCert> all){if(value==null||value.isBlank())return "(no certificate)";return all.stream().filter(c->c.code().equals(value)||c.name().equals(value)).findFirst().map(c->c.name()+" ["+c.code()+"]").orElse(value);}
    static String domainDrift(Environment e,String endpoint,String actual){String expected=e.domains.get(endpoint);return expected==null||actual.isBlank()||expected.equals(actual)?null:"the endpoint domain in the portal is '"+actual+"', the configuration expects '"+expected+"'. Check the Cloud Portal or update the configuration.";}
    static String effectiveDomain(Environment e,String ep,String actual){return actual.isBlank()?e.domains.getOrDefault(ep,""):actual;}
    static boolean domainCovered(String domain, List<String> names) {
        String hostname = domain.toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
        int firstDot = hostname.indexOf('.');
        for (String name : names) {
            String pattern = name.strip().toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
            if (pattern.equals(hostname)) return true;
            if (pattern.startsWith("*.") && firstDot > 0 && hostname.substring(firstDot + 1).equals(pattern.substring(2))) return true;
        }
        return false;
    }
    private static List<String> domains(Path cert){try{Process p=new ProcessBuilder("openssl","x509","-in",cert.toString(),"-noout","-text").start();String text=new String(p.getInputStream().readAllBytes(),StandardCharsets.UTF_8);if(p.waitFor()!=0)return List.of();Matcher m=Pattern.compile("DNS:([^\\s,]+)").matcher(text);List<String> r=new ArrayList<>();while(m.find())r.add(m.group(1).toLowerCase(Locale.ROOT));if(r.isEmpty()){m=Pattern.compile("Subject:.*?CN\\s*=\\s*([^,/\\n]+)").matcher(text);if(m.find())r.add(m.group(1).trim().toLowerCase(Locale.ROOT));}return r;}catch(Exception e){return List.of();}}
    static String domainMismatch(Config c,String name,String domain){Certificate cert=c.certificates.get(name);if(domain.isBlank()||cert==null)return null;List<String> ns=domains(cert.certificate);return ns.isEmpty()||domainCovered(domain,ns)?null:"certificate '"+name+"' ("+String.join(", ",ns)+") does not cover endpoint domain '"+domain+"'.";}
    static String classify(Config c,RemoteCert x,boolean unused){
        if(sapManaged(x.name()))return "SAP-managed";
        if(c.certificates.containsKey(x.name()))return unused&&x.endpoints()==0&&!c.protectedCert(x.code(),x.name())?"configured, unused":"configured";
        if(c.protectedCert(x.code(),x.name()))return "protected"; return x.endpoints()!=0?"in use":"deletable";
    }
    static void writeConfig(Path path,JsonObject raw)throws IOException {
        Path tmp=Files.createTempFile(path.getParent(),"certtool-",".tmp");
        try{Files.setPosixFilePermissions(tmp,EnumSet.of(PosixFilePermission.OWNER_READ,PosixFilePermission.OWNER_WRITE));}catch(UnsupportedOperationException ignored){}
        Files.writeString(tmp,GSON.toJson(raw)+"\n",StandardCharsets.UTF_8,StandardOpenOption.TRUNCATE_EXISTING);
        try{Set<PosixFilePermission> mode=Files.getPosixFilePermissions(path);Files.setPosixFilePermissions(tmp,mode);}catch(Exception ignored){}
        try{Files.move(tmp,path,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}catch(AtomicMoveNotSupportedException e){Files.move(tmp,path,StandardCopyOption.REPLACE_EXISTING);}
    }

    private static void printContext(ConsolePrinter printer, Args args, Config config, Environment env, Credentials user) {
        String mode = args.command.equals("status") ? "read-only"
                : args.apply ? "apply" : "preview (use --apply to change)";
        String environment = env != null ? env.code() : Objects.toString(args.environment, "- (subscription wide)");
        String expiry = user.expires() == null ? "secret expiry not set" : "secret expires " + user.expires().toLocalDate();
        printer.context("SAP Commerce Cloud Certificate Exchange · certtool " + VERSION, List.of(
                Map.entry("Command", args.command),
                Map.entry("Mode", mode),
                Map.entry("Configuration", display(config.path())),
                Map.entry("Subscription", config.subscription()),
                Map.entry("Environment", environment),
                Map.entry("Credentials", user.source() + " · " + expiry),
                Map.entry("Java", System.getProperty("java.version") + " (certtool and sapccm)"),
                Map.entry("Runtime", System.getProperty("os.name") + " " + System.getProperty("os.arch")),
                Map.entry("Started", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")))));
    }

    private static void warnFileMode(Path path){try{Set<PosixFilePermission> p=Files.getPosixFilePermissions(path);if(p.contains(PosixFilePermission.GROUP_READ)||p.contains(PosixFilePermission.OTHERS_READ)||p.contains(PosixFilePermission.GROUP_WRITE)||p.contains(PosixFilePermission.OTHERS_WRITE))System.err.println("WARNING: "+path.getFileName()+" contains credentials and is accessible by other users. Restrict it with chmod 600 "+path.getFileName());}catch(Exception ignored){}}
    static String display(Path p){Path cwd=Path.of("").toAbsolutePath();return p.toAbsolutePath().normalize().startsWith(cwd)?cwd.relativize(p.toAbsolutePath().normalize()).toString():p.toString();}
    private static void help(String prog,String cmd){System.out.println(switch(cmd){case "upload"->"Upload missing configured certificates. Usage: "+prog+" upload [--certificate NAME] [--apply]";case "rollout"->"Assign configured certificates to an environment. Usage: "+prog+" rollout <environment> [--endpoint CODE] [--apply]";case "cleanup"->"Delete unused certificates. Usage: "+prog+" cleanup [--include-unused] [--apply]";case "fetch"->"Add missing endpoints from the portal. Usage: "+prog+" fetch [environment] [--apply]";default->"Compare local and portal certificates. Usage: "+prog+" status [environment]";});}
    private static void overview(String prog){System.out.println("SAP Commerce Cloud Certificate Exchange · certtool "+VERSION+"\n\nUsage: "+prog+" <command> [options]\n\nCommands:\n  upload [--apply]                 Upload missing certificates\n  rollout <environment> [--apply]  Assign certificates to endpoints\n  cleanup [--include-unused] [--apply]  Delete unused certificates\n  status [environment]             Compare local and portal state\n  fetch [environment] [--apply]    Add missing portal endpoints\n\nRun from a project directory containing certtool.json. Changes require --apply.");}
}
