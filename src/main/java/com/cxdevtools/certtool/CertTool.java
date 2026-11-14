package com.cxdevtools.certtool;

import com.google.gson.*;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.time.*;
import java.time.format.*;
import java.util.*;
import java.util.regex.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** SAP Commerce Cloud certificate exchange command line tool. */
public final class CertTool {
    private static final String VERSION = "0.2.0";
    private static final String SAP_MANAGED = "sap-managed", UNMANAGED = "unmanaged";
    private static final Pattern PEM = Pattern.compile("-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", Pattern.DOTALL);
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
    private record SapLease(Sap sap, boolean owned) {}
    record RemoteCert(String code, String name, String issuer, String expiration, int endpoints) {}
    private record Target(List<RemoteCert> candidates, Set<String> accepted, String text, String missing) {}
    private record Cell(String text, String color) { Cell(String text) { this(text, ""); } }
    private static final class ConfigException extends RuntimeException { ConfigException(String m) { super(m); } }
    private static final class SapException extends RuntimeException {
        final String output; final Integer code;
        SapException(String message) { super(message); output = ""; code = null; }
        SapException(String message, String out, int exit) { super(message); output = out; code = exit; }
        String summary() { return code == null ? getMessage() : "sapccm exit code " + code + (output.isBlank() ? "" : "\n" + output); }
    }

    public static void main(String[] argv) { System.exit(run(argv)); }
    static int run(String[] argv) {
        String prog = System.getenv().getOrDefault("CERTTOOL_PROG", "cxdev-certificates");
        if (argv.length == 1 && argv[0].equals("--version")) { System.out.println("certtool " + VERSION); return 0; }
        if (argv.length == 0 || argv[0].equals("--help") || argv[0].equals("-h") || argv[0].equals("help")) { overview(prog); return 0; }
        try {
            Args a = Args.parse(argv);
            if (a.help) { help(prog, a.command); return 0; }
            Config c = loadConfig(a.config);
            Environment env = a.environment == null || a.command.equals("fetch") ? null : c.environment(a.environment);
            Credentials credentials = credentials(c, a.command.equals("rollout") ? env : null);
            warnFileMode(c.path);
            List<String> sapccm = locateSapccm(c.sapccmHome, c.zipDir);
            try (Sap session = new Sap(sapccm, credentials, c.subscription, a.verbose)) {
                context(prog, a, c, env, credentials);
                return switch (a.command) {
                    case "upload" -> upload(c, session, a);
                    case "rollout" -> rollout(c, session, env, a);
                    case "cleanup" -> cleanup(c, session, a);
                    case "status" -> status(c, session, env);
                    case "fetch" -> fetch(c, session, a);
                    default -> { overview(prog); yield 2; }
                };
            }
        } catch (ConfigException e) { System.err.println("ERROR: " + e.getMessage()); return 2; }
          catch (SapException e) { System.err.println("ERROR: " + e.getMessage()); return 1; }
          catch (InterruptedException e) { Thread.currentThread().interrupt(); System.err.println("Aborted."); return 130; }
          catch (Exception e) { System.err.println("ERROR: " + e.getMessage()); return 1; }
    }

    private static final class Args {
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
        Map<String,String> block=env!=null && env.credentials.containsKey("clientId")?env.credentials:c.credentials;
        String source=block==envCredentials(env)?"environments."+env.key+".credentials":"credentials";
        if (env!=null && !env.credentials.containsKey("clientId") && (env.credentials.containsKey("clientSecret")||env.credentials.containsKey("clientExpires"))) throw new ConfigException("environments."+env.key+".credentials defines clientSecret/clientExpires but no clientId; credentials of different technical users are never mixed.");
        String token=env!=null?env.credentials.getOrDefault("tokenEndpoint",c.credentials.getOrDefault("tokenEndpoint","")):c.credentials.getOrDefault("tokenEndpoint","");
        for(String f:List.of("clientId","clientSecret")) if(!block.containsKey(f)) throw new ConfigException("Technical user credentials are missing in "+c.path.getFileName()+": "+source+"."+f);
        if(token.isBlank()) throw new ConfigException("Technical user credentials are missing in "+c.path.getFileName()+": tokenEndpoint");
        LocalDateTime expiry=null; String raw=block.get("clientExpires");
        if(raw!=null&&!raw.isBlank()) { expiry=parseExpiry(raw,c.expiryFormat); if(!expiry.isAfter(LocalDateTime.now())) throw new ConfigException("The client secret has expired ("+source+".clientExpires). Create a new secret and update the configuration."); if(Duration.between(LocalDateTime.now(),expiry).toDays()<14) System.err.println("WARNING: The client secret expires soon ("+expiry.toLocalDate()+")."); }
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
    private static JsonObject obj(JsonObject o,String k){return o.has(k)&&o.get(k).isJsonObject()?o.getAsJsonObject(k):new JsonObject();}
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

    private static List<String> locateSapccm(Path home,Path zipDir) throws IOException {
        String override=System.getenv("CERTTOOL_SAPCCM");
        if(override!=null&&!override.isBlank()) return Arrays.asList(override.split("\\s+"));
        boolean win=System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win");
        Path script=home.resolve("bin").resolve(win?"sapccm.bat":"sapccm");
        if(!Files.isRegularFile(script)) {
            if(!Files.isDirectory(zipDir)) throw new ConfigException("sapccm not found ("+script+") and no CLI archive in "+zipDir+".");
            Path archive;
            try(var files=Files.list(zipDir)){ archive=files.filter(Files::isRegularFile).filter(p->p.getFileName().toString().toUpperCase(Locale.ROOT).startsWith("CXCOMMCLI")&&p.toString().toLowerCase(Locale.ROOT).endsWith(".zip")).sorted().reduce((a,b)->b).orElse(null); }
            if(archive==null) throw new ConfigException("sapccm not found and no CXCOMMCLI*.ZIP in "+zipDir+". Download it from SAP Software Downloads.");
            System.err.println("Extracting "+archive.getFileName()+" to "+home+" ..."); Files.createDirectories(home);
            try(ZipInputStream in=new ZipInputStream(Files.newInputStream(archive))){ ZipEntry e; while((e=in.getNextEntry())!=null){Path target=home.resolve(e.getName()).normalize(); if(!target.startsWith(home.normalize()))throw new ConfigException("Unsafe path in SAP CLI archive."); if(e.isDirectory())Files.createDirectories(target);else{Files.createDirectories(target.getParent());Files.copy(in,target,StandardCopyOption.REPLACE_EXISTING);} }}
            if(!Files.isRegularFile(script))throw new ConfigException(script+" not found after extracting the archive.");
        }
        if(!win)script.toFile().setExecutable(true,true);
        return win?List.of("cmd","/c",script.toString()):List.of(script.toString());
    }

    private static final class Sap implements AutoCloseable {
        final List<String> command; final Credentials credentials; final String subscription; final boolean verbose;
        Path temp;
        Sap(List<String> c,Credentials u,String s,boolean v){command=c;credentials=u;subscription=s;verbose=v;}
        void open() throws IOException {
            temp=Files.createTempDirectory("certtool-");
            try { Files.setPosixFilePermissions(temp,EnumSet.of(PosixFilePermission.OWNER_READ,PosixFilePermission.OWNER_WRITE,PosixFilePermission.OWNER_EXECUTE)); } catch(UnsupportedOperationException ignored){}
            String content="client-id="+property(credentials.id)+"\nclient-secret="+property(credentials.secret)+"\ntoken-url="+property(credentials.tokenUrl)+"\nsubscription-code="+property(subscription)+"\n";
            for(Path dir:List.of(temp.resolve(".config/sapccm"),temp.resolve("sapccm"))){Files.createDirectories(dir);Path file=dir.resolve("config.properties");Files.writeString(file,content,StandardCharsets.ISO_8859_1,StandardOpenOption.CREATE,StandardOpenOption.TRUNCATE_EXISTING);try{Files.setPosixFilePermissions(file,EnumSet.of(PosixFilePermission.OWNER_READ,PosixFilePermission.OWNER_WRITE));}catch(UnsupportedOperationException ignored){}}
        }
        Path tempFile(String name,String content)throws IOException {Path p=temp.resolve(name);Files.writeString(p,content,StandardCharsets.UTF_8);try{Files.setPosixFilePermissions(p,EnumSet.of(PosixFilePermission.OWNER_READ,PosixFilePermission.OWNER_WRITE));}catch(UnsupportedOperationException ignored){}return p;}
        String run(List<String> args,boolean mutating)throws IOException,InterruptedException {
            if(temp==null)open(); List<String> cmd=new ArrayList<>(command);cmd.addAll(args);
            String shown="sapccm "+String.join(" ",args); if(verbose||mutating)System.out.println("  $ "+shown);
            ProcessBuilder pb=new ProcessBuilder(cmd).redirectErrorStream(true);Map<String,String> env=pb.environment();
            String opts=env.getOrDefault("JAVA_OPTS",""); opts+=(opts.isBlank()?"":" ")+"-Dlogging.level.io.netty=OFF --enable-native-access=ALL-UNNAMED";
            if(Runtime.version().feature()>=23)opts+=" --sun-misc-unsafe-memory-access=allow";
            if(System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win"))env.put("LOCALAPPDATA",temp.toString()); else opts+=" -Duser.home="+temp;
            env.put("JAVA_OPTS",opts); env.put("CERTTOOL_SAPCCM_HOME",temp.toString());
            env.put("JAVACMD",Path.of(System.getProperty("java.home"),"bin",System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win")?"java.exe":"java").toString());
            Process p=pb.start();String out=filterNoise(new String(p.getInputStream().readAllBytes(),StandardCharsets.UTF_8));int code=p.waitFor();
            if(verbose&&!out.isBlank())System.out.println(indent(out));
            if(code!=0){Set<String> paths=new HashSet<>();for(String arg:args)if(arg.startsWith("--")&&arg.endsWith(".pem")&&arg.contains("="))paths.add(arg.substring(arg.indexOf('=')+1));
                String details=out.lines().filter(line->!line.isBlank()&&!paths.contains(line.trim())).reduce((a,b)->a+"\n"+b).orElse("(no output)");if(details.matches("(?s).*(\\b401\\b|\\b403\\b|Authorization Failed).*"))details+="\nHint: check environment access and the technical user's role.";throw new SapException("sapccm "+String.join(" ",args)+" failed (exit code "+code+"):\n"+indent(details),details,code);}
            return out;
        }
        public void close(){if(temp!=null)try(var paths=Files.walk(temp)){paths.sorted(Comparator.reverseOrder()).forEach(p->{try{Files.deleteIfExists(p);}catch(IOException ignored){}});}catch(IOException ignored){}}
    }
    private static String property(String value){
        StringBuilder out=new StringBuilder();
        for(int i=0;i<value.length();i++){char ch=value.charAt(i);
            if(ch=='\\')out.append("\\\\");else if(ch=='='||ch==':'||ch=='#'||ch=='!')out.append('\\').append(ch);
            else if(ch==' '&&i==0)out.append("\\ ");else if(ch=='\n')out.append("\\n");else if(ch=='\r')out.append("\\r");else if(ch=='\t')out.append("\\t");
            else if(ch<0x20||ch>0x7e)out.append(String.format(Locale.ROOT,"\\u%04x",(int)ch));else out.append(ch);
        }
        return out.toString();
    }
    private static String filterNoise(String text){return text.lines().filter(s->!s.strip().startsWith("WARNING:")&&!s.contains("io.netty.resolver.dns.macos")).reduce((a,b)->a+"\n"+b).orElse("");}
    private static String indent(String s){return s.strip().lines().map(l->"    "+l).reduce((a,b)->a+"\n"+b).orElse("");}

    static List<Map<String,String>> parseTable(String text,String header) {
        List<String> lines=text.lines().toList(); int hi=-1;
        Pattern col=Pattern.compile("\\S+(?: \\S+)*");
        for(int i=0;i<lines.size();i++)if(lines.get(i).startsWith(header+"  ")||lines.get(i).strip().equals(header)||Arrays.stream(lines.get(i).split(" {2,}")).anyMatch(s->s.equals(header))){hi=i;break;}
        if(hi<0)return null; Matcher hm=col.matcher(lines.get(hi));List<String> names=new ArrayList<>();List<Integer> starts=new ArrayList<>();while(hm.find()){names.add(hm.group());starts.add(hm.start());}
        List<Map<String,String>> rows=new ArrayList<>();for(int i=hi+1;i<lines.size();i++){String line=lines.get(i);if(line.isBlank()){if(!rows.isEmpty())break;continue;}Map<String,String> row=new LinkedHashMap<>();for(int j=0;j<names.size();j++){int start=starts.get(j),end=j+1<starts.size()?starts.get(j+1):line.length();row.put(names.get(j),start>=line.length()?"":line.substring(start,Math.min(end,line.length())).trim());}rows.add(row);}return rows;
    }
    static Map<String,String> details(String text){List<Map<String,String>> rows=parseTable(text,"PROPERTY");Map<String,String> r=new LinkedHashMap<>();if(rows!=null)for(var row:rows)r.put(row.getOrDefault("PROPERTY",""),row.getOrDefault("VALUE",""));return r;}
    private static String run(Sap s,String...args)throws Exception{return s.run(List.of(args),false);}
    private static List<RemoteCert> remote(Sap s)throws Exception {
        String out=run(s,"certificate","list","--subscription-code="+s.subscription);List<Map<String,String>> rows=parseTable(out,"CERTIFICATE CODE");if(rows==null){if(out.contains("No certificates found")||out.isBlank())return List.of();throw new SapException("Could not interpret the output of 'certificate list':\n"+out);}
        List<RemoteCert> result=new ArrayList<>();for(var r:rows){int count;try{count=Integer.parseInt(r.getOrDefault("ENDPOINTS COUNT","0"));}catch(Exception e){count=-1;}result.add(new RemoteCert(r.getOrDefault("CERTIFICATE CODE",""),r.getOrDefault("NAME",""),r.getOrDefault("ISSUER",""),r.getOrDefault("EXPIRATION DATE",""),count));}return result;
    }
    private static Map<String,String> endpoints(Sap s,String env)throws Exception {List<Map<String,String>> rows=parseTable(run(s,"endpoint","list","--subscription-code="+s.subscription,"--environment-code="+env),"ENDPOINT CODE");Map<String,String> r=new LinkedHashMap<>();if(rows!=null)for(var row:rows){String code=row.get("ENDPOINT CODE");if(code!=null&&!code.isBlank())r.put(code,host(row.getOrDefault("URL",row.getOrDefault("DOMAIN NAME",""))));}return r;}
    private static Map<String,String> showEndpoint(Sap s,String env,String code)throws Exception{return details(run(s,"endpoint","show","--subscription-code="+s.subscription,"--environment-code="+env,"--code="+code));}
    private static String host(String value){try{String u=value.contains("://")?value:"//"+value;return Optional.ofNullable(URI.create(u).getHost()).orElse("").toLowerCase(Locale.ROOT);}catch(Exception e){return "";}}
    private static boolean sapManaged(String n){String v=n.toLowerCase(Locale.ROOT).replace('’','\'').replace('´','\'').replace('`','\'');return v.contains("let's encrypt");}
    private static List<RemoteCert> managed(Environment e,List<RemoteCert> all){String p=e.code.toLowerCase(Locale.ROOT)+"-public";return all.stream().filter(c->sapManaged(c.name)&&c.name.toLowerCase(Locale.ROOT).startsWith(p)).sorted(Comparator.comparing(RemoteCert::expiration).thenComparing(RemoteCert::name).reversed()).toList();}
    private static Target target(String name,Environment e,List<RemoteCert> all){if(name.equals(SAP_MANAGED)){List<RemoteCert> list=managed(e,all);RemoteCert first=list.isEmpty()?null:list.get(0);Set<String> accepted=new HashSet<>();list.forEach(c->{accepted.add(c.code);accepted.add(c.name);});return new Target(first==null?List.of():List.of(first),accepted,SAP_MANAGED+(first==null?"":"\n"+first.name+" ["+first.code+"]"),"no SAP-managed certificate for '"+e.code+"' found");}List<RemoteCert> list=all.stream().filter(c->c.name.equals(name)).toList();Set<String> accepted=list.size()==1?Set.of(list.get(0).code,list.get(0).name):Set.of();return new Target(list,accepted,list.size()==1?name+" ["+list.get(0).code+"]":name,"target not uploaded");}
    private static String describe(String value,List<RemoteCert> all){if(value==null||value.isBlank())return "(no certificate)";return all.stream().filter(c->c.code.equals(value)||c.name.equals(value)).findFirst().map(c->c.name+" ["+c.code+"]").orElse(value);}
    private static String domainDrift(Environment e,String endpoint,String actual){String expected=e.domains.get(endpoint);return expected==null||actual.isBlank()||expected.equals(actual)?null:"the endpoint domain in the portal is '"+actual+"', the configuration expects '"+expected+"'. Check the Cloud Portal or update the configuration.";}
    private static String effectiveDomain(Environment e,String ep,String actual){return actual.isBlank()?e.domains.getOrDefault(ep,""):actual;}
    private static boolean domainCovered(String domain,List<String> names){String d=domain.toLowerCase(Locale.ROOT).replaceAll("\\.$","");for(String n:names){if(n.equalsIgnoreCase(d))return true;if(n.startsWith("*.")&&d.contains(".")&&d.substring(d.indexOf('.')+1).equalsIgnoreCase(n.substring(2)))return true;}return false;}
    private static List<String> domains(Path cert){try{Process p=new ProcessBuilder("openssl","x509","-in",cert.toString(),"-noout","-text").start();String text=new String(p.getInputStream().readAllBytes(),StandardCharsets.UTF_8);if(p.waitFor()!=0)return List.of();Matcher m=Pattern.compile("DNS:([^\\s,]+)").matcher(text);List<String> r=new ArrayList<>();while(m.find())r.add(m.group(1).toLowerCase(Locale.ROOT));if(r.isEmpty()){m=Pattern.compile("Subject:.*?CN\\s*=\\s*([^,/\\n]+)").matcher(text);if(m.find())r.add(m.group(1).trim().toLowerCase(Locale.ROOT));}return r;}catch(Exception e){return List.of();}}
    private static String domainMismatch(Config c,String name,String domain){Certificate cert=c.certificates.get(name);if(domain.isBlank()||cert==null)return null;List<String> ns=domains(cert.certificate);return ns.isEmpty()||domainCovered(domain,ns)?null:"certificate '"+name+"' ("+String.join(", ",ns)+") does not cover endpoint domain '"+domain+"'.";}
    private static SapLease lease(Config c,Sap base,Environment env)throws IOException {
        Credentials user=credentials(c,env);if(user.id.equals(base.credentials.id))return new SapLease(base,false);
        Sap separate=new Sap(base.command,user,c.subscription,base.verbose);separate.open();return new SapLease(separate,true);
    }

    static String classify(Config c,RemoteCert x,boolean unused){
        if(sapManaged(x.name))return "SAP-managed";
        if(c.certificates.containsKey(x.name))return unused&&x.endpoints==0&&!c.protectedCert(x.code,x.name)?"configured, unused":"configured";
        if(c.protectedCert(x.code,x.name))return "protected"; return x.endpoints!=0?"in use":"deletable";
    }
    private static int upload(Config c,Sap s,Args a)throws Exception {
        List<String> names=a.certificates.isEmpty()?new ArrayList<>(c.certificates.keySet()):a.certificates;
        List<String> unknown=names.stream().filter(n->!c.certificates.containsKey(n)).toList();if(!unknown.isEmpty()){System.out.println("ERROR: Certificates not configured: "+String.join(", ",unknown));return 2;}
        if(names.isEmpty()){System.out.println("No certificates configured - nothing to do.");return 0;}
        List<RemoteCert> remote=remote(s);List<Certificate> todo=new ArrayList<>();List<String> errors=new ArrayList<>();
        heading("Upload plan"+(a.apply?"":" (preview)"));System.out.printf("%-36s %-12s %s%n","Certificate","Valid until","Action");
        for(String name:names){Certificate cert=c.certificates.get(name);List<RemoteCert> found=remote.stream().filter(x->x.name.equals(name)).toList();List<String> check=checkCertificate(cert);
            if(!found.isEmpty()){System.out.printf("%-36s %-12s skip - already uploaded [%s]%n",name,"-",String.join(", ",found.stream().map(RemoteCert::code).toList()));continue;}
            if(!check.isEmpty()){System.out.printf("%-36s %-12s BLOCKED - local check failed%n",name,"-");check.forEach(e->errors.add(name+": "+e));continue;}
            System.out.printf("%-36s %-12s %s%n",name,"-",a.apply?"upload":"would upload");todo.add(cert);
        }
        if(!a.apply){problems(errors);System.out.println(todo.size()+" certificate(s) would be uploaded"+(errors.isEmpty()?".":", "+errors.size()+" blocked.")+(todo.isEmpty()?"":" Use 'upload --apply' to upload them."));return errors.isEmpty()?0:1;}
        for(Certificate cert:todo)try {
            List<String> blocks=pemBlocks(Files.readString(cert.certificate));Path leaf=blocks.size()>1?s.tempFile("upload-certificate.pem",blocks.get(0)):cert.certificate;
            String chain=(blocks.size()>1?String.join("",blocks.subList(1,blocks.size())):"")+(Files.exists(cert.chain)?Files.readString(cert.chain):"");
            Path ca=Files.exists(cert.chain)&&blocks.size()<=1?cert.chain:s.tempFile("upload-ca-chain.pem",chain.isEmpty()?"\n":chain);
            s.run(List.of("certificate","create","--subscription-code="+s.subscription,"--name="+cert.name,"--certificate-path="+leaf,"--certificate-key-path="+cert.key,"--ca-certificate-path="+ca),true);
        }catch(Exception e){errors.add(cert.name+": upload failed\n"+e.getMessage());}
        problems(errors);System.out.println("Upload finished: "+(todo.size()-errors.size())+" certificate(s) uploaded"+(errors.isEmpty()?".":", "+errors.size()+" error(s)."));return errors.isEmpty()?0:1;
    }
    private static List<String> checkCertificate(Certificate c) {
        List<String> errors=new ArrayList<>();if(!c.name.matches("[\\x20-\\x7E]+"))errors.add("Name must contain printable ASCII only.");
        for(var entry:List.of(Map.entry("Certificate",c.certificate),Map.entry("Private Key",c.key)))if(!Files.isRegularFile(entry.getValue()))errors.add(entry.getKey()+" missing: "+entry.getValue());
        if(Files.exists(c.chain)&&!Files.isRegularFile(c.chain))errors.add("CA chain is not a file: "+c.chain);
        try {if(errors.isEmpty()){String cert=Files.readString(c.certificate),key=Files.readString(c.key);if(!cert.contains("-----BEGIN")||!key.contains("-----BEGIN"))errors.add("Certificate or key is not PEM.");if(key.contains("ENCRYPTED"))errors.add("Private key is password protected, sapccm requires an unencrypted key.");}}
        catch(IOException e){errors.add("Cannot read certificate files: "+e.getMessage());}
        if(errors.isEmpty()&&hasCommand("openssl"))try{
            String info=openssl("x509","-in",c.certificate.toString(),"-noout","-subject","-issuer","-enddate");
            if(info==null)errors.add("Certificate cannot be read: "+c.certificate);
            else {
                String subject=info.lines().filter(x->x.startsWith("subject=")).map(x->x.substring(8).trim()).findFirst().orElse("");
                String issuer=info.lines().filter(x->x.startsWith("issuer=")).map(x->x.substring(7).trim()).findFirst().orElse("");
                String notAfter=info.lines().filter(x->x.startsWith("notAfter=")).map(x->x.substring(9).trim()).findFirst().orElse("");
                if(!notAfter.isBlank())try{Instant expiry=ZonedDateTime.parse(notAfter,DateTimeFormatter.ofPattern("MMM d HH:mm:ss yyyy z",Locale.US).withZone(ZoneOffset.UTC)).toInstant();long days=Duration.between(Instant.now(),expiry).toDays();if(days<0)errors.add("Certificate has expired ("+expiry.toString().substring(0,10)+").");}catch(DateTimeException ignored){}
                String pubCert=openssl("x509","-in",c.certificate.toString(),"-noout","-pubkey");
                String pubKey=openssl("pkey","-in",c.key.toString(),"-pubout");
                if(pubKey==null)errors.add("Private key cannot be read: "+c.key);else if(pubCert!=null&&!pubCert.strip().equals(pubKey.strip()))errors.add("Private key does not match the certificate.");
                if(Files.exists(c.chain)&&openssl("x509","-in",c.chain.toString(),"-noout")==null)errors.add("CA chain cannot be read: "+c.chain);
                boolean bundled=pemBlocks(Files.readString(c.certificate)).size()>1;
                if(!Files.exists(c.chain)&&!bundled&&!subject.isBlank()&&!subject.equals(issuer))errors.add("CA chain missing: add the intermediate certificates to "+c.chain+" or append them to the certificate file (full chain, leaf first).");
            }
        }catch(Exception e){errors.add("OpenSSL check failed: "+e.getMessage());}
        else if(errors.isEmpty())System.err.println("WARNING: openssl not found - certificate contents were not checked.");
        return errors;
    }
    private static String openssl(String...args)throws IOException,InterruptedException{
        List<String> command=new ArrayList<>();command.add("openssl");command.addAll(List.of(args));
        Process p=new ProcessBuilder(command).redirectErrorStream(true).start();
        String out=new String(p.getInputStream().readAllBytes(),StandardCharsets.UTF_8);
        return p.waitFor()==0?out:null;
    }
    private static boolean hasCommand(String name){try{Process p=new ProcessBuilder(System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win")?"where":"which",name).start();return p.waitFor()==0;}catch(Exception e){return false;}}
    private static List<String> pemBlocks(String text){List<String> r=new ArrayList<>();Matcher m=PEM.matcher(text);while(m.find())r.add(m.group()+"\n");return r;}

    private static int rollout(Config c,Sap s,Environment e,Args a)throws Exception {
        Map<String,String> mapping=new LinkedHashMap<>(e.endpoints);if(!a.endpoints.isEmpty()){for(String ep:a.endpoints)if(!mapping.containsKey(ep)){System.out.println("ERROR: Endpoint '"+ep+"' not configured for environment '"+e.key+"'.");return 2;}mapping.keySet().retainAll(a.endpoints);}
        if(mapping.isEmpty()){System.out.println("No endpoints configured for environment '"+e.key+"' - nothing to do.");return 0;}
        List<RemoteCert> all=remote(s);Map<String,String> existing=endpoints(s,e.code);List<String> errors=new ArrayList<>();List<String[]> todo=new ArrayList<>();
        heading("Rollout plan - environment "+e.code+(a.apply?"":" (preview)"));System.out.printf("%-24s %-32s %-32s %s%n","Endpoint","Current certificate","Target certificate","Action");
        for(var ent:mapping.entrySet()) {String ep=ent.getKey(),name=ent.getValue();if(name.equals(UNMANAGED)){System.out.printf("%-24s %-32s %-32s skip - unmanaged%n",ep,"-",name);continue;}
            Target t=target(name,e,all);String action="",current="-";String issue=null;
            if(t.candidates.isEmpty())issue=t.missing+(name.equals(SAP_MANAGED)?"":" - run 'upload' first");else if(t.candidates.size()>1)issue="target name exists more than once";else if(!existing.containsKey(ep))issue="endpoint does not exist in '"+e.code+"'";else if((issue=domainDrift(e,ep,existing.get(ep)))==null&&(issue=domainMismatch(c,name,effectiveDomain(e,ep,existing.get(ep))))==null){
                String value=showEndpoint(s,e.code,ep).getOrDefault("SSL CERTIFICATE","");current=describe(value,all);if(t.accepted.contains(value))action="unchanged - already in place";else{action=a.apply?"switch":"would switch";todo.add(new String[]{ep,t.candidates.get(0).code});}}
            if(issue!=null){action="BLOCKED - "+issue;errors.add(ep+": "+issue);}System.out.printf("%-24s %-32s %-32s %s%n",ep,current,t.text,action);
        }
        if(a.apply)for(String[] item:todo)try{s.run(List.of("endpoint","update","--subscription-code="+s.subscription,"--environment-code="+e.code,"--code="+item[0],"--ssl-certificate="+item[1]),true);}catch(Exception ex){errors.add(item[0]+": "+ex.getMessage());}
        problems(errors);System.out.println((a.apply?"Rollout finished: ":todo.size()+" endpoint(s) would be switched.")+(a.apply?(todo.size()-errors.size())+" endpoint(s) switched"+(errors.isEmpty()?".":", "+errors.size()+" error(s)."):(errors.isEmpty()?" Use 'rollout "+e.key+" --apply' to switch them.":"")));
        return errors.isEmpty()?0:1;
    }
    private static int cleanup(Config c,Sap s,Args a)throws Exception {
        List<RemoteCert> all=remote(s),delete=new ArrayList<>();heading("Cleanup plan"+(a.includeUnused?" - including unused configured certificates":"")+(a.apply?"":" (preview)"));
        System.out.printf("%-36s %-18s %-8s %s%n","Certificate","Code","Status","Action");
        for(RemoteCert x:all){String state=classify(c,x,a.includeUnused);boolean yes=state.equals("deletable")||state.equals("configured, unused");if(yes)delete.add(x);String action=yes?(a.apply?"delete":"would delete"):state.equals("in use")?"keep - still assigned":"keep";System.out.printf("%-36s %-18s %-20s %s%n",x.name,x.code,state,action);}
        if(delete.isEmpty()){System.out.println("Cleanup finished: no deletable certificates found.");return 0;}if(!a.apply){System.out.println(delete.size()+" certificate(s) would be deleted. Use 'cleanup"+(a.includeUnused?" --include-unused":"")+" --apply' to delete them.");return 0;}
        List<String> errors=new ArrayList<>();for(RemoteCert x:delete)try{s.run(List.of("certificate","delete","--subscription-code="+s.subscription,"--certificate-code="+x.code),true);}catch(Exception e){errors.add(x.name+": "+e.getMessage());}problems(errors);return errors.isEmpty()?0:1;
    }
    private static int status(Config c,Sap s,Environment only)throws Exception {
        List<RemoteCert> all=remote(s);int issues=0;List<String> errors=new ArrayList<>();heading("Configured certificates (local)");System.out.printf("%-36s %-15s %-12s %s%n","Certificate","Local check","Valid until","Portal");
        for(Certificate cert:c.certificates.values()){List<String> check=checkCertificate(cert);List<RemoteCert> found=all.stream().filter(x->x.name.equals(cert.name)).toList();if(!check.isEmpty()){issues++;errors.add(cert.name+": "+String.join("; ",check));}System.out.printf("%-36s %-15s %-12s %s%n",cert.name,check.isEmpty()?"OK":"check failed","-",found.isEmpty()?"not uploaded":"uploaded ["+found.get(0).code+"]");}
        heading("Certificates in subscription "+c.subscription);for(RemoteCert x:all)System.out.printf("%-36s %-18s %-18s %d%n",x.name,x.code,classify(c,x,false),x.endpoints);
        Collection<Environment> envs=only==null?c.environments.values():List.of(only);
        for(Environment e:envs){heading("Environment "+e.code+(e.description.isBlank()?"":" ("+e.description+")"));SapLease lease=lease(c,s,e);try{Sap es=lease.sap;Map<String,String> live=endpoints(es,e.code);LinkedHashSet<String> codes=new LinkedHashSet<>(e.endpoints.keySet());codes.addAll(live.keySet());for(String ep:codes){String targetName=e.endpoints.get(ep),value="",state="";if(!live.containsKey(ep)){state="endpoint does not exist";issues++;}else{value=showEndpoint(es,e.code,ep).getOrDefault("SSL CERTIFICATE","");if(targetName==null)state="not configured";else{Target t=target(targetName,e,all);String drift=domainDrift(e,ep,live.get(ep));String mismatch=domainMismatch(c,targetName,effectiveDomain(e,ep,live.get(ep)));state=drift!=null?"domain differs from configuration":targetName.equals(UNMANAGED)?"unmanaged":t.candidates.isEmpty()?t.missing:t.accepted.contains(value)?"OK - target in place":mismatch!=null?"domain not covered":"rollout pending";if(drift!=null)errors.add(e.code+"/"+ep+": "+drift);if(mismatch!=null)errors.add(e.code+"/"+ep+": "+mismatch);if(!List.of("OK - target in place","unmanaged","not configured").contains(state))issues++;}}System.out.printf("  %-22s %-28s %-28s %s%n",ep,describe(value,all),targetName==null?"-":targetName,state);}}finally{if(lease.owned)lease.sap.close();}}
        problems(errors);System.out.println(issues==0?"Status: no problems found.":"Status: "+issues+" problem(s) found.");return issues==0?0:1;
    }
    private static int fetch(Config c,Sap s,Args a)throws Exception {
        List<Map<String,String>> rows=parseTable(run(s,"environment","list","--subscription-code="+s.subscription),"CODE");Map<String,String> portal=new LinkedHashMap<>();if(rows!=null)for(var r:rows)portal.put(r.get("CODE"),r.getOrDefault("NAME",""));
        List<RemoteCert> all=remote(s);JsonObject raw=c.raw.deepCopy(),envs=obj(raw,"environments");List<String> errors=new ArrayList<>();int added=0;
        for(var p:portal.entrySet()){String code=p.getKey();if(a.environment!=null&&!a.environment.equals(code)&&!a.environment.equals(c.environments.containsKey(a.environment)?c.environments.get(a.environment).code:a.environment))continue;
            Environment existing=c.environments.values().stream().filter(e->e.code.equals(code)).findFirst().orElse(null);String key=existing==null?code:existing.key;Environment forCredentials=existing==null?new Environment(key,code,p.getValue(),Map.of(),Map.of(),Map.of()):existing;SapLease lease=lease(c,s,forCredentials);try{Sap es=lease.sap;Map<String,String> live=endpoints(es,code);JsonObject target=envs.has(key)&&envs.get(key).isJsonObject()?envs.getAsJsonObject(key):new JsonObject();JsonObject configured=target.has("endpoints")&&target.get("endpoints").isJsonObject()?target.getAsJsonObject("endpoints"):new JsonObject();
            for(var ep:live.entrySet())if(!configured.has(ep.getKey())){String value=showEndpoint(es,code,ep.getKey()).getOrDefault("SSL CERTIFICATE","");RemoteCert cert=all.stream().filter(x->x.code.equals(value)||x.name.equals(value)).findFirst().orElse(null);String name=cert==null?UNMANAGED:sapManaged(cert.name)?SAP_MANAGED:c.certificates.containsKey(cert.name)?cert.name:UNMANAGED;JsonObject entry=new JsonObject();if(!ep.getValue().isBlank())entry.addProperty("domain",ep.getValue());entry.addProperty("certificate",name);if(a.apply)configured.add(ep.getKey(),entry);System.out.printf("%s / %s %s -> %s%n",key,ep.getKey(),ep.getValue(),a.apply?"added":"would add");added++;}
            if(a.apply&&existing==null&&!p.getValue().isBlank())target.addProperty("description",p.getValue());if(a.apply&&configured.size()>0)target.add("endpoints",configured);if(a.apply&&(!envs.has(key)||configured.size()>0))envs.add(key,target);
            }finally{if(lease.owned)lease.sap.close();}
        }
        if(a.apply&&added>0){raw.add("environments",envs);writeConfig(c.path,raw);}System.out.println(added+" endpoint(s) "+(a.apply?"added":"would be added")+(a.apply?" to "+c.path:". Use 'fetch --apply' to write them."));return errors.isEmpty()?0:1;
    }
    private static void writeConfig(Path path,JsonObject raw)throws IOException {
        Path tmp=Files.createTempFile(path.getParent(),"certtool-",".tmp");
        try{Files.setPosixFilePermissions(tmp,EnumSet.of(PosixFilePermission.OWNER_READ,PosixFilePermission.OWNER_WRITE));}catch(UnsupportedOperationException ignored){}
        Files.writeString(tmp,GSON.toJson(raw)+"\n",StandardCharsets.UTF_8,StandardOpenOption.TRUNCATE_EXISTING);
        try{Set<PosixFilePermission> mode=Files.getPosixFilePermissions(path);Files.setPosixFilePermissions(tmp,mode);}catch(Exception ignored){}
        try{Files.move(tmp,path,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}catch(AtomicMoveNotSupportedException e){Files.move(tmp,path,StandardCopyOption.REPLACE_EXISTING);}
    }

    private static void context(String prog,Args a,Config c,Environment env,Credentials u){
        System.out.println("SAP Commerce Cloud Certificate Exchange · certtool "+VERSION);
        System.out.println("  Command       "+a.command);System.out.println("  Mode          "+(a.command.equals("status")?"read-only":a.command.equals("cleanup")||a.command.equals("upload")||a.command.equals("rollout")||a.command.equals("fetch")?a.apply?"apply":"preview (use --apply to change)":"read-only"));
        System.out.println("  Configuration "+display(c.path));System.out.println("  Subscription  "+c.subscription);System.out.println("  Environment   "+(env==null?"- (subscription wide)":env.code));
        System.out.println("  Credentials   "+u.source+(u.expires==null?" · secret expiry not set":" · secret expires "+u.expires.toLocalDate()));System.out.println("  Java          "+System.getProperty("java.version")+" (certtool and sapccm)");System.out.println("  Runtime       "+System.getProperty("os.name")+" "+System.getProperty("os.arch"));System.out.println("  Started       "+LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
    }
    private static void warnFileMode(Path path){try{Set<PosixFilePermission> p=Files.getPosixFilePermissions(path);if(p.contains(PosixFilePermission.GROUP_READ)||p.contains(PosixFilePermission.OTHERS_READ)||p.contains(PosixFilePermission.GROUP_WRITE)||p.contains(PosixFilePermission.OTHERS_WRITE))System.err.println("WARNING: "+path.getFileName()+" contains credentials and is accessible by other users. Restrict it with chmod 600 "+path.getFileName());}catch(Exception ignored){}}
    private static String display(Path p){Path cwd=Path.of("").toAbsolutePath();return p.toAbsolutePath().normalize().startsWith(cwd)?cwd.relativize(p.toAbsolutePath().normalize()).toString():p.toString();}
    private static void heading(String s){System.out.println("\n"+s);}
    private static void problems(List<String> errors){if(!errors.isEmpty()){heading("Details");errors.forEach(e->System.out.println("  - "+e));}}
    private static void help(String prog,String cmd){System.out.println(switch(cmd){case "upload"->"Upload missing configured certificates. Usage: "+prog+" upload [--certificate NAME] [--apply]";case "rollout"->"Assign configured certificates to an environment. Usage: "+prog+" rollout <environment> [--endpoint CODE] [--apply]";case "cleanup"->"Delete unused certificates. Usage: "+prog+" cleanup [--include-unused] [--apply]";case "fetch"->"Add missing endpoints from the portal. Usage: "+prog+" fetch [environment] [--apply]";default->"Compare local and portal certificates. Usage: "+prog+" status [environment]";});}
    private static void overview(String prog){System.out.println("SAP Commerce Cloud Certificate Exchange · certtool "+VERSION+"\n\nUsage: "+prog+" <command> [options]\n\nCommands:\n  upload [--apply]                 Upload missing certificates\n  rollout <environment> [--apply]  Assign certificates to endpoints\n  cleanup [--include-unused] [--apply]  Delete unused certificates\n  status [environment]             Compare local and portal state\n  fetch [environment] [--apply]    Add missing portal endpoints\n\nRun from a project directory containing certtool.json. Changes require --apply.");}
}
