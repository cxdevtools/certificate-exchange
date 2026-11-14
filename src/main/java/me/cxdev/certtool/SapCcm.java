package me.cxdev.certtool;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.*;

import static me.cxdev.certtool.CertTool.*;

final class SapCcm {
    static final int MAX_LOCK_ATTEMPTS = 20;
    private static final int LOCK_RETRY_DELAY_SECONDS = 15;
    private static final Pattern ENVIRONMENT_LOCK = Pattern.compile(
            "This environment cannot be edited because another process is modifying it\\.\\s+"
                    + "Please wait and try again later\\."
                    + "(?:\\s+Process ID:\\s*([0-9a-fA-F-]{36}))?");

    private SapCcm() {}

    @FunctionalInterface
    interface SapCall {
        String execute() throws IOException, InterruptedException;
    }

    @FunctionalInterface
    interface RetryWait {
        void waitSeconds(int seconds) throws InterruptedException;
    }

    static String runWithLockRetry(SapCall call, RetryWait wait, ConsolePrinter printer)
            throws IOException, InterruptedException {
        try {
            for (int attempt = 1; ; attempt++) {
                try {
                    return call.execute();
                } catch (SapException error) {
                    Matcher lock = ENVIRONMENT_LOCK.matcher(error.output);
                    if (!Objects.equals(error.code, 10) || !lock.find()) throw error;
                    if (attempt == MAX_LOCK_ATTEMPTS) {
                        printer.retryLimitReached(MAX_LOCK_ATTEMPTS);
                        throw error;
                    }
                    printer.retrying(attempt + 1, MAX_LOCK_ATTEMPTS, LOCK_RETRY_DELAY_SECONDS, lock.group(1));
                    wait.waitSeconds(LOCK_RETRY_DELAY_SECONDS);
                    printer.retryStarted(attempt + 1, MAX_LOCK_ATTEMPTS);
                }
            }
        } finally {
            printer.clearRetry();
        }
    }

    record SapLease(Sap sap, boolean owned) implements AutoCloseable {
        @Override
        public void close() {
            if (owned) sap.close();
        }
    }
    record RemoteCert(String code, String name, String issuer, String expiration, int endpoints) {}
    static final class SapException extends RuntimeException {
        final String output; final Integer code;
        SapException(String message) { super(message); output = ""; code = null; }
        SapException(String message, String out, int exit) { super(message); output = out; code = exit; }
        String summary() { return code == null ? getMessage() : "sapccm exit code " + code + (output.isBlank() ? "" : "\n" + output); }
    }

    static final class Sap implements AutoCloseable {
        final List<String> command; final Credentials credentials; final String subscription; final boolean verbose;
        private final ConsolePrinter printer;
        Path temp;
        Sap(List<String> command, Credentials credentials, String subscription, boolean verbose, ConsolePrinter printer) {
            this.command = command;
            this.credentials = credentials;
            this.subscription = subscription;
            this.verbose = verbose;
            this.printer = printer;
        }
        void open() throws IOException {
            temp=Files.createTempDirectory("certtool-");
            try { Files.setPosixFilePermissions(temp,EnumSet.of(PosixFilePermission.OWNER_READ,PosixFilePermission.OWNER_WRITE,PosixFilePermission.OWNER_EXECUTE)); } catch(UnsupportedOperationException ignored){}
            String content="client-id="+property(credentials.id())+"\nclient-secret="+property(credentials.secret())+"\ntoken-url="+property(credentials.tokenUrl())+"\nsubscription-code="+property(subscription)+"\n";
            for(Path dir:List.of(temp.resolve(".config/sapccm"),temp.resolve("sapccm"))){Files.createDirectories(dir);Path file=dir.resolve("config.properties");Files.writeString(file,content,StandardCharsets.ISO_8859_1,StandardOpenOption.CREATE,StandardOpenOption.TRUNCATE_EXISTING);try{Files.setPosixFilePermissions(file,EnumSet.of(PosixFilePermission.OWNER_READ,PosixFilePermission.OWNER_WRITE));}catch(UnsupportedOperationException ignored){}}
        }
        Path tempFile(String name,String content)throws IOException {Path p=temp.resolve(name);Files.writeString(p,content,StandardCharsets.UTF_8);try{Files.setPosixFilePermissions(p,EnumSet.of(PosixFilePermission.OWNER_READ,PosixFilePermission.OWNER_WRITE));}catch(UnsupportedOperationException ignored){}return p;}
        String run(List<String> args,boolean mutating)throws IOException,InterruptedException {
            if (!mutating) printer.loadingSapCall(args);
            if (verbose || mutating) printer.sapCall(args);
            if (!mutating) return runOnce(args);
            try {
                String output = runWithLockRetry(() -> runOnce(args), TimeUnit.SECONDS::sleep, printer);
                printer.stepResult(true);
                return output;
            } catch (SapException | IOException error) {
                printer.stepResult(false);
                throw error;
            }
        }

        private String runOnce(List<String> args) throws IOException, InterruptedException {
            if(temp==null)open(); List<String> cmd=new ArrayList<>(command);cmd.addAll(args);
            ProcessBuilder pb=new ProcessBuilder(cmd).redirectErrorStream(true);Map<String,String> env=pb.environment();
            String opts=env.getOrDefault("JAVA_OPTS",""); opts+=(opts.isBlank()?"":" ")+"-Dlogging.level.io.netty=OFF --enable-native-access=ALL-UNNAMED";
            if(Runtime.version().feature()>=23)opts+=" --sun-misc-unsafe-memory-access=allow";
            if(System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win"))env.put("LOCALAPPDATA",temp.toString()); else opts+=" -Duser.home="+temp;
            env.put("JAVA_OPTS",opts); env.put("CERTTOOL_SAPCCM_HOME",temp.toString());
            env.put("JAVACMD",Path.of(System.getProperty("java.home"),"bin",System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win")?"java.exe":"java").toString());
            Process p=pb.start();String out=filterNoise(new String(p.getInputStream().readAllBytes(),StandardCharsets.UTF_8));int code=p.waitFor();
            if(verbose&&!out.isBlank())printer.sapOutput(out);
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
    static String run(Sap s,String...args)throws Exception{return s.run(List.of(args),false);}
    static List<RemoteCert> remote(Sap s)throws Exception {
        String out=run(s,"certificate","list","--subscription-code="+s.subscription);List<Map<String,String>> rows=parseTable(out,"CERTIFICATE CODE");if(rows==null){if(out.contains("No certificates found")||out.isBlank())return List.of();throw new SapException("Could not interpret the output of 'certificate list':\n"+out);}
        List<RemoteCert> result=new ArrayList<>();for(var r:rows){int count;try{count=Integer.parseInt(r.getOrDefault("ENDPOINTS COUNT",""));}catch(Exception e){count=-1;}result.add(new RemoteCert(r.getOrDefault("CERTIFICATE CODE",""),r.getOrDefault("NAME",""),r.getOrDefault("ISSUER",""),r.getOrDefault("EXPIRATION DATE",""),count));}return result;
    }
    static Map<String,String> endpoints(Sap s,String env)throws Exception {List<Map<String,String>> rows=parseTable(run(s,"endpoint","list","--subscription-code="+s.subscription,"--environment-code="+env),"ENDPOINT CODE");Map<String,String> r=new LinkedHashMap<>();if(rows!=null)for(var row:rows){String code=row.get("ENDPOINT CODE");if(code!=null&&!code.isBlank())r.put(code,host(row.getOrDefault("URL",row.getOrDefault("DOMAIN NAME",""))));}return r;}
    static Map<String,String> showEndpoint(Sap s,String env,String code)throws Exception{return details(run(s,"endpoint","show","--subscription-code="+s.subscription,"--environment-code="+env,"--code="+code));}
    static List<String> certificateDomains(Sap sap, String code) throws IOException, InterruptedException {
        String output = sap.run(List.of("certificate", "show", "--subscription-code=" + sap.subscription,
                "--certificate-code=" + code), false);
        return parseCertificateDomains(output);
    }

    static List<String> parseCertificateDomains(String output) {
        // Unlike endpoint show, certificate show prints key/value rows without a header.
        return output.lines()
                .map(String::strip)
                .filter(line -> line.matches("DOMAINS(?:[ \\t]{2,}.*)?"))
                .findFirst().stream()
                .flatMap(line -> Arrays.stream(line.substring("DOMAINS".length()).split("\\|")))
                .map(String::strip)
                .filter(name -> !name.isEmpty())
                .toList();
    }
    private static String host(String value){try{String u=value.contains("://")?value:"//"+value;return Optional.ofNullable(URI.create(u).getHost()).orElse("").toLowerCase(Locale.ROOT);}catch(Exception e){return "";}}
    static SapLease lease(Config c,Sap base,Environment env)throws IOException {
        Credentials user=credentials(c,env,base.printer::warning);if(user.id().equals(base.credentials.id()))return new SapLease(base,false);
        Sap separate=new Sap(base.command,user,c.subscription(),base.verbose,base.printer);
        return new SapLease(separate,true);
    }

}
