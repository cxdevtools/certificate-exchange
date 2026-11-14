package me.cxdev.certtool;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.function.Consumer;
import java.util.regex.*;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import me.cxdev.certtool.CertTool.Certificate;

final class CertificateFiles {
    private static final Pattern PEM = Pattern.compile("-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", Pattern.DOTALL);

    private CertificateFiles() {}

    record CertificateCheck(String expires, List<String> errors) {}

    static List<String> dnsNames(Path path) throws IOException, CertificateException {
        X509Certificate leaf;
        try (var input = Files.newInputStream(path)) {
            leaf = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
        }
        var alternativeNames = leaf.getSubjectAlternativeNames();
        if (alternativeNames != null) {
            List<String> dns = alternativeNames.stream()
                    .filter(entry -> Integer.valueOf(2).equals(entry.getFirst()))
                    .map(entry -> (String) entry.get(1)).toList();
            if (!dns.isEmpty()) return dns;
        }
        try {
            return new LdapName(leaf.getSubjectX500Principal().getName()).getRdns().stream()
                    .filter(rdn -> rdn.getType().equalsIgnoreCase("CN"))
                    .map(Rdn::getValue).filter(String.class::isInstance).map(String.class::cast).toList();
        } catch (InvalidNameException error) {
            throw new CertificateException("Invalid certificate subject.", error);
        }
    }

    static CertificateCheck checkCertificate(Certificate c, Consumer<String> warning) {
        String expires = "";
        List<String> errors=new ArrayList<>();if(!c.name().matches("[\\x20-\\x7E]+"))errors.add("Name must contain printable ASCII only.");
        for(var entry:List.of(Map.entry("Certificate",c.certificate()),Map.entry("Private Key",c.key())))if(!Files.isRegularFile(entry.getValue()))errors.add(entry.getKey()+" missing: "+entry.getValue());
        if(Files.exists(c.chain())&&!Files.isRegularFile(c.chain()))errors.add("CA chain is not a file: "+c.chain());
        try {if(errors.isEmpty()){String cert=Files.readString(c.certificate()),key=Files.readString(c.key());if(!cert.contains("-----BEGIN")||!key.contains("-----BEGIN"))errors.add("Certificate or key is not PEM.");if(key.contains("ENCRYPTED"))errors.add("Private key is password protected, sapccm requires an unencrypted key.");}}
        catch(IOException e){errors.add("Cannot read certificate files: "+e.getMessage());}
        if(errors.isEmpty()&&hasCommand("openssl"))try{
            String info=openssl("x509","-in",c.certificate().toString(),"-noout","-subject","-issuer","-enddate");
            if(info==null)errors.add("Certificate cannot be read: "+c.certificate());
            else {
                String subject=info.lines().filter(x->x.startsWith("subject=")).map(x->x.substring(8).trim()).findFirst().orElse("");
                String issuer=info.lines().filter(x->x.startsWith("issuer=")).map(x->x.substring(7).trim()).findFirst().orElse("");
                String notAfter=info.lines().filter(x->x.startsWith("notAfter=")).map(x->x.substring(9).trim()).findFirst().orElse("");
                if(!notAfter.isBlank())try{Instant expiry=ZonedDateTime.parse(notAfter,DateTimeFormatter.ofPattern("MMM d HH:mm:ss yyyy z",Locale.US).withZone(ZoneOffset.UTC)).toInstant();expires = expiry.toString().substring(0,10);if(Instant.now().isAfter(expiry))errors.add("Certificate has expired ("+expiry.toString().substring(0,10)+").");}catch(DateTimeException ignored){}
                String pubCert=openssl("x509","-in",c.certificate().toString(),"-noout","-pubkey");
                String pubKey=openssl("pkey","-in",c.key().toString(),"-pubout");
                if(pubKey==null)errors.add("Private key cannot be read: "+c.key());else if(pubCert!=null&&!pubCert.strip().equals(pubKey.strip()))errors.add("Private key does not match the certificate.");
                if(Files.exists(c.chain())&&openssl("x509","-in",c.chain().toString(),"-noout")==null)errors.add("CA chain cannot be read: "+c.chain());
                boolean bundled=pemBlocks(Files.readString(c.certificate())).size()>1;
                if(!Files.exists(c.chain())&&!bundled&&!subject.isBlank()&&!subject.equals(issuer))errors.add("CA chain missing: add the intermediate certificates to "+c.chain()+" or append them to the certificate file (full chain, leaf first).");
            }
        }catch(Exception e){errors.add("OpenSSL check failed: "+e.getMessage());}
        else if(errors.isEmpty())warning.accept("WARNING: openssl not found - certificate contents were not checked.");
        return new CertificateCheck(expires, errors);
    }
    private static String openssl(String...args)throws IOException,InterruptedException{
        List<String> command=new ArrayList<>();command.add("openssl");command.addAll(List.of(args));
        Process p=new ProcessBuilder(command).redirectErrorStream(true).start();
        String out=new String(p.getInputStream().readAllBytes(),StandardCharsets.UTF_8);
        return p.waitFor()==0?out:null;
    }
    private static boolean hasCommand(String name){try{Process p=new ProcessBuilder(System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win")?"where":"which",name).start();return p.waitFor()==0;}catch(Exception e){return false;}}
    static List<String> pemBlocks(String text){List<String> r=new ArrayList<>();Matcher m=PEM.matcher(text);while(m.find())r.add(m.group()+"\n");return r;}

}
