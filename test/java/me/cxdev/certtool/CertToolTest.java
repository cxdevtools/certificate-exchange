package me.cxdev.certtool;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CertToolTest {
    @Test void rolloutDomainCheckRequiresVerifiedCoverage() {
        String output = """
                CERTIFICATE CODE  c123
                NAME              local.cxdev.me
                ISSUER            Example CA
                DOMAINS           local.cxdev.me | *.example.com | shop.example.org
                EXPIRATION DATE   2027-06-01T08:00:00Z
                DESCRIPTION       Example
                """;
        List<String> names = SapCcm.parseCertificateDomains(output);
        assertEquals(List.of("local.cxdev.me", "*.example.com", "shop.example.org"), names);
        assertNull(CertificateCommands.coverageProblem("local.cxdev.me", names, "uploaded"));
        assertNull(CertificateCommands.coverageProblem("shop.example.com", names, "uploaded"));
        assertNull(CertificateCommands.coverageProblem("shop.example.org", names, "uploaded"));
        assertNotNull(CertificateCommands.coverageProblem("deep.shop.example.com", names, "uploaded"));
        assertNotNull(CertificateCommands.coverageProblem("example.com", names, "uploaded"));
        assertNotNull(CertificateCommands.coverageProblem("shop.example.com", List.of(), "uploaded"));
        assertEquals(List.of(), SapCcm.parseCertificateDomains("DOMAINS COUNT  3\nDOMAINS  \n"));
    }

    @Test void prefersLocalSapccmArchive(@TempDir Path root) throws Exception {
        Path tools = Files.createDirectories(root.resolve("tools"));
        Path local = Files.createFile(tools.resolve("CXCOMMCLI01.ZIP"));
        Path shared = Files.createDirectories(root.resolve("dependencies/sapccm"));
        Files.createFile(shared.resolve("CXCOMMCLI99.ZIP"));

        assertEquals(local, CertTool.findSapccmArchive(tools, root));
    }

    @Test void findsSapccmArchiveInNestedEnvironmentDirectory(@TempDir Path root) throws Exception {
        Path shared = Files.createDirectories(root.resolve("dependencies/sapccm-downloads/current"));
        Path archive = Files.createFile(shared.resolve("cxcommcli02.zip"));
        Path unrelated = Files.createDirectories(root.resolve("dependencies/sapartefacts"));
        Files.createFile(unrelated.resolve("CXCOMMCLI99.ZIP"));
        Files.createFile(shared.resolve("unrelated.zip"));

        assertEquals(archive.toRealPath(), CertTool.findSapccmArchive(root.resolve("tools"), root));
        assertNull(CertTool.findSapccmArchive(root.resolve("tools"), null));
    }

    @Test void parsesSapAsciiTablesWithSpacedValues() {
        String text = "CERTIFICATE CODE  NAME          ISSUER            ENDPOINTS COUNT\n"
                + "abc123            my cert name  Let's Encrypt R3  2\n";
        List<Map<String,String>> rows = SapCcm.parseTable(text, "CERTIFICATE CODE");
        assertNotNull(rows);
        assertEquals("my cert name", rows.get(0).get("NAME"));
        assertEquals("Let's Encrypt R3", rows.get(0).get("ISSUER"));
        assertEquals("2", rows.get(0).get("ENDPOINTS COUNT"));
    }

    @Test void parsesEndpointPropertyTable() {
        assertEquals("abc123", SapCcm.details("PROPERTY         VALUE\nSSL CERTIFICATE  abc123\n")
                .get("SSL CERTIFICATE"));
    }

    @Test void overviewDoesNotNeedProjectConfiguration() {
        assertEquals(0, CertTool.run(new String[0]));
    }

    @Test void configResolvesCertificatePathsFromConfigLocation() throws Exception {
        Path dir=Files.createTempDirectory("certtool-test-");
        Path config=dir.resolve("certtool.json");
        Files.writeString(config,"""
                {"subscriptionCode":"SUB","credentials":{"clientId":"id","clientSecret":"secret","tokenEndpoint":"https://example.invalid/token"},
                 "certificates":{"example":{"directory":"tls"}},"environments":{"d1":{"endpoints":{"web":"example"}}}}
                """);
        CertTool.Config loaded=CertTool.loadConfig(config.toString());
        assertEquals(dir.resolve("certificates/tls/certificate.pem"),loaded.certificates().get("example").certificate());
        assertEquals("example",loaded.environments().get("d1").endpoints().get("web"));
    }

    @Test void environmentCredentialsAreSelectedAsOneBlock() throws Exception {
        Path file=Files.createTempFile("certtool-credentials-", ".json");
        Files.writeString(file,"""
                {"subscriptionCode":"SUB","credentials":{"clientId":"subscription-id","clientSecret":"subscription-secret","tokenEndpoint":"https://example.invalid/token"},
                 "environments":{"d1":{"credentials":{"clientId":"environment-id","clientSecret":"environment-secret"}}}}
                """);
        CertTool.Config config=CertTool.loadConfig(file.toString());
        CertTool.Credentials selected=CertTool.credentials(config,config.environment("d1"));
        assertEquals("environment-id",selected.id());
        assertEquals("environments.d1.credentials",selected.source());
        assertEquals("https://example.invalid/token",selected.tokenUrl());
    }

    @Test void refusesEnvironmentSecretWithoutItsClientId() throws Exception {
        Path file=Files.createTempFile("certtool-credentials-", ".json");
        Files.writeString(file,"""
                {"subscriptionCode":"SUB","credentials":{"clientId":"subscription-id","clientSecret":"subscription-secret","tokenEndpoint":"https://example.invalid/token"},
                 "environments":{"d1":{"credentials":{"clientSecret":"environment-secret"}}}}
                """);
        CertTool.Config config=CertTool.loadConfig(file.toString());
        assertThrows(RuntimeException.class,()->CertTool.credentials(config,config.environment("d1")));
    }

    @Test void cleanupProtectionHonorsGlobAndSapManagedCertificates() throws Exception {
        Path file=Files.createTempFile("certtool-protection-", ".json");
        Files.writeString(file,"""
                {"subscriptionCode":"SUB","credentials":{"clientId":"id","clientSecret":"secret","tokenEndpoint":"https://example.invalid/token"},
                 "cleanup":{"protectedCertificates":["legacy-[ab]*"]}}
                """);
        CertTool.Config config=CertTool.loadConfig(file.toString());
        assertEquals("protected",CertTool.classify(config,new SapCcm.RemoteCert("x","legacy-a-old","issuer","",0),true));
        assertEquals("SAP-managed",CertTool.classify(config,new SapCcm.RemoteCert("y","d1-public - 2027-01-01 (Let's Encrypt)","issuer","",0),true));
    }
}
