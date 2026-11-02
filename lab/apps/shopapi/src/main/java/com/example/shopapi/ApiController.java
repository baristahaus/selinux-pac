package com.example.shopapi;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Paths and port come from the environment (systemd EnvironmentFile derived from
 * config/shopapi.manifest.yml). Defaults exist only so {@code java -jar} works
 * off the demo host.
 */
@RestController
public class ApiController {

    private static Path stateDir() {
        return Path.of(envOr("SHOPAPI_STATE_DIR", "/var/lib/shopapi"));
    }

    private static Path logDir() {
        return Path.of(envOr("SHOPAPI_LOG_DIR", "/var/log/shopapi"));
    }

    private static String envOr(String key, String fallback) {
        String v = System.getenv(key);
        return (v == null || v.isBlank()) ? fallback : v;
    }

    @GetMapping(value = "/health", produces = MediaType.TEXT_PLAIN_VALUE)
    public String health() {
        return "OK\n";
    }

    @GetMapping(value = "/state", produces = MediaType.TEXT_PLAIN_VALUE)
    public String state() throws IOException {
        Path dir = stateDir();
        Files.createDirectories(dir);
        Path f = dir.resolve("state.txt");
        Files.writeString(
            f,
            Instant.now().toString() + "\n",
            StandardCharsets.UTF_8,
            StandardOpenOption.CREATE,
            StandardOpenOption.APPEND
        );
        return "STATE " + f + "\n";
    }

    @GetMapping(value = "/log", produces = MediaType.TEXT_PLAIN_VALUE)
    public String log() throws IOException {
        Path dir = logDir();
        Files.createDirectories(dir);
        Path f = dir.resolve("shopapi.log");
        Files.writeString(
            f,
            Instant.now() + " probe\n",
            StandardCharsets.UTF_8,
            StandardOpenOption.CREATE,
            StandardOpenOption.APPEND
        );
        return "LOG " + f + "\n";
    }

    @GetMapping(value = "/info", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, String> info() {
        return Map.of(
            "stateDir", stateDir().toString(),
            "logDir", logDir().toString(),
            "spoolDir", spoolDir().toString(),
            "port", envOr("SHOPAPI_PORT", "8091")
        );
    }

    /**
     * First-ship policy does not label this path. After enforce it must 500 + AVC
     * until a second generate. Do not curl it during soak.
     */
    @GetMapping(value = "/feature-spool", produces = MediaType.TEXT_PLAIN_VALUE)
    public String featureSpool() throws IOException {
        Path dir = spoolDir();
        Files.createDirectories(dir);
        Path f = dir.resolve("feature.log");
        Files.writeString(
            f,
            Instant.now() + " feature\n",
            StandardCharsets.UTF_8,
            StandardOpenOption.CREATE,
            StandardOpenOption.APPEND
        );
        return "SPOOL " + f + "\n";
    }

    private static Path spoolDir() {
        return Path.of(envOr("SHOPAPI_SPOOL_DIR", "/var/spool/shopapi"));
    }
}
