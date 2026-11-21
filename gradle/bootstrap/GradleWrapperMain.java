package org.gradle.wrapper;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Properties;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Source-built bootstrap for the checksum-pinned Gradle distribution. */
public final class GradleWrapperMain {
    private GradleWrapperMain() {}

    public static void main(String[] arguments) throws Exception {
        if (Runtime.version().feature() < 17) throw new IllegalStateException("Use Android Studio's JDK 17 or newer.");
        Path jar = Path.of(GradleWrapperMain.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        Path propertiesPath = jar.getParent().resolve("gradle-wrapper.properties");
        Properties properties = new Properties();
        try (InputStream in = Files.newInputStream(propertiesPath)) { properties.load(in); }
        String source = properties.getProperty("distributionUrl");
        String expected = properties.getProperty("distributionSha256Sum", "").toLowerCase(java.util.Locale.ROOT);
        if (source == null || !expected.matches("[a-f0-9]{64}")) throw new IOException("Gradle URL or SHA-256 is missing.");
        String home = System.getProperty("gradle.user.home", System.getenv("GRADLE_USER_HOME"));
        if (home == null || home.isBlank()) home = Path.of(System.getProperty("user.home"), ".gradle").toString();
        for (int i = 0; i + 1 < arguments.length; i++) if (arguments[i].equals("-g") || arguments[i].equals("--gradle-user-home")) home = arguments[i + 1];
        Path cache = Path.of(home, "wrapper", "dists", "dexpack-8.11.1", expected.substring(0, 16));
        Files.createDirectories(cache);
        boolean windows = System.getProperty("os.name").toLowerCase(java.util.Locale.ROOT).contains("win");
        Path install = cache.resolve("distribution"), marker = cache.resolve("verified.sha256");
        Path executable = install.resolve("gradle-8.11.1/bin/" + (windows ? "gradle.bat" : "gradle"));
        try (FileChannel channel = FileChannel.open(cache.resolve("install.lock"), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
             FileLock lock = channel.lock()) {
            if (!Files.isRegularFile(executable) || !Files.isRegularFile(marker) || !Files.readString(marker).equals(expected)) {
                if (Arrays.asList(arguments).contains("--offline")) throw new IOException("Gradle 8.11.1 is not cached. Run Gradle Sync once with internet access.");
                Path archive = cache.resolve("distribution.zip.part");
                Path temporary = cache.resolve("extracting");
                try {
                    System.out.println("Downloading Gradle 8.11.1…");
                    download(URI.create(source), archive, Integer.parseInt(properties.getProperty("networkTimeout", "60000")));
                    String actual = digest(archive);
                    if (!MessageDigest.isEqual(actual.getBytes(java.nio.charset.StandardCharsets.US_ASCII), expected.getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
                        throw new IOException("Gradle SHA-256 verification failed.");
                    }
                    removeTree(temporary); Files.createDirectories(temporary); extract(archive, temporary);
                    Path candidate = temporary.resolve("gradle-8.11.1/bin/" + (windows ? "gradle.bat" : "gradle"));
                    if (!Files.isRegularFile(candidate)) throw new IOException("Gradle distribution has no launcher.");
                    if (!windows && !candidate.toFile().setExecutable(true, false)) throw new IOException("Cannot make Gradle executable.");
                    removeTree(install); Files.move(temporary, install, StandardCopyOption.ATOMIC_MOVE);
                    Files.writeString(marker, expected);
                } finally { Files.deleteIfExists(archive); removeTree(temporary); }
            }
        }
        List<String> command = new ArrayList<>();
        if (windows) { command.add("cmd.exe"); command.add("/d"); command.add("/c"); }
        command.add(executable.toString()); command.addAll(Arrays.asList(arguments));
        Process process = new ProcessBuilder(command).inheritIO().start();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> { if (process.isAlive()) process.destroy(); }));
        System.exit(process.waitFor());
    }

    static String digest(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256"); byte[] buffer = new byte[1024 * 1024];
        try (InputStream in = Files.newInputStream(path)) { for (int count; (count = in.read(buffer)) >= 0;) if (count > 0) digest.update(buffer, 0, count); }
        return java.util.HexFormat.of().formatHex(digest.digest());
    }

    static void download(URI uri, Path destination, int timeout) throws Exception {
        if (uri.getScheme().equals("file")) { Files.copy(Path.of(uri), destination, StandardCopyOption.REPLACE_EXISTING); return; }
        for (int redirects = 0; redirects < 10; redirects++) {
            if (!"https".equalsIgnoreCase(uri.getScheme())) throw new IOException("Gradle download requires HTTPS.");
            HttpURLConnection connection = (HttpURLConnection) new URL(uri.toString()).openConnection();
            connection.setConnectTimeout(timeout); connection.setReadTimeout(timeout); connection.setInstanceFollowRedirects(false);
            try {
                int code = connection.getResponseCode();
                if (code >= 300 && code < 400) { String location = connection.getHeaderField("Location"); if (location == null) throw new IOException("Invalid download redirect."); uri = uri.resolve(location); continue; }
                if (code != 200) throw new IOException("Gradle download returned HTTP " + code);
                try (InputStream in = connection.getInputStream()) { Files.copy(in, destination, StandardCopyOption.REPLACE_EXISTING); }
                return;
            } finally { connection.disconnect(); }
        }
        throw new IOException("Too many Gradle download redirects.");
    }

    static void extract(Path archive, Path destination) throws IOException {
        Path root = destination.toAbsolutePath().normalize();
        try (ZipInputStream zip = new ZipInputStream(Files.newInputStream(archive))) {
            for (ZipEntry entry; (entry = zip.getNextEntry()) != null;) {
                Path target = root.resolve(entry.getName()).normalize();
                if (!target.startsWith(root)) throw new IOException("Unsafe path in Gradle distribution.");
                if (entry.isDirectory()) Files.createDirectories(target);
                else { Files.createDirectories(target.getParent()); Files.copy(zip, target); }
                zip.closeEntry();
            }
        }
    }

    static void removeTree(Path path) throws IOException {
        if (!Files.exists(path)) return;
        try (java.util.stream.Stream<Path> files = Files.walk(path)) {
            for (Path file : files.sorted(Comparator.reverseOrder()).toList()) Files.delete(file);
        }
    }
}
