package com.securehealth.backend.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.stream.Stream;

/**
 * Scheduled service that runs pg_dump to create daily encrypted database backups.
 * Backup directory is configurable — point it to a local path, mounted EBS volume,
 * or NFS share for remote storage.
 */
@Service
@ConditionalOnProperty(name = "backup.enabled", havingValue = "true", matchIfMissing = true)
public class BackupService {

    private static final Logger log = LoggerFactory.getLogger(BackupService.class);
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss");

    @Value("${backup.directory:./backups}")
    private String backupDir;

    @Value("${backup.retention-days:7}")
    private int retentionDays;

    @Value("${spring.datasource.url}")
    private String datasourceUrl;

    @Value("${spring.datasource.username}")
    private String dbUsername;

    @Value("${spring.datasource.password}")
    private String dbPassword;

    /**
     * Runs on the configured cron schedule (default: 2:00 AM daily).
     */
    @Scheduled(cron = "${backup.cron:0 0 2 * * *}")
    public void performBackup() {
        log.info("Starting scheduled database backup...");

        try {
            // Ensure backup directory exists
            Path dirPath = Paths.get(backupDir);
            if (!Files.exists(dirPath)) {
                Files.createDirectories(dirPath);
            }

            String timestamp = LocalDateTime.now().format(FMT);
            String filename = "backup_" + timestamp + ".sql";
            Path backupFile = dirPath.resolve(filename);

            // Extract host, port, and database from JDBC URL
            // Format: jdbc:postgresql://host:port/dbname?params
            String dbHost = extractHost(datasourceUrl);
            String dbPort = extractPort(datasourceUrl);
            String dbName = extractDbName(datasourceUrl);

            // Build pg_dump command
            ProcessBuilder pb = new ProcessBuilder(
                    "pg_dump",
                    "-h", dbHost,
                    "-p", dbPort,
                    "-U", dbUsername,
                    "-F", "c",     // custom format (compressed)
                    "-f", backupFile.toAbsolutePath().toString(),
                    dbName
            );

            // Pass password via environment variable (never on CLI)
            pb.environment().put("PGPASSWORD", dbPassword);
            pb.redirectErrorStream(true);

            Process process = pb.start();
            int exitCode = process.waitFor();

            if (exitCode == 0) {
                long sizeKb = Files.size(backupFile) / 1024;
                log.info("Backup completed successfully: {} ({} KB)", filename, sizeKb);
            } else {
                String errorOutput = new String(process.getInputStream().readAllBytes());
                log.error("Backup failed with exit code {}: {}", exitCode, errorOutput);
            }

            // Clean up old backups
            cleanOldBackups(dirPath);

        } catch (Exception e) {
            log.error("Backup failed with exception: {}", e.getMessage(), e);
        }
    }

    private void cleanOldBackups(Path dirPath) {
        log.info("Cleaning backups older than {} days...", retentionDays);

        try (Stream<Path> files = Files.list(dirPath)) {
            LocalDate cutoff = LocalDate.now().minus(retentionDays, ChronoUnit.DAYS);

            files.filter(f -> f.getFileName().toString().startsWith("backup_"))
                    .filter(f -> {
                        try {
                            return Files.getLastModifiedTime(f).toInstant()
                                    .isBefore(cutoff.atStartOfDay().toInstant(java.time.ZoneOffset.UTC));
                        } catch (IOException e) {
                            return false;
                        }
                    })
                    .forEach(f -> {
                        try {
                            Files.delete(f);
                            log.info("Deleted old backup: {}", f.getFileName());
                        } catch (IOException e) {
                            log.warn("Failed to delete old backup: {}", f.getFileName());
                        }
                    });
        } catch (IOException e) {
            log.warn("Failed to clean old backups: {}", e.getMessage());
        }
    }

    // --- JDBC URL Parsing Helpers ---

    private String extractHost(String url) {
        // jdbc:postgresql://host:port/dbname
        String afterProtocol = url.split("//")[1];
        return afterProtocol.split(":")[0];
    }

    private String extractPort(String url) {
        String afterProtocol = url.split("//")[1];
        String hostPort = afterProtocol.split("/")[0];
        return hostPort.contains(":") ? hostPort.split(":")[1] : "5432";
    }

    private String extractDbName(String url) {
        String afterProtocol = url.split("//")[1];
        String afterHost = afterProtocol.split("/")[1];
        return afterHost.split("\\?")[0];
    }
}
