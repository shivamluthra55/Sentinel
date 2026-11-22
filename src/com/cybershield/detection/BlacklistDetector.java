
package com.cybershield.detection;

import com.cybershield.model.Alert;
import com.cybershield.model.LogEntry;
import com.cybershield.model.Severity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public class BlacklistDetector {

    public List<Alert> detect(List<LogEntry> entries, String blacklistPath)
            throws IOException {

        Set<String> blacklistedIPs = new HashSet<>();

        List<String> lines = Files.readAllLines(Path.of(blacklistPath));

        for (String line : lines) {
            line = line.trim();

            if (!line.isEmpty() && !line.startsWith("#")) {
                blacklistedIPs.add(line);
            }
        }

        List<Alert> alerts = new ArrayList<>();

        for (LogEntry entry : entries) {

            String ip = entry.getIpAddress();

            if (blacklistedIPs.contains(ip)) {

                Alert alert = new Alert(
                        "BLACKLISTED_IP",
                        Severity.CRITICAL,
                        ip,
                        entry.getUsername(),
                        "Activity detected from blacklisted IP: " + ip,
                        entry.getTimestamp(),
                        "log file"
                );

                alerts.add(alert);
            }
        }

        return alerts;
    }
}
