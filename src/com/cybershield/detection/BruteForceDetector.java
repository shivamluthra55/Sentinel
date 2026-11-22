
package com.cybershield.detection;

import com.cybershield.model.Alert;
import com.cybershield.model.LogEntry;
import com.cybershield.model.Severity;

import java.util.*;

public class BruteForceDetector {

    private static final int THRESHOLD = 5;
    private static final int TIME_WINDOW_SECONDS = 60;

    public List<Alert> detect(List<LogEntry> entries) {

        List<Alert> alerts = new ArrayList<>();

        Map<String, List<LogEntry>> attemptsByIp = new HashMap<>();

        // Group failed login attempts by IP
        for (LogEntry entry : entries) {

            if (entry.isFailedLogin()) {

                String ip = entry.getIpAddress();

                attemptsByIp.putIfAbsent(ip, new ArrayList<>());

                attemptsByIp.get(ip).add(entry);
            }
        }

        // Check each IP for brute-force attempts
        for (Map.Entry<String, List<LogEntry>> mapEntry : attemptsByIp.entrySet()) {

            String ip = mapEntry.getKey();

            List<LogEntry> attempts = mapEntry.getValue();

            attempts.sort(Comparator.comparing(LogEntry::getTimestamp));

            for (int i = 0; i <= attempts.size() - THRESHOLD; i++) {

                LogEntry first = attempts.get(i);
                LogEntry last = attempts.get(i + THRESHOLD - 1);

                long seconds = java.time.Duration.between(
                        first.getTimestamp(),
                        last.getTimestamp()
                ).getSeconds();

                if (seconds <= TIME_WINDOW_SECONDS) {

                    Alert alert = new Alert(
                            "BRUTE_FORCE",
                            Severity.HIGH,
                            ip,
                            first.getUsername(),
                            "Detected " + THRESHOLD +
                            " failed login attempts within " +
                            TIME_WINDOW_SECONDS + " seconds",
                            last.getTimestamp(),
                            "auth.log"
                    );

                    alerts.add(alert);

                    break;
                }
            }
        }

        return alerts;
    }
}
