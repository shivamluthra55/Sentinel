
package com.cybershield.app;

import com.cybershield.detection.BlacklistDetector;
import com.cybershield.model.Alert;
import com.cybershield.model.LogEntry;
import com.cybershield.service.LogParser;

import java.util.ArrayList;
import java.util.List;

public class BlacklistDetectorTest {

    public static void main(String[] args) {

        LogParser parser = new LogParser();

        BlacklistDetector detector = new BlacklistDetector();

        try {

            // Read authentication logs
            LogParser.ParseResult authResult =
                    parser.parseFile("data/auth.log");

            // Read web server logs
            LogParser.ParseResult webResult =
                    parser.parseFile("data/web.log");

            // Combine both log entries
            List<LogEntry> entries = new ArrayList<>();

            entries.addAll(authResult.getEntries());
            entries.addAll(webResult.getEntries());

            // Detect blacklisted IP addresses
            List<Alert> alerts = detector.detect(
                    entries,
                    "data/blacklist.txt"
            );

            // Display results
            System.out.println("========== BLACKLIST DETECTOR ==========");

            System.out.println("Total log entries: " + entries.size());

            System.out.println(
                    "Blacklisted IP alerts detected: " + alerts.size()
            );

            for (Alert alert : alerts) {
                System.out.println(alert);
            }

            System.out.println("========== TEST COMPLETED ==========");

        } catch (Exception e) {

            System.out.println("Error: " + e.getMessage());

            e.printStackTrace();
        }
    }
}
