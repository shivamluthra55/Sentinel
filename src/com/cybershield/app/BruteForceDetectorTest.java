
package com.cybershield.app;

import com.cybershield.detection.BruteForceDetector;
import com.cybershield.model.Alert;
import com.cybershield.model.LogEntry;
import com.cybershield.service.LogParser;

import java.util.List;

public class BruteForceDetectorTest {

    public static void main(String[] args) {

        LogParser parser = new LogParser();

        BruteForceDetector detector = new BruteForceDetector();

        try {

            LogParser.ParseResult result = parser.parseFile("data/auth.log");

            List<LogEntry> entries = result.getEntries();

            List<Alert> alerts = detector.detect(entries);

            System.out.println("Total log entries: " + entries.size());

            System.out.println("Brute-force alerts detected: " + alerts.size());

            for (Alert alert : alerts) {
                System.out.println(alert);
            }

        } catch (Exception e) {

            System.out.println("Error: " + e.getMessage());
        }
    }
}

