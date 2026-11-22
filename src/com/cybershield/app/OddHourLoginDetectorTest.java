
package com.cybershield.app;

import com.cybershield.detection.OddHourLoginDetector;
import com.cybershield.model.Alert;
import com.cybershield.model.LogEntry;
import com.cybershield.service.LogParser;

import java.util.List;

public class OddHourLoginDetectorTest {

    public static void main(String[] args) {

        LogParser parser = new LogParser();

        OddHourLoginDetector detector = new OddHourLoginDetector();

        try {

            // Read authentication logs
            LogParser.ParseResult result =
                    parser.parseFile("data/auth.log");

            List<LogEntry> entries = result.getEntries();

            // Detect unusual login times
            List<Alert> alerts = detector.detect(entries);

            System.out.println("========== ODD HOUR LOGIN DETECTOR ==========");

            System.out.println("Total log entries: " + entries.size());

            System.out.println("Odd-hour alerts detected: " + alerts.size());

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
