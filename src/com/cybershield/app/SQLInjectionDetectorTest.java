
package com.cybershield.app;

import com.cybershield.detection.SQLInjectionDetector;
import com.cybershield.model.Alert;
import com.cybershield.model.LogEntry;
import com.cybershield.service.LogParser;

import java.util.List;

public class SQLInjectionDetectorTest {

    public static void main(String[] args) {

        LogParser parser = new LogParser();

        SQLInjectionDetector detector = new SQLInjectionDetector();

        try {

            // Read web server logs
            LogParser.ParseResult result =
                    parser.parseFile("data/web.log");

            List<LogEntry> entries = result.getEntries();

            // Detect SQL injection attempts
            List<Alert> alerts = detector.detect(entries);

            System.out.println("========== SQL INJECTION DETECTOR ==========");

            System.out.println("Total web log entries: " + entries.size());

            System.out.println(
                    "SQL injection alerts detected: " + alerts.size()
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
