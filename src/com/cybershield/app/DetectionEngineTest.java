package com.cybershield.app;
import com.cybershield.database.AlertDAO;
import com.cybershield.service.LogParser;
import com.cybershield.service.DetectionEngine;
import com.cybershield.model.Alert;

import java.util.List;

public class DetectionEngineTest {

    public static void main(String[] args) throws Exception {

        LogParser parser = new LogParser();

        // Parse authentication logs
        LogParser.ParseResult authResult =
                parser.parseFile("data/auth.log");

        // Parse web logs
        LogParser.ParseResult webResult =
                parser.parseFile("data/web.log");

        // Create detection engine
        DetectionEngine engine = new DetectionEngine();

        // Run all four detectors
        List<Alert> alerts = engine.runDetection(
                authResult.getEntries(),
                webResult.getEntries(),
                "data/blacklist.txt"
        );

        // Display results
        System.out.println("========== CYBERSHIELD DETECTION REPORT ==========");

        System.out.println("Authentication entries: "
                + authResult.getEntries().size());

        System.out.println("Web entries: "
                + webResult.getEntries().size());

        System.out.println("Total alerts detected: " + alerts.size());

        // Save alerts into MySQL
AlertDAO alertDAO = new AlertDAO();

int inserted = alertDAO.addBatch(alerts);

System.out.println("Alerts saved to database: " + inserted);

        System.out.println("\n========== DETECTED ALERTS ==========");

        for (Alert alert : alerts) {
            System.out.println(alert);
        }
    }
}