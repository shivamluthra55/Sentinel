package com.cybershield.app;

import com.cybershield.database.AlertDAO;
import com.cybershield.model.Alert;
import com.cybershield.model.Severity;
import com.cybershield.exception.DatabaseException;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

public class AlertDAOTest {

    public static void main(String[] args) {

        AlertDAO dao = new AlertDAO();

        List<Alert> alerts = new ArrayList<>();

        alerts.add(new Alert(
                "BRUTE_FORCE",
                Severity.CRITICAL,
                "203.0.113.60",
                "admin",
                "Multiple failed login attempts",
                LocalDateTime.now(),
                "auth.log"
        ));

        alerts.add(new Alert(
                "SQL_INJECTION",
                Severity.HIGH,
                "198.51.100.30",
                "unknown",
                "SQL injection pattern detected",
                LocalDateTime.now().plusSeconds(1),
                "web.log"
        ));

        alerts.add(new Alert(
                "BLACKLISTED_IP",
                Severity.MEDIUM,
                "45.33.32.100",
                "unknown",
                "Blacklisted IP detected",
                LocalDateTime.now().plusSeconds(2),
                "auth.log"
        ));

        try {

            int inserted = dao.addBatch(alerts);

            System.out.println("Batch insertion completed!");
            System.out.println("Total alerts inserted: " + inserted);

        } catch (DatabaseException e) {

            System.out.println("Batch insertion failed!");
            System.out.println(e.getMessage());
        }
    }
}