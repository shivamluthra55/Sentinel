
package com.cybershield.app;

import com.cybershield.service.LogParser;
import com.cybershield.service.DetectionEngine;
import com.cybershield.database.AlertDAO;
import com.cybershield.model.Alert;
import java.util.List;

import java.util.Scanner;

public class CyberShieldApp {

    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);

        int choice;

        do {
            System.out.println("\n========================================");
            System.out.println("          CYBERSHIELD");
            System.out.println("     SECURITY MONITORING SYSTEM");
            System.out.println("========================================");

            System.out.println("1. Run Threat Detection");
            System.out.println("2. View Dashboard");
            System.out.println("3. View All Alerts");
            System.out.println("4. Search Alert by IP");
            System.out.println("5. Filter Alerts by Severity");
            System.out.println("6. Update Alert Status");
            System.out.println("7. Delete Alert");
            System.out.println("8. Exit");

            System.out.println("----------------------------------------");
            System.out.print("Enter your choice: ");

            choice = sc.nextInt();

            switch (choice) {

                case 1:
                    runThreatDetection();
                    break;

                case 2:
                    viewDashboard();
                    break;

                case 3:
                    viewAllAlerts();
                    break;

                case 4:
                    searchAlertByIP(sc);
                    break;

               case 5:
                    filterBySeverity(sc);
                    break;

                case 6:
                    updateAlertStatus(sc);
                    break;

                case 7:
                    deleteAlert(sc);
                    break;

                case 8:
                    System.out.println("Thank you for using CyberShield!");
                    break;

                default:
                    System.out.println("Invalid choice. Try again.");
            }
            

        } while (choice != 8);

        sc.close();
    }
    public static void runThreatDetection() {

    try {

        LogParser parser = new LogParser();

        LogParser.ParseResult authResult =
                parser.parseFile("data/auth.log");

        LogParser.ParseResult webResult =
                parser.parseFile("data/web.log");

        DetectionEngine engine = new DetectionEngine();

        List<Alert> alerts = engine.runDetection(
                authResult.getEntries(),
                webResult.getEntries(),
                "data/blacklist.txt"
        );

        System.out.println("\nTotal alerts detected: " + alerts.size());

        AlertDAO dao = new AlertDAO();

        int inserted = 0;
int duplicates = 0;

for (Alert alert : alerts) {

    int result = dao.addAlert(alert);

    if (result > 0) {
        inserted++;
    } else if (result == -1) {
        duplicates++;
    }
}

System.out.println("New alerts saved: " + inserted);
System.out.println("Duplicate alerts skipped: " + duplicates);

    } catch (Exception e) {

        System.out.println("Detection failed: " + e.getMessage());

    }
}
public static void viewAllAlerts() {

    try {

        AlertDAO dao = new AlertDAO();

        List<Alert> alerts = dao.getAll();

        System.out.println("\n========== ALL SECURITY ALERTS ==========");

        if (alerts.isEmpty()) {
            System.out.println("No alerts found.");
            return;
        }

        System.out.printf("%-5s %-18s %-10s %-18s %-15s%n",
                "ID", "TYPE", "SEVERITY", "IP ADDRESS", "STATUS");

        System.out.println("----------------------------------------------------------------");

        for (Alert alert : alerts) {

            System.out.printf("%-5d %-18s %-10s %-18s %-15s%n",
                    alert.getId(),
                    alert.getType(),
                    alert.getSeverity(),
                    alert.getIpAddress(),
                    alert.getStatus());
        }

        System.out.println("\nTotal alerts: " + alerts.size());

    } catch (Exception e) {

        System.out.println("Unable to retrieve alerts: " + e.getMessage());

    }
}
public static void viewDashboard() {

    try {

        AlertDAO dao = new AlertDAO();

        List<Alert> alerts = dao.getAll();

        int critical = 0;
        int high = 0;
        int medium = 0;
        int low = 0;

        int bruteForce = 0;
        int blacklisted = 0;
        int oddHour = 0;
        int sqlInjection = 0;

        for (Alert alert : alerts) {

            String severity = alert.getSeverity().name();

            if (severity.equals("CRITICAL")) {
                critical++;
            } else if (severity.equals("HIGH")) {
                high++;
            } else if (severity.equals("MEDIUM")) {
                medium++;
            } else if (severity.equals("LOW")) {
                low++;
            }

            switch (alert.getType()) {

                case "BRUTE_FORCE":
                    bruteForce++;
                    break;

                case "BLACKLISTED_IP":
                    blacklisted++;
                    break;

                case "ODD_HOUR_LOGIN":
                    oddHour++;
                    break;

                case "SQL_INJECTION":
                    sqlInjection++;
                    break;
            }
        }

        System.out.println("\n========== CYBERSHIELD DASHBOARD ==========");

        System.out.println("\nTOTAL SECURITY ALERTS: " + alerts.size());

        System.out.println("\n--- SEVERITY DISTRIBUTION ---");
        System.out.println("Critical : " + critical);
        System.out.println("High     : " + high);
        System.out.println("Medium   : " + medium);
        System.out.println("Low      : " + low);

        System.out.println("\n--- THREAT CATEGORY DISTRIBUTION ---");
        System.out.println("Brute Force       : " + bruteForce);
        System.out.println("Blacklisted IP    : " + blacklisted);
        System.out.println("Odd Hour Login    : " + oddHour);
        System.out.println("SQL Injection     : " + sqlInjection);

        System.out.println("\n===========================================");

    } catch (Exception e) {

        System.out.println("Dashboard error: " + e.getMessage());

    }
}
public static void searchAlertByIP(Scanner sc) {

    try {

        System.out.print("\nEnter IP address to search: ");
        String ip = sc.next();

        AlertDAO dao = new AlertDAO();

        List<Alert> alerts = dao.findByIp(ip);

        System.out.println("\n========== SEARCH RESULTS ==========");

        if (alerts.isEmpty()) {
            System.out.println("No alerts found for IP: " + ip);
            return;
        }

        for (Alert alert : alerts) {
            System.out.println(alert);
        }

        System.out.println("\nTotal matching alerts: " + alerts.size());

    } catch (Exception e) {

        System.out.println("Search failed: " + e.getMessage());

    }
}
public static void filterBySeverity(Scanner sc) {

    try {

        System.out.println("\n========== FILTER BY SEVERITY ==========");
        System.out.println("1. CRITICAL");
        System.out.println("2. HIGH");
        System.out.println("3. MEDIUM");
        System.out.println("4. LOW");

        System.out.print("Choose severity: ");
        int choice = sc.nextInt();

        String severityName;

        switch (choice) {
            case 1:
                severityName = "CRITICAL";
                break;
            case 2:
                severityName = "HIGH";
                break;
            case 3:
                severityName = "MEDIUM";
                break;
            case 4:
                severityName = "LOW";
                break;
            default:
                System.out.println("Invalid choice.");
                return;
        }

        AlertDAO dao = new AlertDAO();

        List<Alert> alerts = dao.findBySeverity(
                com.cybershield.model.Severity.valueOf(severityName)
        );

        System.out.println("\n========== " + severityName + " ALERTS ==========");

        if (alerts.isEmpty()) {
            System.out.println("No alerts found.");
            return;
        }

        for (Alert alert : alerts) {
            System.out.println(alert);
        }

        System.out.println("\nTotal matching alerts: " + alerts.size());

    } catch (Exception e) {

        System.out.println("Filtering failed: " + e.getMessage());

    }
}
public static void updateAlertStatus(Scanner sc) {
    try {
        System.out.println("\n========== UPDATE ALERT STATUS ==========");

        System.out.print("Enter Alert ID: ");
        int id = sc.nextInt();

        System.out.println("Choose new status:");
        System.out.println("1. NEW");
        System.out.println("2. INVESTIGATING");
        System.out.println("3. RESOLVED");
        System.out.print("Enter choice: ");

        int choice = sc.nextInt();

        String status;

        switch (choice) {
            case 1:
                status = "NEW";
                break;
            case 2:
                status = "INVESTIGATING";
                break;
            case 3:
                status = "RESOLVED";
                break;
            default:
                System.out.println("Invalid choice.");
                return;
        }

        AlertDAO dao = new AlertDAO();
        boolean result = dao.updateStatus(id, status);

        if (result) {
            System.out.println("Alert status updated successfully!");
        } else {
            System.out.println("Alert ID not found.");
        }

    } catch (Exception e) {
        System.out.println("Update failed: " + e.getMessage());
    }
}
public static void deleteAlert(Scanner sc) {
    try {
        System.out.println("\n========== DELETE ALERT ==========");

        System.out.print("Enter Alert ID to delete: ");
        int id = sc.nextInt();

        System.out.print("Are you sure you want to delete this alert? (y/n): ");
        String confirm = sc.next();

        if (!confirm.equalsIgnoreCase("y")) {
            System.out.println("Deletion cancelled.");
            return;
        }

        AlertDAO dao = new AlertDAO();
        boolean result = dao.deleteAlert(id);

        if (result) {
            System.out.println("Alert deleted successfully!");
        } else {
            System.out.println("Alert ID not found.");
        }

    } catch (Exception e) {
        System.out.println("Delete failed: " + e.getMessage());
    }
}
}

