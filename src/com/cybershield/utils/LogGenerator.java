
package com.cybershield.utils;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import com.cybershield.database.DBConnection;
import com.cybershield.exception.DatabaseException;
import com.cybershield.model.Alert;

public class LogGenerator {

    private static final DateTimeFormatter FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final LocalDateTime BASE_DATE =
            LocalDateTime.of(2026, 11, 13, 10, 0, 0);

    public static void generateAll() throws IOException {

        // Create data folder
        Files.createDirectories(Path.of("data"));

        generateAuthLog();
        generateWebLog();
        generateBlacklist();

        System.out.println("All sample log files generated successfully!");
    }

    // Generates authentication logs
    private static void generateAuthLog() throws IOException {

        Random random = new Random(42);

        try (BufferedWriter writer =
                     Files.newBufferedWriter(Path.of("data/auth.log"))) {

            writer.write("# CyberShield Authentication Logs");
            writer.newLine();

            // Normal login activities
            String[] users = {"shivam", "rahul", "admin", "guest"};

            for (int i = 0; i < 4; i++) {

                String timestamp = BASE_DATE.plusMinutes(i).format(FORMAT);
                String ip = "192.168.1." + (10 + random.nextInt(100));

                writeLine(writer, timestamp, ip, users[i],
                        "LOGIN", "SUCCESS", "-");
            }

            // Brute-force simulation: 12 failed logins within 33 seconds
            for (int i = 0; i < 12; i++) {

                String timestamp = BASE_DATE.plusHours(1)
                        .plusSeconds(i * 3L).format(FORMAT);

                writeLine(writer, timestamp, "203.0.113.50",
                        "admin", "LOGIN", "FAILED", "-");
            }

            // Odd-hour login: admin
            writeLine(writer, "2026-11-13 03:12:44",
                    "192.168.1.20", "admin",
                    "LOGIN", "SUCCESS", "-");

            // Odd-hour login: root
            writeLine(writer, "2026-11-13 02:47:10",
                    "10.0.0.99", "root",
                    "LOGIN", "SUCCESS", "-");

            // Blacklisted IP activity
            writeLine(writer, "2026-11-13 14:30:00",
                    "45.33.32.156", "unknown",
                    "LOGIN", "FAILED", "-");

            // Three malformed lines
            writer.write("2026-11-13 15:00:00,203.0.113.10,admin,LOGIN");
            writer.newLine();

            writer.write("invalid-timestamp,203.0.113.11,admin,LOGIN,SUCCESS,-");
            writer.newLine();

            writer.write("2026-11-13 15:02:00,not-an-ip,admin,LOGIN,SUCCESS,-");
            writer.newLine();
        }
    }

    // Generates web server logs
    private static void generateWebLog() throws IOException {

        try (BufferedWriter writer =
                     Files.newBufferedWriter(Path.of("data/web.log"))) {

            writer.write("# CyberShield Web Server Logs");
            writer.newLine();

            // Normal web requests
            writeLine(writer, "2026-11-13 16:00:00",
                    "192.168.1.15", "-", "GET", "200", "/home");

            writeLine(writer, "2026-11-13 16:01:00",
                    "192.168.1.16", "-", "GET", "200", "/about");

            writeLine(writer, "2026-11-13 16:02:00",
                    "192.168.1.17", "-", "POST", "201", "/register");

            // Five SQL injection test requests
            String[] suspiciousPaths = {
                    "/login?user=admin' OR '1'='1",
                    "/search?q=UNION SELECT username,password",
                    "/admin?cmd=DROP TABLE users",
                    "/login?user=admin'--",
                    "/search?q=1%20OR%201=1"
            };

            for (int i = 0; i < suspiciousPaths.length; i++) {

                String timestamp = BASE_DATE.plusHours(6)
                        .plusMinutes(i).format(FORMAT);

                writeLine(writer, timestamp, "198.51.100.23",
                        "-", "GET", "500", suspiciousPaths[i]);
            }

            // Blacklisted IP activity
            writeLine(writer, "2026-11-13 16:30:00",
                    "45.33.32.156", "-", "GET", "403", "/admin");

            // Two malformed lines
            writer.write("2026-11-13 17:00:00,198.51.100.10,-,GET,200");
            writer.newLine();

            writer.write("wrong-date,198.51.100.11,-,GET,500,/login");
            writer.newLine();
        }
    }

    // Generates blacklist file
    private static void generateBlacklist() throws IOException {

        try (BufferedWriter writer =
                     Files.newBufferedWriter(Path.of("data/blacklist.txt"))) {

            writer.write("# Known suspicious IP addresses");
            writer.newLine();

            writer.write("45.33.32.156");
            writer.newLine();

            writer.write("185.220.101.4");
            writer.newLine();
        }
    }

    // Helper method to write one formatted log entry
    private static void writeLine(
            BufferedWriter writer,
            String timestamp,
            String ip,
            String username,
            String action,
            String status,
            String requestPath) throws IOException {

        writer.write(timestamp + "," + ip + "," + username + ","
                + action + "," + status + "," + requestPath);

        writer.newLine();
    }

}

