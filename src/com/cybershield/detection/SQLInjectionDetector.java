
package com.cybershield.detection;

import com.cybershield.model.Alert;
import com.cybershield.model.LogEntry;
import com.cybershield.model.Severity;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class SQLInjectionDetector {

    private static final String[] SQL_PATTERNS = {
        "(?i)\\bunion\\s+select\\b",
        "(?i)\\bor\\s+['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d+",
        "(?i)\\bselect\\b.{0,100}\\bfrom\\b",
        "(?i)\\bdrop\\s+table\\b",
        "(?i)(--|/\\*|\\*/)"
    };

    public List<Alert> detect(List<LogEntry> entries) {

        List<Alert> alerts = new ArrayList<>();

        for (LogEntry entry : entries) {

            String request = entry.getRequestPath();

            if (request == null || request.isEmpty()) {
                continue;
            }

            String decodedRequest = URLDecoder.decode(
                    request,
                    StandardCharsets.UTF_8
            );

            for (String sqlPattern : SQL_PATTERNS) {

                if (Pattern.compile(sqlPattern)
                        .matcher(decodedRequest)
                        .find()) {

                    Alert alert = new Alert(
                            "SQL_INJECTION",
                            Severity.CRITICAL,
                            entry.getIpAddress(),
                            entry.getUsername(),
                            "Possible SQL injection detected in request: "
                                    + request,
                            entry.getTimestamp(),
                            "web.log"
                    );

                    alerts.add(alert);
                    break;
                }
            }
        }

        return alerts;
    }
}
