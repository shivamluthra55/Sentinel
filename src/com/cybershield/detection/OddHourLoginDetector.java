
package com.cybershield.detection;

import com.cybershield.model.Alert;
import com.cybershield.model.LogEntry;
import com.cybershield.model.Severity;

import java.util.ArrayList;
import java.util.List;

public class OddHourLoginDetector {

    private static final int START_HOUR = 0;
    private static final int END_HOUR = 5;

    public List<Alert> detect(List<LogEntry> entries) {

        List<Alert> alerts = new ArrayList<>();

        for (LogEntry entry : entries) {

            // Check whether the entry is a successful login
            if (entry.isLogin() && "SUCCESS".equalsIgnoreCase(entry.getStatus())) {

                String username = entry.getUsername();

                // Check whether the user is admin or root
                if ("admin".equalsIgnoreCase(username)
                        || "root".equalsIgnoreCase(username)) {

                    int hour = entry.getTimestamp().getHour();

                    // Check whether login happened between midnight and 5 AM
                    if (hour >= START_HOUR && hour < END_HOUR) {

                        Alert alert = new Alert(
                                "ODD_HOUR_LOGIN",
                                Severity.HIGH,
                                entry.getIpAddress(),
                                username,
                                "Admin/root login detected at unusual hour: "
                                        + entry.getTimestamp(),
                                entry.getTimestamp(),
                                "auth.log"
                        );

                        alerts.add(alert);
                    }
                }
            }
        }

        return alerts;
    }
}
