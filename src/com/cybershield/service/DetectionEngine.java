package com.cybershield.service;

import com.cybershield.detection.BruteForceDetector;
import com.cybershield.detection.BlacklistDetector;
import com.cybershield.detection.OddHourLoginDetector;
import com.cybershield.detection.SQLInjectionDetector;

import com.cybershield.model.Alert;
import com.cybershield.model.LogEntry;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class DetectionEngine {

    private BruteForceDetector bruteForceDetector;
    private BlacklistDetector blacklistDetector;
    private OddHourLoginDetector oddHourLoginDetector;
    private SQLInjectionDetector sqlInjectionDetector;

    public DetectionEngine() {

    bruteForceDetector = new BruteForceDetector();

    blacklistDetector = new BlacklistDetector();

    oddHourLoginDetector = new OddHourLoginDetector();

    sqlInjectionDetector = new SQLInjectionDetector();
    
    
}
public List<Alert> runDetection(
        List<LogEntry> authEntries,
        List<LogEntry> webEntries,
        String blacklistPath) throws IOException {

    List<Alert> allAlerts = new ArrayList<>();

    // 1. Brute-force detection
    allAlerts.addAll(
            bruteForceDetector.detect(authEntries)
    );

    // 2. Blacklisted IP detection
    allAlerts.addAll(
            blacklistDetector.detect(
                    combineEntries(authEntries, webEntries),
                    blacklistPath
            )
    );

    // 3. Odd-hour login detection
    allAlerts.addAll(
            oddHourLoginDetector.detect(authEntries)
    );

    // 4. SQL injection detection
    allAlerts.addAll(
            sqlInjectionDetector.detect(webEntries)
    );

    return allAlerts;
    
}

private List<LogEntry> combineEntries(
        List<LogEntry> authEntries,
        List<LogEntry> webEntries) {

    List<LogEntry> combined = new ArrayList<>();

    combined.addAll(authEntries);
    combined.addAll(webEntries);

    return combined;
    
}

}