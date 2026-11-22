package com.cybershield.model;

import java.time.LocalDateTime;

public class LogEntry {
    private final LocalDateTime timestamp;
    private final String ipAddress;
    private final String username;
    private final String action;       // LOGIN, GET, POST ...
    private final String status;       // SUCCESS, FAILED, 200, 404 ...
    private final String requestPath;  // "-" for auth logs

    public LogEntry(LocalDateTime timestamp, String ipAddress, String username,
                    String action, String status, String requestPath) {
        this.timestamp = timestamp;
        this.ipAddress = ipAddress;
        this.username = username;
        this.action = action;
        this.status = status;
        this.requestPath = requestPath;
    }

    public LocalDateTime getTimestamp() { return timestamp; }
    public String getIpAddress() { return ipAddress; }
    public String getUsername() { return username; }
    public String getAction() { return action; }
    public String getStatus() { return status; }
    public String getRequestPath() { return requestPath; }

    public boolean isLogin() {
        return "LOGIN".equalsIgnoreCase(action);
    }

    public boolean isFailedLogin() {
        return isLogin() && "FAILED".equalsIgnoreCase(status);
    }

    @Override
    public String toString() {
        return timestamp + " | " + ipAddress + " | " + username + " | "
                + action + " | " + status + " | " + requestPath;
    }
}