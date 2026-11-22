
package com.cybershield.model;

import java.time.LocalDateTime;

public class Alert implements Comparable<Alert> {

    private int id;
    private String type;
    private Severity severity;
    private String ipAddress;
    private String username;
    private String description;
    private String status = "NEW";
    private LocalDateTime detectedAt;
    private String sourceFile;

    // Empty constructor
    public Alert() {
    }

    // Parameterized constructor
    public Alert(String type, Severity severity, String ipAddress,
                 String username, String description,
                 LocalDateTime detectedAt, String sourceFile) {

        this.type = type;
        this.severity = severity;
        this.ipAddress = ipAddress;
        this.username = username;
        this.description = description;
        this.detectedAt = detectedAt;
        this.sourceFile = sourceFile;
    }

    // Getters and setters
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public LocalDateTime getDetectedAt() {
        return detectedAt;
    }

    public void setDetectedAt(LocalDateTime detectedAt) {
        this.detectedAt = detectedAt;
    }

    public String getSourceFile() {
        return sourceFile;
    }

    public void setSourceFile(String sourceFile) {
        this.sourceFile = sourceFile;
    }

    // Sort by highest severity, then newest alert
    @Override
    public int compareTo(Alert other) {

        int severityComparison = Integer.compare(
                other.severity.getWeight(),
                this.severity.getWeight()
        );

        if (severityComparison != 0) {
            return severityComparison;
        }

        return other.detectedAt.compareTo(this.detectedAt);
    }

    @Override
    public String toString() {
        return "Alert{" +
                "id=" + id +
                ", type='" + type + '\'' +
                ", severity=" + severity +
                ", ipAddress='" + ipAddress + '\'' +
                ", username='" + username + '\'' +
                ", description='" + description + '\'' +
                ", status='" + status + '\'' +
                ", detectedAt=" + detectedAt +
                ", sourceFile='" + sourceFile + '\'' +
                '}';
    }
}

