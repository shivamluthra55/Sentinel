
CREATE DATABASE IF NOT EXISTS cybershield;

USE cybershield;

CREATE TABLE IF NOT EXISTS alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    username VARCHAR(50),
    description VARCHAR(255),
    status VARCHAR(20) DEFAULT 'NEW',
    detected_at TIMESTAMP NOT NULL,
    source_file VARCHAR(100),

    UNIQUE KEY uq_alert (type, ip_address, detected_at),

    INDEX idx_ip_address (ip_address),
    INDEX idx_severity (severity)
);
