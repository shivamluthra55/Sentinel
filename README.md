# CyberShield – Security Monitoring System

## Overview

CyberShield is a Java-based security monitoring system that analyzes authentication and web server logs to identify suspicious activities and potential security threats.

It uses Core Java, JDBC and MySQL to detect threats, store security alerts and manage detected incidents through a command-line interface.

## Features

- **Brute Force Detection:** Identifies repeated failed login attempts within a specified time window.
- **Blacklist Detection:** Detects activity originating from blacklisted IP addresses.
- **Odd-Hour Login Detection:** Identifies successful admin/root logins between midnight and 5 AM.
- **SQL Injection Detection:** Identifies suspicious SQL patterns in web requests.
- **Dashboard:** Displays alert statistics and threat categories.
- **Alert Management:** Search, filter, update and delete security alerts.
- **Database Integration:** Stores alerts in MySQL using JDBC.
- **Log Parsing:** Handles valid and malformed log entries.

## Technologies Used

- Java (JDK 21)
- JDBC
- MySQL 8.0
- MySQL Connector/J 8.4.0
- VS Code
- Git and GitHub

## Project Structure

```text
CyberShield/
├── config.properties
├── config.properties.example
├── .gitignore
├── lib/
│   └── mysql-connector-j-8.4.0.jar
├── data/
│   ├── auth.log
│   ├── web.log
│   └── blacklist.txt
├── sql/
│   └── schema.sql
└── src/
    └── com/
        └── cybershield/
            ├── app/
            ├── database/
            ├── detection/
            ├── exception/
            ├── model/
            ├── monitoring/
            ├── service/
            └── utils/
```

## Database Setup

1. Install MySQL Server.
2. Create the database named `cybershield`.
3. Execute the SQL script located at `sql/schema.sql`.
4. Configure database credentials in `config.properties`.

Example configuration:

```properties
db.url=jdbc:mysql://localhost:3306/cybershield
db.username=root
db.password=YOUR_PASSWORD
```

Never upload your actual database password to GitHub.

## How to Run

Compile the Java source files from the project root:

```powershell
javac -cp "lib/mysql-connector-j-8.4.0.jar" -d out (Get-ChildItem -Recurse -Filter *.java src).FullName
```

Run the application:

```powershell
java -cp "out;lib/mysql-connector-j-8.4.0.jar" com.cybershield.app.CyberShieldApp
```

## Application Menu

1. Run Threat Detection
2. View Dashboard
3. View All Alerts
4. Search Alert by IP
5. Filter Alerts by Severity
6. Update Alert Status
7. Delete Alert
8. Exit

## Detection Categories

| Threat | Description |
|---|---|
| BRUTE_FORCE | Repeated failed login attempts |
| BLACKLISTED_IP | Activity from known blacklisted IPs |
| ODD_HOUR_LOGIN | Suspicious admin/root login times |
| SQL_INJECTION | Suspicious SQL patterns in web requests |

## Project Limitations

- Uses sample log files rather than continuous live network monitoring.
- SQL injection detection uses predefined signatures and is intended as a demonstration.
- Detection results depend on the quality and format of the input logs.

## Future Enhancements

- Real-time log monitoring.
- More advanced anomaly detection.
- Email notifications for critical alerts.
- Machine-learning-based threat classification.
- Advanced reporting and analytics.

## Author

Developed as an academic Java programming project.
