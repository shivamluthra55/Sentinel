package com.cybershield.database;

import com.cybershield.model.Alert;
import com.cybershield.model.Severity;
import com.cybershield.exception.DatabaseException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;


public class AlertDAO {

    public int addAlert(Alert alert) throws DatabaseException {

        String sql = "INSERT INTO alerts " +
                "(type, severity, ip_address, username, description, status, detected_at, source_file) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

        try (Connection connection = DBConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setString(1, alert.getType());
            statement.setString(2, alert.getSeverity().name());
            statement.setString(3, alert.getIpAddress());
            statement.setString(4, alert.getUsername());
            statement.setString(5, alert.getDescription());
            statement.setString(6, alert.getStatus());
            statement.setTimestamp(7, Timestamp.valueOf(alert.getDetectedAt()));
            statement.setString(8, alert.getSourceFile());

            return statement.executeUpdate();

        } catch (SQLException e) {

            if ("23000".equals(e.getSQLState())) {
                return -1;
            }

            throw new DatabaseException("Unable to insert alert: " + e.getMessage(), e);
        }
    }
     private Alert mapResultSet(ResultSet rs) throws SQLException {

        Alert alert = new Alert();

        alert.setId(rs.getInt("id"));
        alert.setType(rs.getString("type"));
        alert.setSeverity(
                Severity.valueOf(rs.getString("severity"))
        );
        alert.setIpAddress(rs.getString("ip_address"));
        alert.setUsername(rs.getString("username"));
        alert.setDescription(rs.getString("description"));
        alert.setStatus(rs.getString("status"));

        alert.setDetectedAt(
                rs.getTimestamp("detected_at").toLocalDateTime()
        );

        alert.setSourceFile(rs.getString("source_file"));

        return alert;
    }
public List<Alert> getAll() throws DatabaseException {

    List<Alert> alerts = new ArrayList<>();

    String sql = "SELECT * FROM alerts ORDER BY detected_at DESC";

    try (Connection connection = DBConnection.getConnection();
         PreparedStatement statement = connection.prepareStatement(sql);
         ResultSet rs = statement.executeQuery()) {

        while (rs.next()) {

            Alert alert = mapResultSet(rs);

            alerts.add(alert);
        }

        return alerts;

    } catch (SQLException e) {

        throw new DatabaseException(
                "Unable to retrieve alerts: " + e.getMessage(), e
        );
    }
}

public List<Alert> findByIp(String ipAddress) throws DatabaseException {

    List<Alert> alerts = new ArrayList<>();

    String sql = "SELECT * FROM alerts WHERE ip_address = ?";

    try (Connection connection = DBConnection.getConnection();
         PreparedStatement statement = connection.prepareStatement(sql)) {

        statement.setString(1, ipAddress);

        try (ResultSet rs = statement.executeQuery()) {

            while (rs.next()) {
                alerts.add(mapResultSet(rs));
            }
        }

        return alerts;

    } catch (SQLException e) {

        throw new DatabaseException(
                "Unable to find alerts by IP: " + e.getMessage(), e
        );
    }
}
public boolean updateStatus(int id, String status) throws DatabaseException {

    String sql = "UPDATE alerts SET status = ? WHERE id = ?";

    try (Connection connection = DBConnection.getConnection();
         PreparedStatement statement = connection.prepareStatement(sql)) {

        statement.setString(1, status);
        statement.setInt(2, id);

        int rowsUpdated = statement.executeUpdate();

        return rowsUpdated > 0;

    } catch (SQLException e) {

        throw new DatabaseException(
                "Unable to update alert status: " + e.getMessage(), e
        );
    }
}

public List<Alert> findBySeverity(Severity severity) throws DatabaseException {

    List<Alert> alerts = new ArrayList<>();

    String sql = "SELECT * FROM alerts WHERE severity = ?";

    try (Connection connection = DBConnection.getConnection();
         PreparedStatement statement = connection.prepareStatement(sql)) {

        statement.setString(1, severity.name());

        try (ResultSet rs = statement.executeQuery()) {

            while (rs.next()) {
                alerts.add(mapResultSet(rs));
            }
        }

        return alerts;

    } catch (SQLException e) {

        throw new DatabaseException(
                "Unable to find alerts by severity: " + e.getMessage(), e
        );
    }
}
public Optional<Alert> findById(int id) throws DatabaseException {

    String sql = "SELECT * FROM alerts WHERE id = ?";

    try (Connection connection = DBConnection.getConnection();
         PreparedStatement statement = connection.prepareStatement(sql)) {

        statement.setInt(1, id);

        try (ResultSet rs = statement.executeQuery()) {

            if (rs.next()) {
                return Optional.of(mapResultSet(rs));
            }

            return Optional.empty();
        }

    } catch (SQLException e) {

        throw new DatabaseException(
                "Unable to find alert: " + e.getMessage(), e
        );
    }
}

public boolean deleteAlert(int id) throws DatabaseException {

    String sql = "DELETE FROM alerts WHERE id = ?";

    try (Connection connection = DBConnection.getConnection();
         PreparedStatement statement = connection.prepareStatement(sql)) {

        statement.setInt(1, id);

        int rowsDeleted = statement.executeUpdate();

        return rowsDeleted > 0;

    } catch (SQLException e) {

        throw new DatabaseException(
                "Unable to delete alert: " + e.getMessage(), e
        );
    }
}

public int addBatch(List<Alert> alerts) throws DatabaseException {

    String sql = "INSERT INTO alerts "
            + "(type, severity, ip_address, username, description, status, detected_at, source_file) "
            + "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

    Connection connection = null;

    try {

        connection = DBConnection.getConnection();
        connection.setAutoCommit(false);

        try (PreparedStatement statement = connection.prepareStatement(sql)) {

            for (Alert alert : alerts) {

                statement.setString(1, alert.getType());
                statement.setString(2, alert.getSeverity().name());
                statement.setString(3, alert.getIpAddress());
                statement.setString(4, alert.getUsername());
                statement.setString(5, alert.getDescription());
                statement.setString(6, alert.getStatus());
                statement.setTimestamp(7, Timestamp.valueOf(alert.getDetectedAt()));
                statement.setString(8, alert.getSourceFile());

                statement.addBatch();
            }

            int[] results = statement.executeBatch();

            connection.commit();

            return results.length;

        } catch (SQLException e) {

            connection.rollback();
            throw e;
        }

    } catch (SQLException | DatabaseException e) {

        if (connection != null) {
            try {
                connection.rollback();
            } catch (SQLException rollbackError) {
                e.addSuppressed(rollbackError);
            }
        }

        throw new DatabaseException(
                "Unable to insert alerts in batch: " + e.getMessage(),
                e instanceof SQLException ? (SQLException) e : null
        );

    } finally {

        if (connection != null) {
            try {
                connection.setAutoCommit(true);
                connection.close();
            } catch (SQLException e) {
                System.out.println("Error closing database connection: " + e.getMessage());
            }
        }
    }
}

}


   