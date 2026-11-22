
package com.cybershield.exception;

import java.sql.SQLException;

public class DatabaseException extends Exception {

    public DatabaseException(String message) {
        super(message);
    }

    public DatabaseException(String message, SQLException cause) {
        super(message, cause);
    }

    public String getSqlState() {
        Throwable cause = getCause();

        if (cause instanceof SQLException) {
            return ((SQLException) cause).getSQLState();
        }

        return null;
    }

    public int getErrorCode() {
        Throwable cause = getCause();

        if (cause instanceof SQLException) {
            return ((SQLException) cause).getErrorCode();
        }

        return 0;
    }
}

