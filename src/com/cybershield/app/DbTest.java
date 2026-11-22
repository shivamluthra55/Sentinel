
package com.cybershield.app;

import com.cybershield.database.DBConnection;
import com.cybershield.exception.DatabaseException;

import java.sql.Connection;
import java.sql.DatabaseMetaData;

public class DbTest {

    public static void main(String[] args) {

        try (Connection connection = DBConnection.getConnection()) {

            System.out.println("Database connected successfully!");

            DatabaseMetaData metadata = connection.getMetaData();

            System.out.println("Database: " + connection.getCatalog());
            System.out.println("MySQL Version: " + metadata.getDatabaseProductVersion());

        } catch (DatabaseException | java.sql.SQLException e) {

            System.out.println("Database connection failed!");
            System.out.println("Error: " + e.getMessage());
        }
    }
}
