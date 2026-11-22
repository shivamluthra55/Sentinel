
package com.cybershield.database;

import com.cybershield.exception.DatabaseException;

import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

public class DBConnection {

    public static Connection getConnection() throws DatabaseException {

        Properties properties = new Properties();

        try (FileInputStream input = new FileInputStream("config.properties")) {

            properties.load(input);

            String url = properties.getProperty("db.url");
            String username = properties.getProperty("db.username");
            String password = properties.getProperty("db.password");

            Connection connection = DriverManager.getConnection(
                    url, username, password
            );

            return connection;

        } catch (IOException e) {

            throw new DatabaseException(
                    "Unable to read config.properties: " + e.getMessage()
            );

        } catch (SQLException e) {

            throw new DatabaseException(
                    "Unable to connect to MySQL: " + e.getMessage(), e
            );
        }
    }
}
