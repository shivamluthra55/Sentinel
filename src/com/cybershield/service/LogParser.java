package com.cybershield.service;                    // file lives in the service folder

import com.cybershield.exception.InvalidLogFormatException;
import com.cybershield.model.LogEntry;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class LogParser {

    // The exact date pattern a valid line must use
    private static final DateTimeFormatter FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // Regex for an IPv4 address: four numbers, each 0-255, separated by dots
    private static final Pattern IPV4 = Pattern.compile(
            "^((25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1?\\d?\\d)$");

    /** Bundles everything one file scan produces, because a method can return only one value. */
    public static class ParseResult {
        private final List<LogEntry> entries = new ArrayList<>();   // lines that parsed correctly
        private final List<String> errors = new ArrayList<>();      // one message per bad line
        private int totalLines = 0;                                 // real lines read (blank/comment lines excluded)

        public List<LogEntry> getEntries() { return entries; }
        public List<String> getErrors() { return errors; }
        public int getTotalLines() { return totalLines; }
        public int getBadLines() { return errors.size(); }      // bad lines = number of error messages
    }

    /** Turns ONE line of text into ONE LogEntry, or throws if the line is malformed. */
    public LogEntry parseLine(String line, int lineNumber) throws InvalidLogFormatException {

        String[] parts = line.split(",", 6);        // cut at commas into at most 6 pieces (path may contain commas)

        // CHECK 1: must have all 6 fields
        if (parts.length < 6) {
            throw new InvalidLogFormatException(
                    "expected 6 fields but found " + parts.length, lineNumber, line);
        }

        // CHECK 2: no field may be empty
        for (int i = 0; i < parts.length; i++) {
            parts[i] = parts[i].trim();             // remove spaces around the field
            if (parts[i].isEmpty()) {
                throw new InvalidLogFormatException(
                        "field " + (i + 1) + " is empty", lineNumber, line);
            }
        }

        // CHECK 3: the timestamp must be a real date and time
        LocalDateTime time;
        try {
            time = LocalDateTime.parse(parts[0], FORMAT);       // text -> date-time object
        } catch (DateTimeParseException e) {                    // Java's own error for a bad date
            throw new InvalidLogFormatException(                // convert it into OUR exception
                    "invalid timestamp '" + parts[0] + "'", lineNumber, line);
        }

        // CHECK 4: the IP must be a valid IPv4 address
        if (!IPV4.matcher(parts[1]).matches()) {
            throw new InvalidLogFormatException(
                    "invalid IP address '" + parts[1] + "'", lineNumber, line);
        }

        // All checks passed: build the object.
        // action and status are upper-cased so "login" and "LOGIN" are treated the same.
        return new LogEntry(time, parts[1], parts[2],
                parts[3].toUpperCase(), parts[4].toUpperCase(), parts[5]);
    }

    /** Reads a whole file. A bad line is recorded and skipped, so it never stops the scan. */
    public ParseResult parseFile(String path) throws IOException {
        ParseResult result = new ParseResult();

        // try-with-resources: the reader closes automatically, even if an error happens
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            String line;
            int lineNumber = 0;

            while ((line = reader.readLine()) != null) {        // null means end of file
                lineNumber++;

                if (line.isBlank() || line.startsWith("#")) {   // skip blank lines and comments
                    continue;
                }

                result.totalLines++;                            // count only real lines

                try {
                    result.entries.add(parseLine(line, lineNumber));   // good line: store the LogEntry
                } catch (InvalidLogFormatException e) {
                    result.errors.add(e.getMessage());                 // bad line: store message, keep going
                }
            }
        }
        return result;
    }
}