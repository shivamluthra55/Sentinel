package com.cybershield.exception;
/** Thrown when one log line is malformed. The parser catches it and continues with the next line. */
public class InvalidLogFormatException extends Exception {
private final int lineNumber;
private final String badLine;

public InvalidLogFormatException(String reason, int lineNumber, String badLine) {
super("Line " + lineNumber + ": " + reason);
this.lineNumber = lineNumber;
this.badLine = badLine;
   }
public int getLineNumber() { return lineNumber; }
public String getBadLine() { return badLine; }
}