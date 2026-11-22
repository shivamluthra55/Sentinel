
package com.cybershield.app;

import com.cybershield.service.LogParser;
import com.cybershield.service.LogParser.ParseResult;
import com.cybershield.utils.LogGenerator;

public class Day1Test {

    public static void main(String[] args) throws Exception {

        // Step 1: Generate sample log files
        System.out.println("Generating sample logs...");
        LogGenerator.generateAll();

        // Step 2: Create LogParser object
        LogParser parser = new LogParser();

        // Step 3: Parse authentication log
        System.out.println("\n========== AUTH LOG ==========");

        ParseResult authResult = parser.parseFile("data/auth.log");

        System.out.println("Total lines: " + authResult.getTotalLines());
        System.out.println("Valid entries: " + authResult.getEntries().size());
        System.out.println("Malformed lines: " + authResult.getErrors().size());

        // Step 4: Parse web log
        System.out.println("\n========== WEB LOG ==========");

        ParseResult webResult = parser.parseFile("data/web.log");

        System.out.println("Total lines: " + webResult.getTotalLines());
        System.out.println("Valid entries: " + webResult.getEntries().size());
        System.out.println("Malformed lines: " + webResult.getErrors().size());

        // Step 5: Display final summary
        int totalValid = authResult.getEntries().size()
                       + webResult.getEntries().size();

        int totalErrors = authResult.getErrors().size()
                        + webResult.getErrors().size();

        System.out.println("\n========== FINAL SUMMARY ==========");
        System.out.println("Total valid entries: " + totalValid);
        System.out.println("Total malformed lines: " + totalErrors);

        System.out.println("\nDay 1 checkpoint completed!");
    }
}
