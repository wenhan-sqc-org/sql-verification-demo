package com.example.demo;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * SonarQube SQL Verification Demo — Application-Layer Companion
 *
 * This file contains Java patterns that trigger SonarQube rules which cannot
 * be detected inside plain .sql files.  Each section maps to the corresponding
 * section in sonarqube_demo.sql.
 *
 * Detectable rules demonstrated here:
 *   S2077  – Formatting SQL queries is security-sensitive  (Section 1)
 *   S2068  – Credentials should not be hard-coded          (Section 2)
 *   S1764  – Identical expressions on both sides of an operator (Section 6)
 *   S3776  – Cognitive Complexity of methods should not be too high (Section 8)
 */
public class DatabaseService {

    // =========================================================================
    // SECTION 1 — SQL INJECTION  (SonarQube rule: S2077)
    // =========================================================================
    // SonarQube scans Java/Python/PHP/etc. for dynamic SQL string construction.
    // The .sql stored-procedure equivalent (see sonarqube_demo.sql §1) is NOT
    // scanned; this Java method IS.

    /** [BAD] String concatenation builds an injectable query — S2077 fires here. */
    public List<String> bad_getUserByName(Connection conn, String username) throws Exception {
        // SonarQube S2077: user-controlled value flows into a SQL string
        String query = "SELECT id, username FROM users WHERE username = '" + username + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query); // <-- S2077 flagged on this line

        List<String> results = new ArrayList<>();
        while (rs.next()) {
            results.add(rs.getString("username"));
        }
        return results;
    }

    /** [GOOD] Parameterized PreparedStatement — no injection risk, S2077 silent. */
    public List<String> good_getUserByName(Connection conn, String username) throws Exception {
        String query = "SELECT id, username FROM users WHERE username = ?";
        PreparedStatement pstmt = conn.prepareStatement(query);
        pstmt.setString(1, username);
        ResultSet rs = pstmt.executeQuery();

        List<String> results = new ArrayList<>();
        while (rs.next()) {
            results.add(rs.getString("username"));
        }
        return results;
    }

    // =========================================================================
    // SECTION 2 — HARDCODED CREDENTIALS  (SonarQube rule: S2068)
    // =========================================================================
    // S2068 scans both .sql files and application code for literal strings that
    // look like passwords.  The Java pattern below guarantees detection regardless
    // of whether the SQL plugin is configured.

    /** [BAD] Hard-coded password literal — S2068 fires on the string below. */
    public Connection bad_getConnection() throws Exception {
        String url      = "jdbc:mysql://localhost:3306/mydb";
        String user     = "app_user";
        String password = "SuperSecret123!"; // <-- S2068 flagged here
        return DriverManager.getConnection(url, user, password);
    }

    /** [GOOD] Password sourced from environment / secrets manager — S2068 silent. */
    public Connection good_getConnection() throws Exception {
        String url      = "jdbc:mysql://localhost:3306/mydb";
        String user     = System.getenv("DB_USER");
        String password = System.getenv("DB_PASSWORD");
        return DriverManager.getConnection(url, user, password);
    }

    // =========================================================================
    // SECTION 6 — DUPLICATE / REDUNDANT CONDITIONS  (SonarQube rule: S1764)
    // =========================================================================
    // S1764 fires when the same expression appears on both sides of a binary
    // operator.  The SQL "status = 'PENDING' OR status = 'PENDING'" pattern
    // does not trigger this Java rule; the Java equivalent below does.

    /** [BAD] Identical sub-expressions in a boolean condition — S1764 fires. */
    public boolean bad_isEligible(int score) {
        // S1764: both sides of && are identical — the second check is redundant
        return score > 50 && score > 50; // <-- S1764 flagged here
    }

    /** [GOOD] Each sub-expression tests a distinct condition. */
    public boolean good_isEligible(int score, boolean isVerified) {
        return score > 50 && isVerified;
    }

    // =========================================================================
    // SECTION 8 — COGNITIVE COMPLEXITY  (SonarQube rule: S3776)
    // =========================================================================
    // S3776 measures the cognitive complexity of a method.  SonarQube counts
    // nesting increments for each `if`, `else`, `for`, `switch`, etc.
    // Nested CASE expressions in a .sql file are not counted by the SQL plugin;
    // deeply nested conditionals in Java ARE counted.

    /**
     * [BAD] Deeply nested if/else mirrors the nested CASE in sonarqube_demo.sql §8.
     * Cognitive complexity is well above the default threshold of 15 — S3776 fires.
     */
    public String bad_getPriorityLabel(String status, double totalAmount, String customerTier) {
        // +1 (if)
        if (status.equals("PENDING")) {
            // +2 (nested if)
            if (totalAmount > 1000) {
                // +3 (nested if)
                if (customerTier.equals("GOLD")) {
                    return "HIGH_PRIORITY_GOLD";
                } else { // +1
                    // +4 (nested if)
                    if (customerTier.equals("SILVER")) {
                        return "HIGH_PRIORITY_SILVER";
                    } else { // +1
                        return "HIGH_PRIORITY";
                    }
                }
            } else { // +1
                // +3 (nested if)
                if (totalAmount > 500) {
                    return "MEDIUM_PRIORITY";
                } else { // +1
                    return "NORMAL_PRIORITY";
                }
            }
        } else { // +1
            // +2 (nested if)
            if (status.equals("SHIPPED")) {
                return "IN_TRANSIT";
            } else { // +1
                return "NOT_PENDING";
            }
        }
        // Total cognitive complexity ≈ 18 — exceeds default threshold of 15
        // S3776 fires here
    }

    /**
     * [GOOD] Flat guard-clause structure — same logic, cognitive complexity ≤ 5.
     * S3776 is silent.
     */
    public String good_getPriorityLabel(String status, double totalAmount, String customerTier) {
        if (!status.equals("PENDING"))       return "NOT_PENDING";
        if (status.equals("SHIPPED"))        return "IN_TRANSIT";
        if (totalAmount > 1000 && customerTier.equals("GOLD"))   return "HIGH_PRIORITY_GOLD";
        if (totalAmount > 1000 && customerTier.equals("SILVER")) return "HIGH_PRIORITY_SILVER";
        if (totalAmount > 1000)              return "HIGH_PRIORITY";
        if (totalAmount > 500)               return "MEDIUM_PRIORITY";
        return "NORMAL_PRIORITY";
    }
}
