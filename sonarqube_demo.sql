-- =============================================================================
-- SonarQube SQL Verification Demo
-- =============================================================================
-- This file demonstrates SQL patterns relevant to SonarQube verification.
--
-- Detection layer key used in each section:
--   [SQL-NATIVE]  Detectable by SonarQube's SQL plugin scanning this file.
--   [APP-LAYER]   Rule fires on application code (Java/Python/etc.), NOT on
--                 .sql files.  See java/DatabaseService.java for each case.
--   [BEST-PRACTICE] No standard SonarQube rule; enforced via custom rules,
--                   DB-level tooling, or code review.
-- =============================================================================


-- =============================================================================
-- SECTION 1: SQL INJECTION VULNERABILITIES
-- =============================================================================
-- Detection layer : [APP-LAYER]
-- SonarQube rule  : S2077 — "Formatting SQL queries is security-sensitive"
-- Why not here    : S2077 analyses how application code (Java, Python, PHP,
--                   C#, JS) constructs SQL strings at runtime.  SonarQube's
--                   SQL plugin does not trace variable flow inside stored
--                   procedure bodies.
-- See             : java/DatabaseService.java  bad_getUserByName()
--                                              good_getUserByName()
-- -----------------------------------------------------------------------------

-- [SQL REFERENCE — BAD] Shows the database-side anti-pattern;
-- the injection risk is triggered from application code, not here.
CREATE OR REPLACE PROCEDURE bad_get_user_by_name(p_username VARCHAR(100))
BEGIN
    SET @sql = CONCAT('SELECT * FROM users WHERE username = ''', p_username, '''');
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END;

-- [SQL REFERENCE — GOOD] Parameterized stored procedure; safe regardless of caller.
CREATE OR REPLACE PROCEDURE good_get_user_by_name(p_username VARCHAR(100))
BEGIN
    SELECT id, username, email, created_at
    FROM users
    WHERE username = p_username;
END;


-- =============================================================================
-- SECTION 2: HARDCODED CREDENTIALS
-- =============================================================================
-- Detection layer : [SQL-NATIVE] + [APP-LAYER]
-- SonarQube rule  : S2068 — "Credentials should not be hard-coded"
-- Note            : SonarQube scans SQL files for IDENTIFIED BY / PASSWORD()
--                   literal patterns.  The Java equivalent in DatabaseService
--                   guarantees detection even if the SQL plugin is not enabled.
-- See             : java/DatabaseService.java  bad_getConnection()
--                                              good_getConnection()
-- -----------------------------------------------------------------------------

-- [BAD] Hardcoded password literal — S2068 should fire on this line.
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'SuperSecret123!';

-- [GOOD] Reference credentials from a secrets manager or environment variable;
-- never embed passwords in SQL scripts committed to version control.
-- CREATE USER 'app_user'@'localhost' IDENTIFIED BY '${APP_USER_PASSWORD}';


-- =============================================================================
-- SECTION 3: SELECT * USAGE (Code Smell)
-- =============================================================================
-- Detection layer : [BEST-PRACTICE]
-- SonarQube rule  : No built-in rule in the standard SQL plugin.
--                   Enforce via a custom SonarQube rule, sqlfluff (L028/L044),
--                   or a team coding standard.
-- Note            : S1680 (previously cited here) is a Java rule about
--                   identical boolean operands — it does NOT apply to SQL.
-- -----------------------------------------------------------------------------

-- [BAD] SELECT * fetches all columns; fragile and expensive.
SELECT * FROM orders WHERE status = 'PENDING';

-- [GOOD] Explicitly name required columns.
SELECT
    order_id,
    customer_id,
    total_amount,
    status,
    created_at
FROM orders
WHERE status = 'PENDING';


-- =============================================================================
-- SECTION 4: MISSING WHERE CLAUSE ON UPDATE / DELETE
-- =============================================================================
-- Detection layer : [BEST-PRACTICE]
-- SonarQube rule  : No built-in rule in the standard SQL plugin.
--                   Enforce via sqlfluff (L044), a custom SonarQube rule,
--                   or database-level SAFE_UPDATES mode (MySQL).
-- Note            : S2737 (previously cited here) is a Java rule about empty
--                   catch blocks — it does NOT apply to SQL WHERE clauses.
-- -----------------------------------------------------------------------------

-- [BAD] UPDATE without WHERE modifies every row in the table.
UPDATE products SET stock_count = 0;

-- [GOOD] Scope mutations to the intended rows.
UPDATE products
SET stock_count = 0
WHERE product_id = 42;

-- [BAD] DELETE without WHERE deletes the entire table.
DELETE FROM audit_logs;

-- [GOOD] Scope the deletion appropriately.
DELETE FROM audit_logs
WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY);


-- =============================================================================
-- SECTION 5: NULL HANDLING ISSUES
-- =============================================================================
-- Detection layer : [BEST-PRACTICE]
-- SonarQube rule  : No built-in rule in the standard SQL plugin.
--                   Some static analysis tools (e.g. SchemaSpy, sqlcheck)
--                   detect = NULL comparisons; enforce via code review.
-- -----------------------------------------------------------------------------

-- [BAD] Comparing with NULL using = always evaluates to UNKNOWN, never TRUE.
SELECT * FROM employees WHERE manager_id = NULL;

-- [GOOD] Use IS NULL / IS NOT NULL for null checks.
SELECT
    employee_id,
    first_name,
    last_name
FROM employees
WHERE manager_id IS NULL;

-- [BAD] Arithmetic with a potentially NULL column produces NULL silently.
SELECT product_id, (price * discount_rate) AS discounted_price
FROM products;

-- [GOOD] Handle NULL with COALESCE to guarantee a safe default.
SELECT
    product_id,
    (price * COALESCE(discount_rate, 1.0)) AS discounted_price
FROM products;


-- =============================================================================
-- SECTION 6: DUPLICATE / REDUNDANT CONDITIONS
-- =============================================================================
-- Detection layer : [APP-LAYER]
-- SonarQube rule  : S1764 — "Identical expressions should not be used on both
--                   sides of a binary operator"
-- Why not here    : S1764 is a Java/C#/etc. rule that tracks identical
--                   sub-expressions within a boolean expression in code.
--                   SonarQube's SQL plugin does not perform equivalent
--                   predicate-duplication analysis on WHERE clauses.
-- See             : java/DatabaseService.java  bad_isEligible()
--                                              good_isEligible()
-- -----------------------------------------------------------------------------

-- [SQL REFERENCE — BAD] Redundant OR — second predicate is identical to first.
SELECT order_id FROM orders
WHERE status = 'PENDING' OR status = 'PENDING';

-- [SQL REFERENCE — GOOD] Single predicate.
SELECT order_id FROM orders
WHERE status = 'PENDING';

-- [SQL REFERENCE — BAD] Tautological condition — always TRUE.
SELECT customer_id FROM customers
WHERE 1 = 1 AND is_active = 1;

-- [SQL REFERENCE — GOOD] Remove the tautology.
SELECT customer_id FROM customers
WHERE is_active = 1;


-- =============================================================================
-- SECTION 7: IMPROPER ERROR HANDLING IN STORED PROCEDURES
-- =============================================================================
-- Detection layer : [BEST-PRACTICE]
-- SonarQube rule  : No standard SonarQube rule for SQL stored procedure
--                   transaction safety.  Enforce via code review or a custom
--                   SonarQube rule targeting BEGIN/COMMIT without HANDLER.
-- -----------------------------------------------------------------------------

-- [BAD] No transaction or error handler — partial failure leaves data inconsistent.
CREATE OR REPLACE PROCEDURE bad_transfer_funds(
    p_from_account INT,
    p_to_account   INT,
    p_amount       DECIMAL(15,2)
)
BEGIN
    UPDATE accounts SET balance = balance - p_amount WHERE account_id = p_from_account;
    UPDATE accounts SET balance = balance + p_amount WHERE account_id = p_to_account;
END;

-- [GOOD] Transaction with SQLEXCEPTION handler ensures atomic rollback.
CREATE OR REPLACE PROCEDURE good_transfer_funds(
    p_from_account INT,
    p_to_account   INT,
    p_amount       DECIMAL(15,2)
)
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;

    START TRANSACTION;

    UPDATE accounts
    SET balance = balance - p_amount
    WHERE account_id = p_from_account;

    UPDATE accounts
    SET balance = balance + p_amount
    WHERE account_id = p_to_account;

    COMMIT;
END;


-- =============================================================================
-- SECTION 8: COGNITIVE COMPLEXITY — DEEPLY NESTED LOGIC
-- =============================================================================
-- Detection layer : [APP-LAYER]
-- SonarQube rule  : S3776 — "Cognitive Complexity of methods should not be
--                   too high" (default threshold: 15)
-- Why not here    : S3776 counts nesting increments inside methods/functions
--                   in application languages (Java, Python, C#, JS, etc.).
--                   SonarQube's SQL plugin does not compute cognitive complexity
--                   for nested CASE expressions in SQL.
-- See             : java/DatabaseService.java  bad_getPriorityLabel()
--                                              good_getPriorityLabel()
-- -----------------------------------------------------------------------------

-- [SQL REFERENCE — BAD] Deeply nested CASE — mirrors the Java bad example.
SELECT
    order_id,
    CASE
        WHEN status = 'PENDING' THEN
            CASE
                WHEN total_amount > 1000 THEN
                    CASE
                        WHEN customer_tier = 'GOLD' THEN 'HIGH_PRIORITY_GOLD'
                        ELSE 'HIGH_PRIORITY'
                    END
                ELSE 'NORMAL_PRIORITY'
            END
        ELSE 'NOT_PENDING'
    END AS priority_label
FROM orders;

-- [SQL REFERENCE — GOOD] Flattened CASE with explicit predicates.
SELECT
    o.order_id,
    CASE
        WHEN o.status != 'PENDING'                                        THEN 'NOT_PENDING'
        WHEN o.total_amount > 1000 AND o.customer_tier = 'GOLD'          THEN 'HIGH_PRIORITY_GOLD'
        WHEN o.total_amount > 1000                                        THEN 'HIGH_PRIORITY'
        ELSE                                                                   'NORMAL_PRIORITY'
    END AS priority_label
FROM orders o;


-- =============================================================================
-- SECTION 9: FUNCTION ON INDEXED COLUMN (Performance)
-- =============================================================================
-- Detection layer : [BEST-PRACTICE]
-- SonarQube rule  : No SonarQube rule exists for this pattern.
--                   Detect via EXPLAIN / query plan analysis, database-specific
--                   advisors (MySQL EXPLAIN, pg_stat_statements), or sqlfluff.
-- -----------------------------------------------------------------------------

-- [BAD] Wrapping an indexed column in a function defeats the index.
SELECT customer_id, email
FROM customers
WHERE UPPER(email) = 'JOHN@EXAMPLE.COM';

-- [GOOD] Store data in canonical form; filter without a wrapping function.
SELECT customer_id, email
FROM customers
WHERE email = 'john@example.com';


-- =============================================================================
-- SECTION 10: SCHEMA BEST PRACTICES
-- =============================================================================
-- Detection layer : [SQL-NATIVE] (partially)
-- SonarQube rule  : Some SonarQube DB quality profiles flag tables without
--                   primary keys.  Enforce missing NOT NULL / type correctness
--                   via a custom rule or database migration linter (Flyway,
--                   Liquibase with checks enabled).
-- -----------------------------------------------------------------------------

-- [BAD] No primary key, ambiguous data types, nullable name.
CREATE TABLE bad_events (
    name     VARCHAR(255),
    payload  TEXT,
    ts       VARCHAR(50)   -- storing timestamps as strings is error-prone
);

-- [GOOD] Explicit primary key, proper data types, NOT NULL constraints.
CREATE TABLE good_events (
    event_id   BIGINT        NOT NULL AUTO_INCREMENT,
    name       VARCHAR(255)  NOT NULL,
    payload    JSON,
    created_at TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (event_id)
);


-- =============================================================================
-- END OF DEMO
-- =============================================================================
