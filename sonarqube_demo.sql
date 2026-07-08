-- =============================================================================
-- SonarQube SQL Verification Demo
-- =============================================================================
-- This file demonstrates SQL patterns that SonarQube can detect and verify,
-- including common vulnerabilities, code smells, and best practices.
-- =============================================================================


-- =============================================================================
-- SECTION 1: SQL INJECTION VULNERABILITIES
-- =============================================================================

-- [BAD] Dynamic SQL built with string concatenation — injectable
-- SonarQube rule: S2077 (Formatting SQL queries is security-sensitive)
CREATE OR REPLACE PROCEDURE bad_get_user_by_name(p_username VARCHAR(100))
BEGIN
    SET @sql = CONCAT('SELECT * FROM users WHERE username = ''', p_username, '''');
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END;

-- [GOOD] Use parameterized queries / prepared statements
CREATE OR REPLACE PROCEDURE good_get_user_by_name(p_username VARCHAR(100))
BEGIN
    SELECT id, username, email, created_at
    FROM users
    WHERE username = p_username;
END;


-- =============================================================================
-- SECTION 2: HARDCODED CREDENTIALS
-- =============================================================================

-- [BAD] Hardcoded password in SQL — SonarQube rule: S2068
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'SuperSecret123!';

-- [GOOD] Reference credentials from a secrets manager or environment config;
-- avoid embedding passwords directly in SQL scripts committed to version control.
-- CREATE USER 'app_user'@'localhost' IDENTIFIED BY '${APP_USER_PASSWORD}';


-- =============================================================================
-- SECTION 3: SELECT * USAGE (Code Smell)
-- =============================================================================

-- [BAD] SELECT * fetches all columns, making queries fragile and expensive
-- SonarQube rule: S1680
SELECT * FROM orders WHERE status = 'PENDING';

-- [GOOD] Explicitly name required columns
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

-- [BAD] UPDATE without a WHERE clause modifies every row in the table
-- SonarQube rule: S2737
UPDATE products SET stock_count = 0;

-- [GOOD] Always scope mutations to the intended rows
UPDATE products
SET stock_count = 0
WHERE product_id = 42;

-- [BAD] DELETE without WHERE — deletes entire table contents
DELETE FROM audit_logs;

-- [GOOD] Scope the deletion appropriately
DELETE FROM audit_logs
WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY);


-- =============================================================================
-- SECTION 5: NULL HANDLING ISSUES
-- =============================================================================

-- [BAD] Comparing with NULL using = always evaluates to UNKNOWN, never TRUE
SELECT * FROM employees WHERE manager_id = NULL;

-- [GOOD] Use IS NULL / IS NOT NULL for null checks
SELECT
    employee_id,
    first_name,
    last_name
FROM employees
WHERE manager_id IS NULL;

-- [BAD] Arithmetic with a potentially NULL column without coalescing
SELECT product_id, (price * discount_rate) AS discounted_price
FROM products;

-- [GOOD] Handle NULL with COALESCE to guarantee a safe default
SELECT
    product_id,
    (price * COALESCE(discount_rate, 1.0)) AS discounted_price
FROM products;


-- =============================================================================
-- SECTION 6: DUPLICATE / REDUNDANT CONDITIONS
-- =============================================================================

-- [BAD] Redundant OR condition — the second predicate is always covered by the first
-- SonarQube rule: S1764
SELECT order_id FROM orders
WHERE status = 'PENDING' OR status = 'PENDING';

-- [GOOD] Remove the duplicate predicate
SELECT order_id FROM orders
WHERE status = 'PENDING';

-- [BAD] Tautological condition — always TRUE, adds no filtering
SELECT customer_id FROM customers
WHERE 1 = 1 AND is_active = 1;

-- [GOOD] Remove the tautology
SELECT customer_id FROM customers
WHERE is_active = 1;


-- =============================================================================
-- SECTION 7: IMPROPER ERROR HANDLING IN STORED PROCEDURES
-- =============================================================================

-- [BAD] No error handling — failures silently propagate
CREATE OR REPLACE PROCEDURE bad_transfer_funds(
    p_from_account INT,
    p_to_account   INT,
    p_amount       DECIMAL(15,2)
)
BEGIN
    UPDATE accounts SET balance = balance - p_amount WHERE account_id = p_from_account;
    UPDATE accounts SET balance = balance + p_amount WHERE account_id = p_to_account;
END;

-- [GOOD] Wrap in a transaction with explicit error handling and rollback
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

-- [BAD] Deeply nested CASE expressions are hard to read and maintain
-- SonarQube rule: S3776
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

-- [GOOD] Flatten logic with explicit predicates or a lookup/reference table
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
-- SECTION 9: MISSING INDEX HINTS / PERFORMANCE SMELLS
-- =============================================================================

-- [BAD] Function applied to an indexed column prevents index usage
SELECT customer_id, email
FROM customers
WHERE UPPER(email) = 'JOHN@EXAMPLE.COM';

-- [GOOD] Store emails in a canonical form, or use a function-based index,
-- and filter without wrapping the column in a function
SELECT customer_id, email
FROM customers
WHERE email = 'john@example.com';


-- =============================================================================
-- SECTION 10: SCHEMA BEST PRACTICES
-- =============================================================================

-- [BAD] Table created without a primary key and with ambiguous data types
CREATE TABLE bad_events (
    name     VARCHAR(255),
    payload  TEXT,
    ts       VARCHAR(50)   -- storing timestamps as strings is error-prone
);

-- [GOOD] Explicit primary key, proper data types, NOT NULL constraints
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
