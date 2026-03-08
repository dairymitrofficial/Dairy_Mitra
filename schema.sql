

-- =========================================
-- USERS TABLE
-- =========================================
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,

    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,

    phone VARCHAR(20),
    dairy_name VARCHAR(255),

    is_verified BOOLEAN DEFAULT FALSE,

    otp VARCHAR(10),
    otp_expiry DATETIME,

    reset_token VARCHAR(255),
    reset_token_expiry DATETIME,

    otp_code VARCHAR(6),
    otp_created_at DATETIME,

    security_password_hash VARCHAR(255),
    security_otp VARCHAR(6),
    security_otp_expiry DATETIME
);


-- =========================================
-- VENDORS TABLE
-- =========================================
CREATE TABLE vendors (

    id INT AUTO_INCREMENT PRIMARY KEY,

    vendor_id INT NOT NULL,

    name VARCHAR(100) NOT NULL,

    address TEXT,

    milk_type ENUM('cow','buffalo','both') DEFAULT 'cow',

    phone VARCHAR(15),

    user_id INT NOT NULL,

    FOREIGN KEY (user_id)
    REFERENCES users(id)
    ON DELETE CASCADE,

    UNIQUE KEY unique_vendor_per_user (vendor_id,user_id)

);


-- =========================================
-- MILK COLLECTION TABLE
-- =========================================
CREATE TABLE milk_collection (

    id INT AUTO_INCREMENT PRIMARY KEY,

    vendor_id INT,
    user_id INT,

    date DATE,

    slot ENUM('morning','evening') NOT NULL,

    milk_type ENUM('cow','buffalo') NOT NULL,

    quantity FLOAT NOT NULL,

    FOREIGN KEY (vendor_id,user_id)
    REFERENCES vendors(vendor_id,user_id)
    ON DELETE CASCADE,

    UNIQUE KEY unique_entry
    (vendor_id,user_id,date,slot,milk_type)

);


-- =========================================
-- ADVANCE TABLE
-- =========================================
CREATE TABLE advance (

    id INT AUTO_INCREMENT PRIMARY KEY,

    vendor_id INT,
    user_id INT,

    date DATE,

    amount FLOAT NOT NULL,

    FOREIGN KEY (vendor_id,user_id)
    REFERENCES vendors(vendor_id,user_id)
    ON DELETE CASCADE,

    UNIQUE KEY unique_advance
    (vendor_id,user_id,date)

);


-- =========================================
-- FOOD SACK RATE TABLE
-- =========================================
CREATE TABLE food_sack_rates (

    id INT AUTO_INCREMENT PRIMARY KEY,

    user_id INT NOT NULL,

    name VARCHAR(100) NOT NULL,

    rate FLOAT NOT NULL,

    date_from DATE NOT NULL,

    FOREIGN KEY (user_id)
    REFERENCES users(id)
    ON DELETE CASCADE

);


-- =========================================
-- FOOD SACK TABLE
-- =========================================
CREATE TABLE food_sack (

    id INT AUTO_INCREMENT PRIMARY KEY,

    vendor_id INT,
    user_id INT,

    date DATE,

    sack_qty INT NOT NULL,

    sack_rate_id INT NOT NULL,

    total_cost FLOAT NOT NULL,

    FOREIGN KEY (vendor_id,user_id)
    REFERENCES vendors(vendor_id,user_id)
    ON DELETE CASCADE,

    FOREIGN KEY (sack_rate_id)
    REFERENCES food_sack_rates(id)
    ON DELETE CASCADE,

    UNIQUE KEY unique_food
    (vendor_id,user_id,date,sack_rate_id)

);


-- =========================================
-- MILK RATE TABLE
-- =========================================
CREATE TABLE milk_rates (

    id INT AUTO_INCREMENT PRIMARY KEY,

    user_id INT NOT NULL,

    animal ENUM('cow','buffalo') NOT NULL,

    rate FLOAT NOT NULL,

    date_from DATE NOT NULL,

    FOREIGN KEY (user_id)
    REFERENCES users(id)
    ON DELETE CASCADE

);


