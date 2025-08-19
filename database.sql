CREATE DATABASE IF NOT EXISTS milk_collection;
USE milk_collection;

-- Users Table (login and OTP-related functionality)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    phone VARCHAR(20) NOT NULL,
    dairy_name VARCHAR(255),
    is_verified BOOLEAN DEFAULT FALSE,
    otp VARCHAR(10),
    otp_expiry DATETIME,
    reset_token VARCHAR(255),
    reset_token_expiry DATETIME
);

-- ✅ Vendors Table (Updated: vendor_id + user_id unique)
CREATE TABLE IF NOT EXISTS vendors (
    id INT AUTO_INCREMENT PRIMARY KEY,
    vendor_id VARCHAR(20) NOT NULL,
    name VARCHAR(100) NOT NULL,
    address TEXT,
    milk_type ENUM('cow', 'buffalo', 'both') DEFAULT 'cow',
    phone VARCHAR(15),
    user_id INT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE KEY unique_vendor_per_user (vendor_id, user_id)
);

-- Milk Collection Table
CREATE TABLE IF NOT EXISTS milk_collection (
    id INT AUTO_INCREMENT PRIMARY KEY,
    vendor_id VARCHAR(20),
    user_id INT,
    date DATE,
    slot ENUM('morning', 'evening') NOT NULL,
    milk_type ENUM('cow', 'buffalo') NOT NULL,
    quantity FLOAT NOT NULL,
    FOREIGN KEY (vendor_id, user_id) REFERENCES vendors(vendor_id, user_id),
    UNIQUE KEY unique_entry (vendor_id, user_id, date, slot, milk_type)
);

-- Advance Table
CREATE TABLE IF NOT EXISTS advance (
    id INT AUTO_INCREMENT PRIMARY KEY,
    vendor_id VARCHAR(20),
    user_id INT,
    date DATE,
    amount FLOAT NOT NULL,
    FOREIGN KEY (vendor_id, user_id) REFERENCES vendors(vendor_id, user_id),
    UNIQUE KEY unique_advance (vendor_id, user_id, date)
);

-- Food Sack Rates Table (must come before food_sack)
CREATE TABLE IF NOT EXISTS food_sack_rates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    name VARCHAR(100) NOT NULL,
    rate FLOAT NOT NULL,
    date_from DATE NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Food Sack Table (references food_sack_rates)
CREATE TABLE IF NOT EXISTS food_sack (
    id INT AUTO_INCREMENT PRIMARY KEY,
    vendor_id VARCHAR(20),
    user_id INT,
    date DATE,
    sack_qty INT NOT NULL,
    sack_rate_id INT NOT NULL,
    total_cost FLOAT NOT NULL,
    FOREIGN KEY (vendor_id, user_id) REFERENCES vendors(vendor_id, user_id),
    FOREIGN KEY (sack_rate_id) REFERENCES food_sack_rates(id),
    UNIQUE KEY unique_food (vendor_id, user_id, date, sack_rate_id)
);


-- Milk Rates Table
CREATE TABLE IF NOT EXISTS milk_rates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    animal ENUM('cow', 'buffalo') NOT NULL,
    rate FLOAT NOT NULL,
    date_from DATE NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);


USE milk_collection;
SELECT * FROM milk_collection;



