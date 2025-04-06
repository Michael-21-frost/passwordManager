
CREATE DATABASE password_manager;
USE password_manager;


CREATE TABLE  users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    two_fa_secret VARCHAR(255),  -- Stores encrypted 2FA secret (if enabled)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE passwords (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    service_name VARCHAR(255) NOT NULL,  -- Example: "Gmail"
    encrypted_password TEXT NOT NULL,    -- AES-256 encrypted password
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);



