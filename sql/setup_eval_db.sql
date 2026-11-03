-- Isolated database for the MySQL execution experiment (notebook 05).
-- Same schema and seed data as the first paper's lab app (db-setup.js), in a
-- separate database so the lab app's own data is never touched.
-- The experiment connects as a SELECT-only user: injected DROP/INSERT/
-- INTO OUTFILE/LOAD_FILE etc. fail with a privilege error instead of running.
-- Replace CHANGE_ME with the password stored in the project's .env file.

CREATE DATABASE IF NOT EXISTS sqli_ml_eval;
USE sqli_ml_eval;

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS products;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT '2026-01-01 00:00:00'
);

CREATE TABLE products (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  price DECIMAL(10, 2) NOT NULL,
  stock INT DEFAULT 0,
  created_at TIMESTAMP DEFAULT '2026-01-01 00:00:00'
);

INSERT INTO users (username, email, password) VALUES
  ('admin', 'admin@test.com', 'admin123'),
  ('test_user', 'test@test.com', 'test123'),
  ('john', 'john@test.com', 'john123');

INSERT INTO products (name, description, price, stock) VALUES
  ('Laptop', 'High-performance laptop for professionals', 999.99, 15),
  ('Mouse', 'Wireless mouse with precision tracking', 29.99, 50),
  ('Keyboard', 'Mechanical keyboard with RGB lighting', 89.99, 30),
  ('Monitor', '27-inch 4K UHD monitor', 399.99, 20),
  ('Headphones', 'Noise-cancelling wireless headphones', 199.99, 25),
  ('USB Hub', '7-port USB hub with fast charging', 49.99, 40),
  ('Webcam', '1080p HD webcam for streaming', 79.99, 35),
  ('External SSD', '1TB portable SSD storage', 129.99, 22);

CREATE USER IF NOT EXISTS 'sqli_eval'@'localhost' IDENTIFIED BY 'CHANGE_ME';
GRANT SELECT ON sqli_ml_eval.* TO 'sqli_eval'@'localhost';
FLUSH PRIVILEGES;
