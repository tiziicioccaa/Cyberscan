USE cyberscan_db;

ALTER TABLE scan_logs MODIFY target_value VARCHAR(2048) NOT NULL;
