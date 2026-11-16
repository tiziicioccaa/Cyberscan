-- Selecciona la base donde vive el historial del plugin.
USE cyberscan_db;

-- Amplía el campo para aceptar URLs largas sin cambiar el resto de la tabla.
ALTER TABLE scan_logs MODIFY target_value VARCHAR(2048) NOT NULL;
