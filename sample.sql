SELECT 
  vuln_file_log.id, path, detected_on,
  HEX(vuln_digest_status.digest) AS digest, vuln_status.status AS `status` 
FROM vuln_file_log 
  INNER JOIN vuln_digest_status ON vuln_file_log.digest_id = vuln_digest_status.id
  INNER JOIN vuln_status ON vuln_digest_status.status_id = vuln_status.id
;
SELECT * FROM `vuln_status`;
SELECT * FROM `vuln_digest_status`;
SELECT * FROM `vuln_file_log`;
