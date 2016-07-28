<?php
/*
Plugin Name: vuln
Description: Testing
Author: Guillaume Xavier Taillon
Version: 10734.49
*/

if (!defined(ABSPATH)) {
  echo "go away";
  //exit;
}

add_action('admin_menu', 'vuln_admin_setup_menu');
function vuln_admin_setup_menu() {
  add_menu_page('Vuln debug', 'Vuln', 'manage_options', 'vuln-plugin', 'vuln_admin_init');
}

register_activation_hook(__FILE__, 'vuln_activation');
add_action('vuln_cron_file_log_event', 'vuln_cron_file_log');
function vuln_activation() {
  wp_schedule_event(time() + 10, 'hourly', 'vuln_cron_file_log_event');
}

register_deactivation_hook(__FILE__, 'vuln_deactivation');
function vuln_deactivation() {
  wp_clear_scheduled_hook('vuln_cron_file_log_event');
}

add_action('template_redirect', 'vuln_wp_error_detection');
function vuln_wp_error_detection() {
  if (is_404()) {
    
  }
}

function vuln_pdo_print_file_log($pdo) {
  $sql = '
    SELECT 
      vuln_file_log.id AS id, path, detected_on, HEX(path_digest) AS path_digest,
      HEX(vuln_digest_status.digest) AS digest, vuln_status.status AS `status` 
    FROM vuln_file_log 
      INNER JOIN vuln_digest_status ON vuln_file_log.digest_id = vuln_digest_status.id
      INNER JOIN vuln_status ON vuln_digest_status.status_id = vuln_status.id
    ORDER BY path
    ;
  ';
  try {
    echo "id\tdetected_on\tdigest\tpath_digest\tpath\tstatus\n";
    foreach ($pdo->query($sql) as $row) {
      echo $row['id'], "\t";
      echo $row['detected_on'], "\t";
      echo $row['digest'], "\t";
      echo $row['path_digest'], "\t";
      echo $row['path'], "\t";
      echo $row['status'], "\n";
    }
  } catch(PDOException $e) {
    echo $e->getMessage();
    echo $e->getTraceAsString();
  }
}

function vuln_pdo_print_file_event($pdo) {
  $sql = '
    SELECT 
      `vuln_file_event`.`id` as `id`, `path`, `when`, `what`
    FROM `vuln_file_event`
      INNER JOIN `vuln_file_log` ON `vuln_file_event`.`file_log_id` = `vuln_file_log`.`id` 
    ORDER BY `when` DESC, `path` ASC 
    ;
  ';
  try {
    echo "id\twhen\tpath\twhat\n";
    foreach ($pdo->query($sql) as $row) {
      echo $row['id'], "\t";
      echo $row['when'], "\t";
      echo $row['path'], "\t";
      echo $row['what'], "\n";
    }
  } catch(PDOException $e) {
    echo $e->getMessage();
    echo $e->getTraceAsString();
  }
}

function vuln_pdo_print_digest_status($pdo) {
  $sql = '
    SELECT
      vuln_digest_status.id AS id, HEX(vuln_digest_status.digest) AS digest, vuln_status.status AS `status` 
    FROM vuln_digest_status
      INNER JOIN vuln_status ON vuln_digest_status.status_id = vuln_status.id
    ;
  ';
  try {
    echo "id\tdigest\tstatus\n";
    foreach ($pdo->query($sql) as $row) {
      echo $row['id'], "\t";
      echo $row['digest'], "\t";
      echo $row['status'], "\n";
    }
  } catch(PDOException $e) {
    echo $e->getMessage();
    echo $e->getTraceAsString();
  }
}

function vuln_pdo_create_tables($pdo) {
  $sql ="
    CREATE TABLE `vuln_status` (
      `id` int unsigned not null auto_increment,
      `status` varchar(8),
      primary key (`id`)
    );
    INSERT INTO `vuln_status`
      (`status`)
    VALUES
      ('clean'),
      ('unsafe'),
      ('pending'),
      ('unknown')
    ;
    CREATE TABLE `vuln_digest_status` (
      `id` int unsigned not null auto_increment,
      `digest` binary(16) not null unique,
      `status_id` int unsigned not null,
      primary key (`id`),
      index `vuln_digest_status_idx_digest` (`digest`),
      index `vuln_digest_status_idx_status_id` (`status_id`),
      foreign key (`status_id`)
        references `vuln_status` (`id`)
        on delete restrict
        on update cascade
    );
    INSERT INTO `vuln_digest_status`
      (`digest`, `status_id`)
    VALUES
      (UNHEX('D41D8CD98F00B204E9800998ECF8427E'), 1)
    ;
    CREATE TABLE `vuln_file_log` (
      `id` int unsigned not null auto_increment,
      `path` varchar(4096) not null,
      `path_digest` binary(16) unique,
      `detected_on` timestamp not null,
      `digest_id` int unsigned not null,
      primary key (`id`),
      index `vuln_file_log_idx_path_digest` (`path_digest`),
      index `vuln_file_log_idx_digest_id` (`digest_id`),
      foreign key (`digest_id`)
        references `vuln_digest_status` (`id`)
        on delete restrict
        on update cascade
    );
    CREATE TABLE `vuln_file_log_cron` (
      `id` int unsigned not null auto_increment,
      `cron_on` timestamp not null,
      primary key (`id`)
    );
    CREATE TABLE `vuln_file_event` (
      `id` int unsigned not null auto_increment,
      `when` timestamp not null,
      `what` varchar(4096) not null,
      `file_log_id` int unsigned not null,
      primary key (`id`),
      index `vuln_file_log_idx_file_log_id` (`file_log_id`),
      foreign key (`file_log_id`)
        references `vuln_file_log` (`id`)
        on delete cascade
        on update cascade
    );
    CREATE TABLE `vuln_probing_event` (
      `id` int unsigned not null auto_increment,
      `when` timestamp not null,
      `who` varchar(255) not null,
      primary key (`id`),
    );
    // http://www.artfulsoftware.com/infotree/qrytip.php?id=552
    DELIMITER GO
    CREATE FUNCTION levenshtein( s1 VARCHAR(255), s2 VARCHAR(255) )
      RETURNS INT
      DETERMINISTIC
      BEGIN
        DECLARE s1_len, s2_len, i, j, c, c_temp, cost INT;
        DECLARE s1_char CHAR;
        -- max strlen=255
        DECLARE cv0, cv1 VARBINARY(256);
        SET s1_len = CHAR_LENGTH(s1), s2_len = CHAR_LENGTH(s2), cv1 = 0x00, j = 1, i = 1, c = 0;
        IF s1 = s2 THEN
          RETURN 0;
        ELSEIF s1_len = 0 THEN
          RETURN s2_len;
        ELSEIF s2_len = 0 THEN
          RETURN s1_len;
        ELSE
          WHILE j <= s2_len DO
            SET cv1 = CONCAT(cv1, UNHEX(HEX(j))), j = j + 1;
          END WHILE;
          WHILE i <= s1_len DO
            SET s1_char = SUBSTRING(s1, i, 1), c = i, cv0 = UNHEX(HEX(i)), j = 1;
            WHILE j <= s2_len DO
              SET c = c + 1;
              IF s1_char = SUBSTRING(s2, j, 1) THEN 
                SET cost = 0; ELSE SET cost = 1;
              END IF;
              SET c_temp = CONV(HEX(SUBSTRING(cv1, j, 1)), 16, 10) + cost;
              IF c > c_temp THEN SET c = c_temp; END IF;
                SET c_temp = CONV(HEX(SUBSTRING(cv1, j+1, 1)), 16, 10) + 1;
                IF c > c_temp THEN 
                  SET c = c_temp; 
                END IF;
                SET cv0 = CONCAT(cv0, UNHEX(HEX(c))), j = j + 1;
            END WHILE;
            SET cv1 = cv0, i = i + 1;
          END WHILE;
        END IF;
        RETURN c;
      END
    GO
    CREATE FUNCTION levenshtein_ratio( s1 VARCHAR(255), s2 VARCHAR(255) )
      RETURNS INT
      DETERMINISTIC
      BEGIN
        DECLARE s1_len, s2_len, max_len INT;
        SET s1_len = LENGTH(s1), s2_len = LENGTH(s2);
        IF s1_len > s2_len THEN 
          SET max_len = s1_len; 
        ELSE 
          SET max_len = s2_len; 
        END IF;
        RETURN ROUND((1 - LEVENSHTEIN(s1, s2) / max_len) * 100);
      END
    GO
    DELIMITER ;
    ;
  " ;
  try {
    $pdo->exec($sql);
  } catch(PDOException $e) {
    echo $e->getMessage();
    echo $e->getTraceAsString();
  }
}

function vuln_pdo_table_exists($pdo, $table) {
  try {
    // can't bind table!
    $stmt = $pdo->prepare("SELECT 1 FROM $table LIMIT 1");
    $stmt->execute();
    return true;
  } catch (PDOException $e) {
    return false;
  }
}

function vuln_pdo_table_empty($pdo, $table) {
  try {
    // can't bind table!
    $stmt = $pdo->prepare("SELECT 1 FROM $table LIMIT 1");
    $stmt->execute();
    return !$stmt->fetchColumn();
  } catch (PDOException $e) {
    return false;
  }
}

function vuln_pdo_drop_table($pdo, $table) {
  try {
    // can't bind a table name!
    $stmt = $pdo->prepare("DROP TABLE IF EXISTS $table");
    $stmt->execute();
  } catch (PDOException $e) {
    echo $e->getMessage();
    echo $e->getTraceAsString();
  }
}

function vuln_pdo_reset($pdo) {
  try {
    $stmt = $pdo->prepare("SET foreign_key_checks = 0");
    $stmt->execute();

    $query = $pdo->query("SHOW TABLES");
    $tables = $query->fetchAll(PDO::FETCH_COLUMN);
    foreach ($tables as $table) {
      $prefix = substr($table, 0, 5);
      if ($prefix === "vuln_") {
        vuln_pdo_drop_table($pdo, $table);
      }
    }

    $stmt = $pdo->prepare("SET foreign_key_checks = 1");
    $stmt->execute();
  } catch(PDOException $e) {
    echo $e->getMessage();
    echo $e->getTraceAsString();
  }
}

function vuln_find($dir) {
  $result = array();
  $current_dir = scandir($dir);
  foreach ($current_dir as $file) {
    $path = $dir . DIRECTORY_SEPARATOR . $file;
    $result[] = $path;
    $is_ref = in_array($file, array(".",".."));
    $is_dir = is_dir($path);
    if (!$is_ref && $is_dir) {
      $sub_dir = vuln_find($path);
      $result = array_merge($result, $sub_dir);
    }
  }
  return $result;
}

function print_array($arr) {
  foreach ($arr as $val) {
    echo $val, "\n";
  }
}

function vuln_pdo_log_digest_unsafe($pdo, $file_digest, $status_id = 4) {
  $stmt = $pdo->prepare("INSERT INTO `vuln_digest_status` (`digest`, `status_id`) VALUES (:digest, :status_id) ON DUPLICATE KEY UPDATE `status_id` = IF(`status_id` = 3, :status_id, `status_id`), `id` = LAST_INSERT_ID(`id`)");
  $stmt->bindParam(':digest', $file_digest);
  $stmt->bindParam(':status_id', $status_id);
  $stmt->execute();
  return $pdo->lastInsertId('id');
}

function vuln_pdo_get_file_log_unsafe($pdo, $path_digest) {
  $stmt = $pdo->prepare("
    SELECT `vuln_digest_status`.`digest` as `digest`
    FROM `vuln_file_log`
      INNER JOIN `vuln_digest_status` ON `vuln_file_log`.`digest_id` = `vuln_digest_status`.`id`
    WHERE `path_digest` = :path_digest");
  $stmt->bindParam(':path_digest', $path_digest);
  $stmt->execute();
  return $stmt->fetch();
}

function vuln_pdo_log_file_event_unsafe($pdo, $what, $file_log_id) {
  $stmt = $pdo->prepare("INSERT INTO `vuln_file_event` (`what`, `file_log_id`) VALUES (:what, :file_log_id)");
  $stmt->bindParam(':what', $what);
  $stmt->bindParam(':file_log_id', $file_log_id);
  $stmt->execute();
}

function vuln_pdo_log_file_new_unsafe($pdo, $file_name, $path_digest, $digest_id) {
  $stmt = $pdo->prepare("INSERT INTO `vuln_file_log` (`path`, `path_digest`, `detected_on`, `digest_id`) VALUES (:path, :path_digest, now(), :digest_id)");
  $stmt->bindParam(':path', $file_name);
  $stmt->bindParam(':path_digest', $path_digest);
  $stmt->bindParam(':digest_id', $digest_id);
  $stmt->execute();
  return $pdo->lastInsertId('id');
}

function vuln_pdo_log_file_change_unsafe($pdo, $file_name, $path_digest, $digest_id) {
  $stmt = $pdo->prepare("INSERT INTO `vuln_file_log` (`path`, `path_digest`, `detected_on`, `digest_id`) VALUES (:path, :path_digest, now(), :digest_id) ON DUPLICATE KEY UPDATE `digest_id` = :digest_id");
  $stmt->bindParam(':path', $file_name);
  $stmt->bindParam(':path_digest', $path_digest);
  $stmt->bindParam(':digest_id', $digest_id);
  $stmt->execute();
  return $pdo->lastInsertId('id');
}

function vuln_pdo_log_file_same_unsafe($pdo, $path_digest) {
  $stmt = $pdo->prepare("UPDATE `vuln_file_log` SET `detected_on` = now() WHERE `path_digest` = :path_digest");
  $stmt->bindParam(':path_digest', $path_digest);
  $stmt->execute();
}

function vuln_pdo_log_file($pdo, $file_name, $log_event = true) {
  try {
    $file_digest = md5_file($file_name, true);
    $path_digest = md5($file_name, true);
    $digest_id = vuln_pdo_log_digest_unsafe($pdo, $file_digest);
    $path_digest_exists = vuln_pdo_get_file_log_unsafe($pdo, $path_digest);
    if (!$path_digest_exists) {
      $file_log_id = vuln_pdo_log_file_new_unsafe($pdo, $file_name, $path_digest, $digest_id);
      if ($log_event) {
        vuln_pdo_log_file_event_unsafe($pdo,
          'file created between patrols, () -> (' . strtoupper(bin2hex($file_digest)) . ')',
          $file_log_id);
      }
    } else if ($path_digest_exists['digest'] !== $file_digest) {
      $file_log_id = vuln_pdo_log_file_change_unsafe($pdo, $file_name, $path_digest, $digest_id);
      if ($log_event) {
        vuln_pdo_log_file_event_unsafe($pdo,
          'file changed between patrols, (' . strtoupper(bin2hex($path_digest_exists['digest'])) . ') -> (' . strtoupper(bin2hex($file_digest)) . ')',
          $file_log_id);
      }
    } else {
      vuln_pdo_log_file_same_unsafe($pdo, $path_digest);
    }
    return true;
  } catch (PDOException $e) {
    echo $e->getMessage();
    echo $e->getTraceAsString();
    return false;
  }
}

function vuln_pdo_create() {
  $dsn = 'mysql:host=localhost;dbname=igl711-a15_02095';
  $username = 'igl711-a15.02095';
  $password = 'W?Dj>jrlE0D44C!B3!LO';
  $options = array(
    PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES utf8',
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
  ); 
  try {
    $pdo = new PDO($dsn, $username, $password, $options);
    return $pdo;
  } catch(PDOException $e) {
    echo $e->getMessage();
    echo $e->getTraceAsString();
  }
}

function vuln_pdo_log_cron_unsafe($pdo) {
  $stmt = $pdo->prepare("INSERT INTO `vuln_file_log_cron` (`cron_on`) VALUES (now())");
  $stmt->execute();
  return $pdo->lastInsertId('id');
}

function vuln_pdo_get_last_cron_unsafe($pdo) {
  $stmt = $pdo->prepare("SELECT MAX(`cron_on`) FROM `vuln_file_log_cron`");
  $stmt->bindParam(':path_digest', $path_digest);
  $stmt->execute();
  return $stmt->fetchColumn();
}

function vuln_pdo_log_file_missing_unsafe($pdo, $before, $after) {
  $stmt = $pdo->prepare("
    SELECT `vuln_file_log`.`id` AS `id`, HEX(`vuln_digest_status`.`digest`) AS `digest`
    FROM `vuln_file_log`
      INNER JOIN `vuln_digest_status` ON `vuln_file_log`.`digest_id` = `vuln_digest_status`.`id`
    WHERE `detected_on` >= :before AND `detected_on` < :after");
  $stmt->bindParam(':before', $before);
  $stmt->bindParam(':after', $after);
  $stmt->execute();

  while ($file_log = $stmt->fetch()) {
      vuln_pdo_log_file_event_unsafe($pdo,
        'file removed between patrols, (' . $file_log['digest'] . ') -> ()',
        $file_log['id']);
  }
}

function vuln_cron_file_log() {
  $pdo = vuln_pdo_create();
  $last_cron_on = vuln_pdo_get_last_cron_unsafe($pdo);
  vuln_pdo_log_cron_unsafe($pdo);
  $current_cron_on = vuln_pdo_get_last_cron_unsafe($pdo);

  $not_first_run = !vuln_pdo_table_empty($pdo, 'vuln_file_log');
  $wp_file_list = vuln_find(ABSPATH);
  $wp_file_list = array_slice($wp_file_list, 0, 100); // LIMIT
  foreach ($wp_file_list as $wp_file) {
    vuln_pdo_log_file($pdo, $wp_file, $not_first_run);
  }
  if ($not_first_run) {
    vuln_pdo_log_file_missing_unsafe($pdo, $last_cron_on, $current_cron_on);
  }
}

function vuln_cron_xforce() {
  $api_key = 'f49542f6-59fa-4a87-96c6-0775f7714d8f';
  $api_pwd = 'eee3870a-e8ab-4a01-83a9-4c024b509ecd';
}

function vuln_pdo_load_md5($pdo) {
  $md5_file = plugin_dir_path(__FILE__) . 'unpacked_hashes.md5';
  $file_handle = fopen($md5_file, 'r');
  fgets($file_handle); // discard first line (header)
  $i = 0; // LIMIT
  try {
    while (!feof($file_handle) /**/&& $i++ < 100/**/) {
      $line = fgets($file_handle);
      $original_md5_str = substr($line, 0, 32);
      $original_md5 = hex2bin($original_md5_str);
      vuln_pdo_log_digest_unsafe($pdo, $original_md5, 2);

      $unpacked_md5_str = substr($line, 32+2, 32);
      $unpacked_md5 = hex2bin($unpacked_md5_str);
      vuln_pdo_log_digest_unsafe($pdo, $unpacked_md5, 2);
    }
  } catch(PDOException $e) {
    echo $e->getMessage();
    echo $e->getTraceAsString();
  }
  fclose($file_handle);
}

function vuln_admin_init() {
  echo "<pre>";
  $pdo = vuln_pdo_create();
  //vuln_pdo_reset($pdo);
  
  $vuln_table_exists = vuln_pdo_table_exists($pdo, 'vuln_status');
  if (!$vuln_table_exists) {
    vuln_pdo_create_tables($pdo);
  }
  vuln_pdo_load_md5($pdo);
  vuln_cron_file_log();
  vuln_pdo_print_digest_status($pdo);
  vuln_pdo_print_file_event($pdo);
  vuln_pdo_print_file_log($pdo);
  echo "</pre>";
}
?>
