<?php
/*
Plugin Name: vuln
Description: Testing
Author: Patate en chaleur
Version: 1000.3
*/
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

function vuln_pdo_print_file_log($pdo) {
  $sql = '
    SELECT 
      vuln_file_log.id AS id, path, detected_on, HEX(path_digest) AS path_digest,
      HEX(vuln_digest_status.digest) AS digest, vuln_status.status AS `status` 
    FROM vuln_file_log 
      INNER JOIN vuln_digest_status ON vuln_file_log.digest_id = vuln_digest_status.id
      INNER JOIN vuln_status ON vuln_digest_status.status_id = vuln_status.id
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
      vuln_file_log.id AS id, path, detected_on, what,
      HEX(vuln_digest_status.digest) AS digest, vuln_status.status AS `status` 
    FROM vuln_file_event
      INNER JOIN vuln_file_log ON vuln_file_event.file_log_id = vuln_file_log.id 
      INNER JOIN vuln_digest_status ON vuln_file_log.digest_id = vuln_digest_status.id
      INNER JOIN vuln_status ON vuln_digest_status.status_id = vuln_status.id
    ORDER BY detected_on DESC, vuln_file_log.id ASC
    ;
  ';
  try {
    echo "id\tdetected_on\tdigest\tpath\twhat\tstatus\n";
    foreach ($pdo->query($sql) as $row) {
      echo $row['id'], "\t";
      echo $row['detected_on'], "\t";
      echo $row['digest'], "\t";
      echo $row['path'], "\t";
      echo $row['what'], "\t";
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
      ('safe'),
      ('unsafe'),
      ('pending'),
      ('unknown')
    ;
    CREATE TABLE `vuln_digest_status` (
      `id` int unsigned not null auto_increment,
      `digest` binary(16) not null,
      `status_id` int unsigned not null,
      primary key (`id`),
      index `vuln_digest_status_idx_status_id` (`status_id`),
      foreign key (`status_id`)
        references `vuln_status` (`id`)
        on delete restrict
        on update cascade
    );
    INSERT INTO `vuln_digest_status`
      (`digest`, `status_id`)
    VALUES
      (UNHEX('e3fc50a88d0a364313df4b21ef20c29e'), 1)
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
    INSERT INTO `vuln_file_log`
      (`path`, `detected_on`, `digest_id`)
    VALUES
      ('/home', '2013-08-05 18:19:03', 1)
    ;
    CREATE TABLE `vuln_file_log_cron` (
      `id` int unsigned not null auto_increment,
      `cron_on` timestamp not null,
      primary key (`id`)
    );
    CREATE TABLE `vuln_file_event` (
      `id` int unsigned not null auto_increment,
      `what` varchar(4096) not null,
      `file_log_id` int unsigned not null,
      primary key (`id`),
      index `vuln_file_log_idx_file_log_id` (`file_log_id`),
      foreign key (`file_log_id`)
        references `vuln_file_log` (`id`)
        on delete cascade
        on update cascade
    );
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

function vuln_pdo_log_digest_unsafe($pdo, $file_digest) {
  $stmt = $pdo->prepare("INSERT INTO `vuln_digest_status` (`digest`, `status_id`) VALUES (:digest, 3) ON DUPLICATE KEY UPDATE digest=digest");
  $stmt->bindParam(':digest', $file_digest);
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

function vuln_pdo_log_file($pdo, $file_name) {
  try {
    $file_digest = md5_file($file_name, true);
    $path_digest = md5($file_name, true);
    $digest_id = vuln_pdo_log_digest_unsafe($pdo, $file_digest);
    $path_digest_exists = vuln_pdo_get_file_log_unsafe($pdo, $path_digest);
    if (!$path_digest_exists) {
      $file_log_id = vuln_pdo_log_file_new_unsafe($pdo, $file_name, $path_digest, $digest_id);
      vuln_pdo_log_file_event_unsafe($pdo,
        'file created between patrols',
        $file_log_id);
    } else if ($path_digest_exists['digest'] !== $file_digest) {
      $file_log_id = vuln_pdo_log_file_change_unsafe($pdo, $file_name, $path_digest, $digest_id);
      vuln_pdo_log_file_event_unsafe($pdo,
        'file changed between patrols, previous digest was ' . $path_digest_exists['digest'],
        $file_log_id);
    } else {
      // no change -> no-op
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
}

function vuln_cron_file_log() {
  $pdo = vuln_pdo_create();
  vuln_pdo_log_cron_unsafe($pdo);

  $wp_file_list = vuln_find(ABSPATH);
  $wp_file_list = array_slice($wp_file_list, 0, 100);
  foreach ($wp_file_list as $wp_file) {
    vuln_pdo_log_file($pdo, $wp_file);
  }
}

function vuln_cron_xforce() {
  $api_key = 'f49542f6-59fa-4a87-96c6-0775f7714d8f';
  $api_pwd = 'eee3870a-e8ab-4a01-83a9-4c024b509ecd';
}

function vuln_admin_init() {
  echo "<pre>";
  $pdo = vuln_pdo_create();
  //vuln_pdo_reset($pdo);
  
  $vuln_table_exists = vuln_pdo_table_exists($pdo, 'vuln_status');
  if (!$vuln_table_exists) {
    vuln_pdo_create_tables($pdo);
  }

  $wp_file_list = vuln_find(ABSPATH);
  $wp_file_list = array_slice($wp_file_list, 0, 100);
  foreach ($wp_file_list as $wp_file) {
    vuln_pdo_log_file($pdo, $wp_file);
  }
  vuln_pdo_print_file_event($pdo);
  vuln_pdo_print_file_log($pdo);
  echo "</pre>";
}
?>
