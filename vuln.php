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

function vuln_pdo_print_file_log($pdo) {
  $sql = '
    SELECT 
      vuln_file_log.id AS id, path, detected_on,
      HEX(vuln_digest_status.digest) AS digest, vuln_status.status AS `status` 
    FROM vuln_file_log 
      INNER JOIN vuln_digest_status ON vuln_file_log.digest_id = vuln_digest_status.id
      INNER JOIN vuln_status ON vuln_digest_status.status_id = vuln_status.id
    ;
  ';
  foreach ($pdo->query($sql) as $row) {
      echo $row['id'], "\t";
      echo $row['path'], "\t";
      echo $row['detected_on'], "\t";
      echo $row['status'], "\t";
      echo $row['digest'], "\n";
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
      ('pending')
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
      `path` VARCHAR(4096) not null,
      `detected_on` TIMESTAMP not null,
      `digest_id` int unsigned not null,
      primary key (`id`),
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
  " ;
  try {
    $pdo->exec($sql);
  } catch(PDOException $e) {
    echo $e->getMessage();
  }
}

function vuln_pdo_table_exists($pdo, $table) {
  try {
    $result = $pdo->query("SELECT 1 FROM $table LIMIT 1");
    return true;
  } catch (PDOException $e) {
    return false;
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

function vuln_admin_init() {
  $dsn = 'mysql:host=localhost;dbname=igl711-a15_02095';
  $username = 'igl711-a15.02095';
  $password = 'W?Dj>jrlE0D44C!B3!LO';
  $options = array(
    PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES utf8',
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
  ); 
  try {
    $pdo = new PDO($dsn, $username, $password, $options);
  } catch(PDOException $e) {
    echo $e->getMessage();//Remove or change message in production code
  }
  $vuln_table_exists = vuln_pdo_table_exists($pdo, 'vuln_status');
  if (!vuln_table_exists) {
    vuln_pdo_create_tables($pdo);
  }
  echo "<pre>";
  vuln_pdo_print_file_log($pdo);

  $wp_file_list = vuln_find(ABSPATH);
  print_array($wp_file_list);
  echo "</pre>";
}
?>

