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

function vuln_admin_init() {
  $dsn = 'mysql:host=localhost;dbname=igl711-a15_02095';
  $username = 'igl711-a15.02095';
  $password = 'W?Dj>jrlE0D44C!B3!LO';
  $options = array(
    PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES utf8',
  ); 
  $pdo = new PDO($dsn, $username, $password, $options);

  $statement = $pdo->query("SELECT 'Hello, dear MySQL user!' AS _message FROM DUAL");
  $row = $statement->fetch(PDO::FETCH_ASSOC);
  echo htmlentities($row['_message']);
}
/*
$table = "tcompany";
try {
     $db = new PDO("mysql:dbname=mydb;host=localhost", "root", "" );
     $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );//Error Handling
     $sql ="CREATE table $table(
     ID INT( 11 ) AUTO_INCREMENT PRIMARY KEY,
     Prename VARCHAR( 50 ) NOT NULL, 
     Name VARCHAR( 250 ) NOT NULL,
     StreetA VARCHAR( 150 ) NOT NULL, 
     StreetB VARCHAR( 150 ) NOT NULL, 
     StreetC VARCHAR( 150 ) NOT NULL, 
     County VARCHAR( 100 ) NOT NULL,
     Postcode VARCHAR( 50 ) NOT NULL,
     Country VARCHAR( 50 ) NOT NULL);" ;
     $db->exec($sql);
     print("Created $table Table.\n");

} catch(PDOException $e) {
    echo $e->getMessage();//Remove or change message in production code
}
*/
?>

