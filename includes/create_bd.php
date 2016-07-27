<?php
/**
 * \file create_bd.php
 * Contient le code pour la création des tables dans la BD de wordpress.
 * \author Julien Aspirot <julien.aspirot@usherbrooke.ca>
 * \brief  Contient le code pour la création des tables dans la BD de wordpress.
 * \date 26/07/2016
 * \copyright IFT606 - WPVulz
 *
 */

//Sécurité en cas d'accès direct
if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly
}

//Variable global pour l'accès à la base de données
global $wpdb;

//Création des tables pour les vulnérabilités

//On valide que la table wordpress_vulnerabilities n'existe pas et si c'est le cas alors on la fabrique
if ($wpdb->get_var("SHOW TABLES LIKE '{$wpdb->prefix}wordpress_vulnerabilities'") != $wpdb->prefix . 'wordpress_vulnerabilities'){
    $wpdb->query("CREATE TABLE {$wpdb->prefix}wordpress_vulnerabilities (
	id integer not null auto_increment,
	vuldbapi_id integer not null,
	title TINYTEXT CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
	wordpress_version TINYTEXT CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,	
	references TEXT CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
	vuln_type TINYTEXT CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
	fixed_in TINYTEXT CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
	raw_json TEXT CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
	
	PRIMARY KEY (id)
	);");
}

//On valide que la table plugins_vulnerabilities n'existe pas et si c'est le cas alors on la fabrique
if ($wpdb->get_var("SHOW TABLES LIKE '{$wpdb->prefix}plugins_vulnerabilities'") != $wpdb->prefix . 'plugins_vulnerabilities'){
    $wpdb->query("CREATE TABLE {$wpdb->prefix}plugins_vulnerabilities (
	id integer not null auto_increment,
	vuldbapi_id integer not null,
	title TINYTEXT CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
	plugin_name TINYTEXT CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
	plugin_version TINYTEXT CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,	
	references TEXT CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
	vuln_type TINYTEXT CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
	fixed_in TINYTEXT CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
	raw_json TEXT CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,

	PRIMARY KEY (id)
	);");
}
//Fin de la création des tables pour la BD