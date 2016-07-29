<?php	

//Sécurité en cas d'accès direct
if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly
}

/**
 * Fired during plugin activation.
 *
 * This class defines all code necessary to run during the plugin's activation.
 *
 * @since      1.0.0
 * @package    wp_vulnfinder
 * @subpackage wp_vulnfinder/includes
 */
class wp_vulnfinder_Activator {

	/**
	 * Contain everything needed to install the plugin
	 *
	 * Long Description.
	 *
	 * @since    1.0.0
	 */
	
	public static function activate() {
		self::activation_api();
		self::activation_scan();
	}
	
	protected static function activation_scan() {
		
		require_once plugin_dir_path( dirname( __FILE__ ) ) . 'admin/class-wp-vulnfinder-scan.php';
		require_once plugin_dir_path( dirname( __FILE__ ) ) . 'admin/class-wp-vulnfinder-api.php';
		
		$scan = new wp_vulnfinder_scan();
		$api = new wp_vulnfinder_api("wp-vulnfinder", "1.0.0");
		
		add_action('vuln_cron_file_log_event', array($scan, 'vuln_cron_file_log'));
		add_action('vuln_cron_api_get', array($api, 'vuln_cron_get_api'));
		wp_schedule_event(time() + 10, 'hourly', 'vuln_cron_file_log_event');
		wp_schedule_event(time() + 10, 'hourly', 'vuln_cron_api_get');
	}
	
	
	protected static function activation_api(){
		/**
		 * \file create_bd.php
		 * Contient le code pour la création des tables dans la BD de wordpress.
		 * \author Julien Aspirot <julien.aspirot@usherbrooke.ca>
		 * \brief  Contient le code pour la création des tables dans la BD de wordpress.
		 * \date 26/07/2016
		 * \copyright IFT606 - WPVulz
		 *
		 */
		 
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
			reference TEXT CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
			vuln_type TINYTEXT CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
			fixed_in TINYTEXT CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
			
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
			reference TEXT CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
			vuln_type TINYTEXT CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
			fixed_in TINYTEXT CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,

			PRIMARY KEY (id)
			);");
		}
		//Fin de la création des tables pour la BD
	}

}
