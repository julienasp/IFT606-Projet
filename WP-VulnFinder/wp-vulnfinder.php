<?php

/**

 * @wordpress_plugin
 * Plugin Name:       wp_vulnfinder
 * Plugin URI:        http://igl711_a15_51_ja.espaceweb.usherbrooke.ca/
 * Description:       find vuln in wordpress
 * Version:           1.0.0
 * Author:            wp_vulnfinder
 * Author URI:        http://igl711_a15_51_ja.espaceweb.usherbrooke.ca/
 * License:           GPL_2.0+
 * License URI:       http://www.gnu.org/licenses/gpl_2.0.txt
 * Text Domain:       wp_vulnfinder
 * Domain Path:       /languages
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * The code that runs during plugin activation.
 * This action is documented in includes/class_plugin_name_activator.php
 */
function activate_wp_vulnfinder() {
	require_once plugin_dir_path( __FILE__ ) . 'includes/class-wp-vulnfinder-activator.php';
	wp_vulnfinder_Activator::activate();
}

/**
 * The code that runs during plugin deactivation.
 * This action is documented in includes/class_plugin_name_deactivator.php
 */
function deactivate_wp_vulnfinder() {
	require_once plugin_dir_path( __FILE__ ) . 'includes/class-wp-vulnfinder-deactivator.php';
	wp_vulnfinder_Deactivator::deactivate();
}

register_activation_hook( __FILE__, 'activate_wp_vulnfinder' );
register_deactivation_hook( __FILE__, 'deactivate_wp_vulnfinder' );

/**
 * The core plugin class that is used to define internationalization,
 * admin_specific hooks, and public_facing site hooks.
 */
require plugin_dir_path( __FILE__ ) . 'includes/class-wp-vulnfinder.php';

/**
 * Begins execution of the plugin.
 *
 * Since everything within the plugin is registered via hooks,
 * then kicking off the plugin from this point in the file does
 * not affect the page life cycle.
 *
 * @since    1.0.0
 */
function run_wp_vulnfinder() {

	$plugin = new wp_vulnfinder();
	$plugin->run();

}
run_wp_vulnfinder();
