<?php

/**
 * The admin-specific functionality of the plugin.
 *
 * @since      1.0.0
 *
 * @package    wp-vulnfinder
 * @subpackage wp-vulnfinder/admin
 */

/**
 * The admin-specific functionality of the plugin.
 *
 * Defines the plugin name, version, and two examples hooks for how to
 * enqueue the admin-specific stylesheet and JavaScript.
 *
 * @package    wp-vulnfinder
 * @subpackage wp-vulnfinder/admin
 */
class wp_vulnfinder_widget {

	/**
	 * The ID of this plugin.
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      string    $plugin_name    The ID of this plugin.
	 */
	const NAME = "wp-vulnfinder_widget";

	/**
	 * The version of this plugin.
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      string    $version    The current version of this plugin.
	 */
	private $version;

	/**
	 * Initialize the class and set its properties.
	 *
	 * @since    1.0.0
	 * @param      string    $plugin_name       The name of this plugin.
	 * @param      string    $version    The version of this plugin.
	 */
	 
	 protected $loader;
	 
	public function __construct($loader) {

		require_once plugin_dir_path( dirname( __FILE__ ) ) . 'includes/class-wp-vulnfinder-loader.php';
		
		$this->loader = $loader; 

	}

	/**
	 * Register the stylesheets for the admin area.
	 *
	 * @since    1.0.0
	 */
	public function activate() {
		$this->loader->add_action( 'wp_dashboard_setup', __CLASS__, 'register_dashboard' );
	}

	public function register_dashboard() {
		wp_add_dashboard_widget( 'vulnfinder_widget', self :: NAME , array(__CLASS__, 'vulnfinder_dashboard_widget') );
	}

	public function vulnfinder_dashboard_widget() {
		echo 'Hey ! it\'s me your widget.';
	}
}
