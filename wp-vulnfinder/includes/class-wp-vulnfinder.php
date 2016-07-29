<?php

/**
 * The file that defines the core plugin class
 */

/**
 * The core plugin class.
 *
 * This is used to define internationalization, admin-specific hooks, and
 *
 * Also maintains the unique identifier of this plugin as well as the current
 * version of the plugin.
 *
 * @since      1.0.0
 * @package    wp-vulnfinder
 * @subpackage wp-vulnfinder/includes
 */
class wp_vulnfinder {

	/**
	 * The loader that's responsible for maintaining and registering all hooks that power
	 * the plugin.
	 *
	 * @since    1.0.0
	 * @access   protected
	 * @var      Plugin_Name_Loader    $loader    Maintains and registers all hooks for the plugin.
	 */
	protected $loader;

	/**
	 * The unique identifier of this plugin.
	 *
	 * @since    1.0.0
	 * @access   protected
	 * @var      string    $plugin_name    The string used to uniquely identify this plugin.
	 */
	protected $wp_vulnfinder;

	/**
	 * The current version of the plugin.
	 *
	 * @since    1.0.0
	 * @access   protected
	 * @var      string    $version    The current version of the plugin.
	 */
	protected $version;

	/**
	 * Define the core functionality of the plugin.
	 *
	 * Set the plugin name and the plugin version that can be used throughout the plugin.
	 * Load the dependencies, define the locale, and set the hooks for the admin area and
	 * the public-facing side of the site.
	 *
	 * @since    1.0.0
	 */
	public function __construct() {

		$this->plugin_name = 'wp-vulnfinder';
		$this->version = '1.0.0';

		$this->load_dependencies();
		$this->define_admin_hooks();
		$this->define_widget();
		$this->define_scan();

	}

	/**
	 * Load the required dependencies for this plugin.
	 *
	 * Include the following files that make up the plugin:
	 *
	 * Create an instance of the loader which will be used to register the hooks
	 * with WordPress.
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function load_dependencies() {

		/**
		 * The class responsible for orchestrating the actions and filters of the
		 * core plugin.
		 */
		require_once plugin_dir_path( dirname( __FILE__ ) ) . 'includes/class-wp-vulnfinder-loader.php';


		/**
		 * The class responsible for defining all actions that occur in the admin area.
		 */
		require_once plugin_dir_path( dirname( __FILE__ ) ) . 'admin/class-wp-vulnfinder-admin.php';
		
		/**
		 * The class responsible for defining all actions that occur in the scan area.
		 */
		require_once plugin_dir_path( dirname( __FILE__ ) ) . 'admin/class-wp-vulnfinder-scan.php';

		/**
		*The class responsible for the widget controller
		*of the plugin.
		*/
		require_once plugin_dir_path( dirname( __FILE__ ) ) . 'includes/class-wp-vulnfinder-widget.php';

		$this->loader = new wp_vulnfinder_Loader();

	}

	/**
	 * Register all of the hooks related to the admin area functionality
	 * of the plugin.
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function define_admin_hooks() {

		$plugin_admin = new wp_vulnfinder_Admin( $this->get_plugin_name(), $this->get_version() );

		$this->loader->add_action( 'admin_enqueue_scripts', $plugin_admin, 'enqueue_styles' );
		$this->loader->add_action( 'admin_enqueue_scripts', $plugin_admin, 'enqueue_scripts' );
		$this->loader->add_action( 'admin_menu', $plugin_admin, 'vulnfinder_admin_menu');

	}

	/**
	 * Register all of the hooks related to the widget
	 * of the plugin.
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function define_widget() {
		$widget = new wp_vulnfinder_widget($this->loader);
		
		$widget->activate();
	}
	
	/**
	 * Register all of the hooks related to the scan cron job
	 * of the plugin.
	 *
	 * @since    1.0.0
	 * @access   private
	 */
	private function define_scan() {
		
		$timestamp = wp_next_scheduled('create_update_lookup');
		
		if ( $timestamp == false ){
			
			$plugin_admin = new wp_vulnfinder_Admin( $this->get_plugin_name(), $this->get_version() );
			
			wp_schedule_event( time(), 'hourly', 'create_update_lookup');
			$this->loader->add_action( 'create_update_lookup', $plugin_admin, 'update_lookup');
		}

		$scan = new wp_vulnfinder_scan();
		$this->loader->add_action( 'template_redirect', $scan, 'vuln_wp_error_detection' );
		
	}

	/**
	 * Run the loader to execute all of the hooks with WordPress.
	 *
	 * @since    1.0.0
	 */
	public function run() {
		$this->loader->run();
	}

	/**
	 * The name of the plugin used to uniquely identify it within the context of
	 * WordPress and to define internationalization functionality.
	 *
	 * @since     1.0.0
	 * @return    string    The name of the plugin.
	 */
	public function get_plugin_name() {
		return $this->plugin_name;
	}

	/**
	 * The reference to the class that orchestrates the hooks with the plugin.
	 *
	 * @since     1.0.0
	 * @return    Plugin_Name_Loader    Orchestrates the hooks of the plugin.
	 */
	public function get_loader() {
		return $this->loader;
	}

	/**
	 * Retrieve the version number of the plugin.
	 *
	 * @since     1.0.0
	 * @return    string    The version number of the plugin.
	 */
	public function get_version() {
		return $this->version;
	}

}
