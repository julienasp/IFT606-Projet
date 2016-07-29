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
class wp_vulnfinder_Admin {

	/**
	 * The ID of this plugin.
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      string    $plugin_name    The ID of this plugin.
	 */
	private $plugin_name;

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
	public function __construct( $plugin_name, $version ) {

		$this->plugin_name = $plugin_name;
		$this->version = $version;

	}

	/**
	 * Register the stylesheets for the admin area.
	 *
	 * @since    1.0.0
	 */
	public function enqueue_styles() {

		wp_enqueue_style( $this->plugin_name, plugin_dir_url( __FILE__ ) . 'css/wp-vulnfinder-admin.css', array(), $this->version, 'all' );

	}

	/**
	 * Register the JavaScript for the admin area.
	 *
	 * @since    1.0.0
	 */
	public function enqueue_scripts() {

		wp_enqueue_script( $this->plugin_name, plugin_dir_url( __FILE__ ) . 'js/wp-vulnfinder-admin.js', array( 'jquery' ), $this->version, false );

	}
	
	public function vulnfinder_admin_menu() {
		add_menu_page(
			'vulnfinder',
			'vulnfinder',
			'manage_options',
			'vulnfinder_plugin',
			array(__CLASS__, 'vulnfinder_options_page')
		);
	}
	
	public function vulnfinder_options_page() {
		include __DIR__ . '/partials/wp-vulnfinder-admin-display.php';
	}
	
	public function update_lookup(){
		global $wpdb;
		
		/**
		* Get old list of plugin and version
		**/
		$result = $wpdb->get_results("SELECT * FROM wp_options WHERE option_name like '%_site_transient_update_plugins%'");
		 foreach( $result as $key => $row ){
			$obj = unserialize($row->option_value);
		 }
		 
		 /**
		 * IF attributes checked exist in wp_options => a plugin was updated or added to wordpress otherwise checked doesn't exist
		 **/
		 if(property_exists($obj, "checked")){

			 $plugin_list = $wpdb->get_results("SELECT name, version from plugin_list");
			 
			 /**
			 * IF its the first we lookup for scan -> table is empty so we fill it
			 **/
			 if(empty($plugin_list)){
				 foreach( $obj->checked as $key => $value){
					 print ( $value );
					 $rs = $wpdb->insert("plugin_list", array(
					 'name' => $key,
					 'version' => $value));
				 }
			 }
			 /**
			 * IF table is not empty -> we compare current table with wp_options table to see if something was updated or added
			 **/
			 else {
				 $arr = array();
				 
				 foreach($plugin_list as $key => $row){
					 $arr[$row->name] = $row->version;
				 }
				 
				 /**
				 * IF not equal -> something was updated so we perform a scan 
				 **/
				 if($obj->checked != $arr){
					 include __DIR__ . '/partials/wp-vulnfinder-scan.php';
				 }
			 }
		 }
	}
}
