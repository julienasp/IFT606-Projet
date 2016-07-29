<?php

/**
 * The api callout functionality of the plugin.
 *
 * @since      1.0.0
 *
 * @package    wp-vulnfinder
 * @subpackage wp-vulnfinder/admin
 */

/**
 * The api callout functionality of the plugin.
 *
 * Defines function to get info from api
 *
 * @package    wp-vulnfinder
 * @subpackage wp-vulnfinder/admin
 */
class wp_vulnfinder_api {

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
	
	public function vuln_cron_get_api(){
		
		global $wpdb;
		
		if ($wpdb->get_var("SHOW TABLES LIKE '{$wpdb->prefix}wordpress_vulnerabilities'") != $wpdb->prefix . 'wordpress_vulnerabilities'){}
		else{
			$this->get_wp_vuln_from_api( $wpdb, get_bloginfo('version') );
		}
		
		if ($wpdb->get_var("SHOW TABLES LIKE '{$wpdb->prefix}plugins_vulnerabilities'") != $wpdb->prefix . 'plugins_vulnerabilities'){}
		else{
			$plugins = get_option('active_plugins');

			foreach($plugins as $value){
				$data = get_plugin_data( "C:\wamp64\www\mysite\wp-content\plugins\\".$value, false, false);
				$this->get_plugin_vuln_from_api($wpdb, $data['Name'], $data['Version']);
			}
		}
	}
	
	/**
	 * \fn get_vuln_wordpress( &$wpdb, $wpVersion )
	 * \brief s'occupe de retourner un assosiative array avec la réponse ou null si aucun vuln
	 * \param Object &$wpdb reférence sur l'objet wordpress database
	 * \param string $wpVersion version de wordpress pour lequel on fait l'appel.
	 * \return Array retourne un tableau assosiatif ou NULL
	 */
	public function get_vuln_wordpress( &$wpdb, $wpVersion  ) {    
		$wpVersion = str_replace(".", "", $wpVersion); // on retire le . pour la requête http
		//Requête SQL pour avoir toutes les anomalies en lien avec notre numéro de page
		$sql="select *
			FROM {$wpdb->prefix}wordpress_vulnerabilities ";
		// On sélectionne seulement la version demandé            
		$where='WHERE wordpress_version = "'.$wpVersion.'"';
		$sql.=$where;
		$result = $wpdb->get_results( $sql );
		if($result == NULL){        
			$temp = $this->get_wp_vuln_from_api($wpdb,$wpVersion);
			if($temp == NULL) return NULL;
			return $temp;
		}
		return $result;
	}

	/**
	 * \fn get_vuln_plugin( &$wpdb, $pluginName  ) {
	 * \brief s'occupe de retourner un assosiative array de la réponse en DB ou API ou null si aucun anomalie
	 * \param Object &$wpdb reférence sur l'objet wordpress database
	 * \param string $pluginName nom du plugin pour lequel on fait l'appel.
	 * \return Array retourne un tableau assosiatif
	 */
	function get_vuln_plugin( &$wpdb, $pluginName,$pluginVersion  ) {
	$pluginName = str_replace(" ", "",$pluginName); // on retire les espaces pour la requête http    
	//Requête SQL pour avoir toutes les anomalies en lien avec notre numéro de page
		$sql="select *
			FROM {$wpdb->prefix}plugins_vulnerabilities ";
		// On sélectionne seulement la version demandé            
		$where='WHERE plugin_name = "'.$pluginName.'"';
		$sql.=$where;    
		$result = $wpdb->get_results( $sql );
		if($result == NULL){        
			$temp = get_plugin_vuln_from_api($wpdb,$pluginName,$pluginVersion);
			if($temp == NULL) return NULL;
			return $temp;
		}
		return $result;
	}

	/**
	 * \fn get_wp_vulndb_api($wpVersion)
	 * \brief s'occupe de retourner un assosiative array avec la réponse ou null si aucun vuln (CALL API)
	 * \param string $wpVersion version de wordpress pour lequel on fait l'appel.
	 * \return Array retourne un tableau assosiatif ou NULL
	 */
	function get_wp_vuln_from_api(&$wpdb,$wpVersion){
		$url ='https://wpvulndb.com/api/v2/wordpresses/'.$wpVersion.'/';    
		if($this->get_http_response_code($url) != "200"){
			return NULL;
		}    
		// Tableau contenant les options de téléchargement
		$options=array(
			  CURLOPT_URL            => $url, // Url cible (l'url la page que vous voulez télécharger)
			  CURLOPT_RETURNTRANSFER => true, // Retourner le contenu téléchargé dans une chaine (au lieu de l'afficher directement)
			  CURLOPT_HEADER         => false // Ne pas inclure l'entête de réponse du serveur dans la chaine retournée
		); 
		// Création d'un nouvelle ressource cURL
		$CURL=curl_init();
	 
		// Configuration des options de téléchargement
		curl_setopt_array($CURL,$options);
	 
		// Exécution de la requête
		$json_response = curl_exec($CURL);
		
		// Fermeture de la session cURL
		curl_close($CURL);
		
		$result=json_decode($json_response,true); //json_decode pour transformer la string en assosiative array  
		$vuln = reset($result); // retourne le premier element aka le array avec la version courante
		
		if($vuln != false){
			$vuln['wordpress_version'] = $wpVersion;
			return insert_wordpress_vuln($wpdb,$vuln);
		}
		else {
			return NULL;    
		}
	}


	/**
	 * \fn get_wpvulndb_api($wpVersion)
	 * \brief s'occupe de retourner un assosiative array avec la réponse ou null si aucun vuln (CALL API)
	 * \param string $pluginName nom du plugin pour lequel on fait l'appel.
	 * \return Array retourne un tableau assosiatif ou NULL
	 */
	function get_plugin_vuln_from_api(&$wpdb,$pluginName,$pluginVersion){
		$url ='https://wpvulndb.com/api/v2/plugins/'.$pluginName.'/';
		

		$context = stream_context_create($opts);
		if($this->get_http_response_code($url) != "200"){
			return NULL;
		}
		
		// Tableau contenant les options de téléchargement
		$options=array(
			  CURLOPT_URL            => $url, // Url cible (l'url la page que vous voulez télécharger)
			  CURLOPT_RETURNTRANSFER => true, // Retourner le contenu téléchargé dans une chaine (au lieu de l'afficher directement)
			  CURLOPT_HEADER         => false // Ne pas inclure l'entête de réponse du serveur dans la chaine retournée
		);
	 
		// Création d'un nouvelle ressource cURL
		$CURL=curl_init();
	 
		// Configuration des options de téléchargement
		curl_setopt_array($CURL,$options);
	 
		// Exécution de la requête
		$json_response = curl_exec($CURL);
		
		// Fermeture de la session cURL
		curl_close($CURL);
		
		$result=json_decode($json_response,true); //json_decode pour transformer la string en assosiative array    
		
		$vuln = reset($result); // retourne le premier element aka le array avec la version courante
		
		if($vuln != false){
			$vuln['plugin_name'] = $pluginName;
			$vuln['plugin_version'] = $pluginVersion;
			return insert_plugin_vuln($wpdb,$vuln);
		}
		else {
			return NULL;    
		}
	}

	/**
	 * \fn insert_wordpress_vuln($result)
	 * \brief insert toutes les vulnerabilités dans la BD
	 * \param Object $url le url sur lequel on fait l'appel
	 * \return un code de reponse http
	 */
	function insert_wordpress_vuln(&$wpdb,$result){
		
		$vulnsFormated = array();
		
		foreach($result['vulnerabilities'] as $vuln){
			//Ajout de la vulnerabilité courante
			$values=array(
				'vuldbapi_id'=>$vuln['id'],
				'title'=>htmlspecialchars($vuln['title'],ENT_QUOTES),
				'wordpress_version'=>htmlspecialchars($result['wordpress_version'],ENT_QUOTES),
				'reference'=>htmlspecialchars($vuln['references']['url'][0],ENT_QUOTES),
				'vuln_type'=>htmlspecialchars($vuln['vuln_type'],ENT_QUOTES),
				'fixed_in'=>htmlspecialchars($vuln['fixed_in'],ENT_QUOTES)
			);
			
			//Insersion des données contenues dans $values dans la table wordpress_vulnerabilities
			$wpdb->insert($wpdb->prefix.'wordpress_vulnerabilities',$values);
			array_push($vulnsFormated,$values);
		}
		return $vulnsFormated;
	}

	/**
	 * \fn insert_plugin_vuln($result)
	 * \brief insert toutes les vulnerabilités dans la BD
	 * \param Object $url le url sur lequel on fait l'appel
	 * \return un code de reponse http
	 */
	function insert_plugin_vuln(&$wpdb,$result){
		
		$vulnsFormated = array();
		
		foreach($result['vulnerabilities'] as $vuln){
			//Ajout de la vulnerabilité courante
			$values=array(
				'vuldbapi_id'=>$vuln['id'],
				'title'=>htmlspecialchars($vuln['title'],ENT_QUOTES),
				'plugin_name'=>htmlspecialchars($result['plugin_name'],ENT_QUOTES),
				'plugin_version'=>htmlspecialchars($result['plugin_version'],ENT_QUOTES),
				'reference'=>htmlspecialchars($vuln['references']['url'][0],ENT_QUOTES),
				'vuln_type'=>htmlspecialchars($vuln['vuln_type'],ENT_QUOTES),
				'fixed_in'=>htmlspecialchars($vuln['fixed_in'],ENT_QUOTES)
			);
			
			//Insersion des données contenues dans $values dans la table wordpress_vulnerabilities
			$wpdb->insert($wpdb->prefix.'plugins_vulnerabilities',$values);
			array_push($vulnsFormated,$values);
		}
		return $vulnsFormated;
	}

	/**
	 * \fn get_http_response_code($url) 
	 * \brief retourne le http respond code, afin de s'assurer que la page existe bien
	 * \param Object $url le url sur lequel on fait l'appel
	 * \return un code de reponse http
	 */
	function get_http_response_code($url) {
		$c = curl_init();
		curl_setopt($c, CURLOPT_HEADER, true);
		curl_setopt($c, CURLOPT_NOBODY, true);
		curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($c, CURLOPT_SSL_VERIFYHOST, true);
		curl_setopt($c, CURLOPT_URL, $url);
		curl_exec($c);
		$status = curl_getinfo($c, CURLINFO_HTTP_CODE);
		curl_close($c);
		return $status;
	}
	
}
