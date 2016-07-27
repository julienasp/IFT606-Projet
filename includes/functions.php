<?php

/**
 * \file functions.php
 * \brief Contient des fonctions utiles
 * \author Julien Aspirot <julien.aspirot@usherbrooke.ca>
 * \copyright IFT606 - WPVulz
 * \date 26/07/2016
 */

//Sécurité en cas d'accès direct
if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly
}

/**
 * \fn get_anomalies_from_page( &$wpdb, $wpVersion )
 * \brief s'occupe de retourner un assosiative array avec la réponse ou null si aucun anomalie
 * \param Object &$wpdb reférence sur l'objet wordpress database
 * \param string $wpVersion version de wordpress pour lequel on fait l'appel.
 * \return Array retourne un tableau assosiatif
 */
function get_vulz_from_wordpress( &$wpdb, $wpVersion  ) {
    //Requête SQL pour avoir toutes les anomalies en lien avec notre numéro de page
    $sql="select *
		FROM {$wpdb->prefix}wordpress_vulnerabilities t";
    // On sélectionne seulement la version demandé            
    $where='WHERE wordpress_version = "'.$wpVersion.'"';
    $sql.=$where;    
    $result = $wpdb->get_results( $sql );
    if(result == NULL){
        temp = get_wpvulndb_api($wpVersion);
        
    }
    return $wpdb->get_results( $sql );
}

function get_wpvulndb_api($wpVersion){
// Création d'un flux
$opts = array(
  'http'=>array(
    'method'=>"GET"        
  )
);

$context = stream_context_create($opts);
if(get_http_response_code('https://wpvulndb.com/api/v2/wordpresses/'.$wpVersion.'/') != "200"){
    return NULL;
}

// Open the file using the HTTP headers set above
$results = file_get_contents('https://wpvulndb.com/api/v2/wordpresses/'.$wpVersion.'/', false, $context);
    
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

/**
 * \fn get_anomalies_from_page( &$wpdb, $page )
 * \brief s'occupe de retourner un assosiative array de la réponse en DB ou API ou null si aucun anomalie
 * \param Object &$wpdb reférence sur l'objet wordpress database
 * \param string $pluginName nom du plugin pour lequel on fait l'appel.
 * \return Array retourne un tableau assosiatif
 */
function get_vulz_from_plugin( &$wpdb, $pluginName  ) {
    //Requête SQL pour avoir toutes les anomalies en lien avec notre numéro de page
    $sql="select t.*,c.name as category,
		TIMESTAMPDIFF(MONTH,t.update_time,UTC_TIMESTAMP()) as date_modified_month,
		TIMESTAMPDIFF(DAY,t.update_time,UTC_TIMESTAMP()) as date_modified_day,
		TIMESTAMPDIFF(HOUR,t.update_time,UTC_TIMESTAMP()) as date_modified_hour,
 		TIMESTAMPDIFF(MINUTE,t.update_time,UTC_TIMESTAMP()) as date_modified_min,
 		TIMESTAMPDIFF(SECOND,t.update_time,UTC_TIMESTAMP()) as date_modified_sec
		FROM {$wpdb->prefix}mga_anomalies t
		INNER JOIN {$wpdb->prefix}mga_categories_anomalie c ON t.cat_id=c.id ";
//La liste est trier en ordre de MàJ
    $order_by='ORDER BY t.update_time DESC ';
//On prend 10 tuples à partir de la page ( courante - 1 * 10 ). Donc page 1, nous avons LIMIT 0,10 et pour la page 2 nous avons LIMIT 10,10
    $limit_start=( $page -1 ) * 10;
    $limit="LIMIT ".$limit_start.",10 ";
    $sql.=$order_by;
    $sql.=$limit;
    return $wpdb->get_results( $sql );
}
