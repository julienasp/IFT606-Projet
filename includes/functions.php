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
 * \fn get_vuln_wordpress( &$wpdb, $wpVersion )
 * \brief s'occupe de retourner un assosiative array avec la réponse ou null si aucun vuln
 * \param Object &$wpdb reférence sur l'objet wordpress database
 * \param string $wpVersion version de wordpress pour lequel on fait l'appel.
 * \return Array retourne un tableau assosiatif ou NULL
 */
function get_vuln_wordpress( &$wpdb, $wpVersion  ) {    
    
    //Requête SQL pour avoir toutes les anomalies en lien avec notre numéro de page
    $sql="select *
		FROM {$wpdb->prefix}wordpress_vulnerabilities t";
    // On sélectionne seulement la version demandé            
    $where='WHERE wordpress_version = "'.$wpVersion.'"';
    $sql.=$where;    
    $result = $wpdb->get_results( $sql );
    if($result == NULL){
        $wpVersion = str_replace(".", ""); // on retire le . pour la requête http
        $temp = get_wp_vuln_from_api($wpVersion);
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
function get_vuln_plugin( &$wpdb, $pluginName  ) {
    //Requête SQL pour avoir toutes les anomalies en lien avec notre numéro de page
    $sql="select *
		FROM {$wpdb->prefix}plugins_vulnerabilities t";
    // On sélectionne seulement la version demandé            
    $where='WHERE plugin_name = "'.$pluginName.'"';
    $sql.=$where;    
    $result = $wpdb->get_results( $sql );
    if($result == NULL){
        $pluginName = str_replace(" ", ""); // on retire les espaces pour la requête http
        $temp = get_wp_vuln_from_api($pluginName);
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
function get_wp_vuln_from_api($wpVersion){
    $url ='https://wpvulndb.com/api/v2/wordpresses/'.$wpVersion.'/';    
    if(get_http_response_code($url) != "200"){
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
    
    $result=json_decode($json_response); //json_decode pour transformer la string en assosiative array  
    $vuln = reset($result); // retourne le premier element aka le array avec la version courante
    
    if($vuln != false){
        $vuln['wordpress_version'] = $wpVersion;
        return insert_wordpress_vuln($vuln);
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
function get_plugin_vuln_from_api($pluginName){
    $url ='https://wpvulndb.com/api/v2/plugins/'.$pluginName.'/';

    $context = stream_context_create($opts);
    if(get_http_response_code($url) != "200"){
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
    
    $result=json_decode($json_response); //json_decode pour transformer la string en assosiative array    
    
    $vuln = reset($result); // retourne le premier element aka le array avec la version courante
    
    if($vuln != false){
        $vuln['plugin_name'] = $pluginName;
        return insert_plugin_vuln($vuln);
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
function insert_wordpress_vuln($result){
    
    $vulnsFormated = array();
    
    foreach($result['vulnerabilities'] as $vuln){
        //Ajout de la vulnerabilité courante
        $values=array(
            'vuldbapi_id'=>$vuln['id'],
            'title'=>htmlspecialchars($vuln['title'],ENT_QUOTES),
            'wordpress_version'=>htmlspecialchars($result['wordpress_version'],ENT_QUOTES),
            'references'=>htmlspecialchars($vuln['references']['url'][0],ENT_QUOTES),
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
function insert_plugin_vuln($result){
    
    $vulnsFormated = array();
    
    foreach($result['vulnerabilities'] as $vuln){
        //Ajout de la vulnerabilité courante
        $values=array(
            'vuldbapi_id'=>$vuln['id'],
            'title'=>htmlspecialchars($vuln['title'],ENT_QUOTES),
            'plugin_name'=>htmlspecialchars($result['wordpress_version'],ENT_QUOTES),
            'plugin_version'=>htmlspecialchars($result['wordpress_version'],ENT_QUOTES),
            'references'=>htmlspecialchars($vuln['references']['url'][0],ENT_QUOTES),
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
