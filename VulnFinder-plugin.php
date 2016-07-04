<?php
/**
 * Plugin Name: Plugin de gestion d'anomalies
 * Description: Mini gestionnaires d'anomalies pour le Travail pratique 1 du cours IGL711
 * License: éducation
 * Version: 0.0.1
 * Author: Julien Aspirot
 */

/**
 * \file anomalies-plugin.php
 * Fichier d'initialisation, wordpress repère dynamiquement ce fichier nous permettant ainsi d'activer ou desactiver le plugin.
 * Lorsque Wordpress active ou desactive le plugin ce fichier sera executé.
 * \author Julien Aspirot <julien.aspirot@usherbrooke.ca>
 * \brief     Fichier d'initialisation, wordpress repère dynamiquement ce fichier nous permettant ainsi d'activer ou desactiver le plugin.
 * \date 26/09/2015
 * \copyright Équipe 2 - IGL711
 *
 */

//Sécurité en cas d'accès direct
if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////
global $wp_rewrite;
$wp_rewrite = new WP_Rewrite;

//Lorsque le plugin est activé la fonction installation est appellé
register_activation_hook( __FILE__, installation ) ;

/**
 * \fn installation()
 * \brief S'occupe d'inclure les fichiers importants du plugin.
 * \post création des tables dans la base de données
 * \return void
 */
function installation()
{
    //create_bd.php s'occupe de bâtir l'infrastructure de notre base de données
    include_once(plugin_dir_path(__FILE__) . 'includes/create_bd.php');
}

//Inclusion de tous les fichiers nécessaires
include_once(plugin_dir_path(__FILE__) . 'includes/create_bd.php'); //S'assure que les tables sont présentes

//On valide si la page pour les détails d'une anomalie existe
$page_details = get_page_by_title( "Détails d'une anomalie" );
$GLOBALS['page_detail_id'] = 0;
if(is_null( $page_details ) )
{
    //n'existe pas alors on la crée
    $new_post = array(
        'post_title' => "Détails d'une anomalie",
        'post_content' => '[mga_shortcode_single]',
        'post_status' => 'publish',
        'post_date' => date('Y-m-d H:i:s'),
        'post_author' => 1,
        'post_type' => 'page',
    );
    $GLOBALS['page_detail_id'] = wp_insert_post($new_post);
}
else
{
    $GLOBALS['page_detail_id'] = $page_details->ID;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Ajout d'un shortcode [mga_shortcode_ajout] permettant de générer le code necessaire à l'ajout des anomalies
add_shortcode( 'mga_shortcode_ajout','mga_shortcode_ajout' );


/**
 * \fn mga_shortcode_ajout()
 * \brief S'occupe de générer tout le code html, css et php pour l'ajout d'une anomalie.
 * \post création d'un shortcode wordpress, qui contient du code html, css et php.
 * \return void
 */
function mga_shortcode_ajout(){
    ob_start();
    echo '<div class="support_bs">';
    include_once( plugin_dir_path(__FILE__) . 'includes/create_new_ticket.php' );
    echo '</div>';
    return ob_get_clean();
}

//Ajout d'un shortcode [mga_shortcode_listing] permettant de générer le code necessaire au listing des anomalies
add_shortcode( 'mga_shortcode_listing','mga_shortcode_listing' );


/**
 * \fn mga_shortcode_listing()
 * \brief S'occupe de générer tout le code html, css et php pour la table d'énumération des anomalies.
 * \post création d'un shortcode wordpress, qui contient du code html, css et php.
 * \return void
 */
function mga_shortcode_listing(){
    ob_start();
    echo '<div class="support_bs">';
    include_once( plugin_dir_path(__FILE__) . 'includes/listing_anomalies.php' );
    echo '</div>';
    return ob_get_clean();
}

//Ajout d'un shortcode [mga_shortcode_single] permettant de générer le code necessaire voir et modifier les détails d'une anomalie
add_shortcode( 'mga_shortcode_single','mga_shortcode_single' );


/**
 * \fn mga_shortcode_single()
 * \brief S'occupe de générer tout le code html, css et php pour afficher les détails d'une anomalie.
 * \post création d'un shortcode wordpress, qui contient du code html, css et php.
 * \return void
 */
function mga_shortcode_single(){
    ob_start();
    echo '<div class="support_bs">';
    include_once( plugin_dir_path(__FILE__) . 'includes/single_anomalie.php' );
    echo '</div>';
    return ob_get_clean();
}

//Ajout d'actions afin de bien lier tous les fichiers de style et javascript que nous allons ajouter dans le header
add_action( 'wp_enqueue_scripts', 'loadScripts' );
add_action( 'wp_enqueue_style', 'loadScripts' );

/**
 * Fonction
 *
 */
/**
 * \fn loadScripts()
 * \brief S'occupe de lier tous les fichiers de style .css et les fichiers javascripts que nous allons utiliser.
 * \post les libraries et les fichiers de style sont ajoutés à leurs files Wordpress correspondante.
 * \return void
 */
function loadScripts(){
    wp_enqueue_script( 'jquery' );
    wp_enqueue_script( 'jquery-ui-core' );
    wp_enqueue_style('bootstrap', plugin_dir_url( __FILE__ ) . 'asset/js/bootstrap/css/bootstrap.css');
    wp_enqueue_style('display_ticket', plugin_dir_url( __FILE__ ) . 'asset/css/display_ticket.css');
    wp_enqueue_style('public', plugin_dir_url( __FILE__ ) . 'asset/css/public.css');
    wp_enqueue_script('bootstrap', plugin_dir_url( __FILE__ ) . 'asset/js/bootstrap/js/bootstrap.min.js');
}












