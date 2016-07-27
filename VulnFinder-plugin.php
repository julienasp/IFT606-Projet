<?php
/**
 * Plugin Name: Vulnfinder
 * Description: Plugin pour trouver les vulnérabilités de wordpress et des plugins installés
 * License: éducation
 * Version: 0.0.1
 * Author: Julien Aspirot
 */

/**
 * \file vulnfinder-plugin.php
 * Fichier d'initialisation, wordpress repère dynamiquement ce fichier nous permettant ainsi d'activer ou desactiver le plugin.
 * Lorsque Wordpress active ou desactive le plugin ce fichier sera executé.
 * \author Julien Aspirot <julien.aspirot@usherbrooke.ca>
 * \brief     Fichier d'initialisation, wordpress repère dynamiquement ce fichier nous permettant ainsi d'activer ou desactiver le plugin.
 * \date 26/09/2015
 * \copyright IFT606 - WPVulz
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












