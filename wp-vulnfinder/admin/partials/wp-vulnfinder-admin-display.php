<?php

/**
 * Provide a admin area view for the plugin
 *
 * This file is used to markup the admin-facing aspects of the plugin.
 *
 * @since      1.0.0
 *
 * @package    wp-vulnfinder
 * @subpackage wp-vulnfinder/admin/partials
 */
 
/* global $wpdb;
 
 $result = $wpdb->get_results("SELECT * FROM wp_options WHERE option_name like '%_site_transient_update_plugins%'");
 foreach( $result as $key => $row ){
	$obj = unserialize($row->option_value);
 }
 
 if(property_exists( $obj, 'checked')){
	
 }
 if(count($obj->response) > 0 ){
	 foreach($obj->response as $key => $std){
		 var_dump($std);
	 }
 }
echo '------------------------------------------------ \n';
 var_dump($obj);*/

global $wpdb;

require_once plugin_dir_path( realpath(__DIR__ . '/..') ) . 'admin/class-wp-vulnfinder-api.php';
$api = new wp_vulnfinder_api("dsfds", "sfsf");

if ($wpdb->get_var("SHOW TABLES LIKE '{$wpdb->prefix}wordpress_vulnerabilities'") != $wpdb->prefix . 'wordpress_vulnerabilities'){}
else{
	$api->get_vuln_wordpress( $wpdb, str_replace('.', '', get_bloginfo('version')) );
}

/*if ($wpdb->get_var("SHOW TABLES LIKE '{$wpdb->prefix}plugins_vulnerabilities'") != $wpdb->prefix . 'plugins_vulnerabilities'){
	
}else{
	$plugins = get_option('active_plugins');

	foreach($plugins as $value){
		$data = get_plugin_data( "C:\wamp64\www\mysite\wp-content\plugins\\".$value, false, false);
		$res = $api->get_plugin_vuln_from_api($wpdb, $data['Name'], $data['Version']);
		
		if ( $res != NULL ){
			$api->insert_plugin_vuln($wpdb, $res);
			print("insert plugin vuln");
		}
	}
}*/
 
require_once plugin_dir_path( realpath(__DIR__ . '/..') ) . 'admin/class-wp-vulnfinder-scan.php';
 $scan = new wp_vulnfinder_scan();
 $scan->vuln_admin_init();

?>
<!-- This file should primarily consist of HTML with a little bit of PHP. -->
<!DOCTYPE html">
<html>
<head>
  <title>vulnerabilities statistics</title>
	<link href="../wp-content/plugins/riadh/stylesheet.css" rel="stylesheet" type="text/css"> 
	<script type='text/javascript' src='../wp-content/plugins/riadh/script.js'></script>

</head>
	<style>
	.bar-chart .eje-x li:nth-child(1):before {
	background: #E64C65; 
	<?php 
	global $wpdb;
	$count1=$wpdb->get_var ( "SELECT COUNT(*) FROM wordpress_vulnurabilites" );
	$count2=$wpdb->get_var ( "SELECT COUNT(*) FROM plugins_vulnerabilites" );
	$countx1=$wpdb->get_var ( "SELECT COUNT(*) FROM wordpress_vulnurabilites WHERE vuln_type='XSS'" );
	$countx2=$wpdb->get_var ( "SELECT COUNT(*) FROM plugins_vulnerabilites WHERE vuln_type='XSS'" );?>
	height: <?php echo (($countx1+$countx2)/($count1+count2))*1200?>%;
	}
	
	.bar-chart .eje-x li:nth-child(2):before {
	  background: #11A8AB;  
	  <?php 
	global $wpdb;
	$countp1=$wpdb->get_var ( "SELECT COUNT(*) FROM wordpress_vulnurabilites WHERE vuln_type='PASSBY'" );
	$countp2=$wpdb->get_var ( "SELECT COUNT(*) FROM plugins_vulnerabilites WHERE vuln_type='PASSBY'" );?>
	height: <?php echo (($countp1+$countp2)/($count1+count2))*1200?>%;
	}
	.bar-chart .eje-x li:nth-child(3):before {
	  background: #FCB150;  
	  <?php 
	global $wpdb;
	$counts1=$wpdb->get_var ( "SELECT COUNT(*) FROM wordpress_vulnurabilites WHERE vuln_type='SSRF'" );
	$counts2=$wpdb->get_var ( "SELECT COUNT(*) FROM plugins_vulnerabilites WHERE vuln_type='SSRF'" );?>
	height: <?php echo (($counts1+$counts2)/($count1+count2))*1200?>%;
	}
	.bar-chart .eje-x li:nth-child(4):before {
	  background: #4FC4F6;  
	  <?php 
	global $wpdb;
	$countr1=$wpdb->get_var ( "SELECT COUNT(*) FROM wordpress_vulnurabilites WHERE vuln_type='REDIRECT'" );
	$countr2=$wpdb->get_var ( "SELECT COUNT(*) FROM plugins_vulnerabilites WHERE vuln_type='REDIRECT'" );?>
	height: <?php echo (($countr1+$countr2)/($count1+count2))*1200?>%;
	}
	.bar-chart .eje-x li:nth-child(5):before {
	  background: #FFED0D;  
	  <?php 
	global $wpdb;
	$countc1=$wpdb->get_var ( "SELECT COUNT(*) FROM wordpress_vulnurabilites WHERE vuln_type='CSRF'" );
	$countc2=$wpdb->get_var ( "SELECT COUNT(*) FROM plugins_vulnerabilites WHERE vuln_type='CSRF'" );?>
	height: <?php echo (($countc1+$countc2)/($count1+count2))*1200?>%;
	}
	.bar-chart .eje-x li:nth-child(6):before {
	  background: #F46FDA;  
	  <?php 
	global $wpdb;
	$countq1=$wpdb->get_var ( "SELECT COUNT(*) FROM wordpress_vulnurabilites WHERE vuln_type='SQL_INJECTION'" );
	$countq2=$wpdb->get_var ( "SELECT COUNT(*) FROM plugins_vulnerabilites WHERE vuln_type='SQL_INJECTION'" );?>
	height: <?php echo (($countq1+$countq2)/($count1+count2))*1200?>%;
	}
	
	</style>
<body>
<div id="body">
<h1 id="txt_title">VULNERABILIES STATISTICS</h1>

  <div class="bar-chart-block block">
    <h2 class='titular'>BAR CHART <span></span></h2>
    <div class='grafico bar-chart'>
       <ul class='eje-y'>
         <li data-ejeY='100'></li>
         <li data-ejeY='75'></li>
         <li data-ejeY='50'></li>
         <li data-ejeY='25'></li>
         
       </ul>
       <ul class='eje-x'>
         <li data-ejeX='37'><i>XSS</i></li>
         <li data-ejeX='56'><i>PASSBY</i></li>
         <li data-ejeX='25'><i>SSRF</i></li>
         <li data-ejeX='18'><i>REDIRECT</i></li>
         <li data-ejeX='45'><i>CSRF</i></li>
         <li data-ejeX='50'><i>SQL-Inj</i></li>
       </ul>
	  </div>

	  <table class="table">
		<thead>
        <tr>
            <th>Vuln-type</th>
            <th>Num_vulns WPress</th>
			<th>Num_vulns Plugin</th>
			<th>Total</th>
            <th>Percentage</th>
           
        </tr>
    </thead>
    <tbody>
	<tr id="xss">
		<td style="background-color:#E64C65;">XSS</td>
		<td><?php echo $countx1;?></td>
		<td><?php echo $countx2;?></td>
		<td><?php echo($countx1+$countx2)?></td>
		<td style="background-color:#E64C65;"><?php echo(($countx1+$countx2)/($count1+count2))*100?>%</td>
	</tr>
	<tr id="passby">
		<td style="background-color:#11A8AB;">PASSBY</td>
		<td><?php echo $countp1;?></td>
		<td><?php echo $countp2;?></td>
		<td><?php echo($countp1+$countp2)?></td>
		<td style="background-color:#11A8AB;"><?php echo (($countp1+$countp2)/($count1+count2))*100?>%</td>
	</tr>
	<tr id="ssrf">
		<td style="background-color:#FCB150;">SSRF</td>
		<td><?php echo $counts1;?></td>
		<td><?php echo $counts2;?></td>
		<td><?php echo($counts1+$counts2)?></td>
		<td style="background-color:#FCB150;"><?php echo (($counts1+$counts2)/($count1+count2))*100?>%</td>
	</tr>
	<tr id="reirect">
		<td style="background-color:#4FC4F6;">REDIRECT</td>
		<td><?php echo $countr1;?></td>
		<td><?php echo $countr2;?></td>
		<td><?php echo($countxr1+$countr2)?></td>
		<td style="background-color:#4FC4F6;"><?php echo (($countr1+$countr2)/($count1+count2))*100?>%</td>
	</tr>
	<tr id="csrf">
		<td style="background-color:#FFED0D;">CSRF</td>
		<td><?php echo $countc1;?></td>
		<td><?php echo $countc2;?></td>
		<td><?php echo($countc1+$countc2)?></td>
		<td style="background-color:#FFED0D;"><?php echo (($countc1+$countc2)/($count1+count2))*100?>%</td>
	</tr>
	<tr td="sql">
		<td style="background-color:#F46FDA;">SQL-Inj</td>
		<td><?php echo $countq1;?></td>
		<td><?php echo $countq2;?></td>
		<td><?php echo($countq1+$countq2)?></td>
		<td style="background-color:#F46FDA;"><?php echo (($countq1+$countq2)/($count1+count2))*100?>%</td>
	</tr>
	 </tbody>
	</table>
	  
  </div>
</div>
  
            
<div id=tables>
<table class="wp_vul">
<caption><h2>WP Vulnerabilities</h2></caption>
    <thead>
        <tr>
            <th>Title</th>
            <th>WP Version</th>
            <th>References</th>
            <th>Vuln type</th>
			<th>Fixed in</th>
        </tr>
    </thead>
    <tbody>
	<?php 
	global $wpdb;
	$count=$wpdb->get_var ( "SELECT COUNT(*) FROM wordpress_vulnurabilites" );
	for ($x = 1; $x <= $count; $x++) {?>
        <tr>
            <td>
				<?php
				global $wpdb;
				$v=$wpdb->get_var ( "SELECT title FROM wordpress_vulnurabilites Where id=$x" );
				echo $v;			
				?>
			</td>
			<td>
				<?php
				global $wpdb;
				$v=$wpdb->get_var ( "SELECT wordpress_version FROM wordpress_vulnurabilites Where id=$x" );
				echo $v;			
				?>
			</td>
			<td>
				<?php
				global $wpdb;
				$v=$wpdb->get_var ( "SELECT reference FROM wordpress_vulnurabilites Where id=$x" );
				echo $v;			
				?>
			</td>
			<td>
				<?php
				global $wpdb;
				$v=$wpdb->get_var ( "SELECT vuln_type FROM wordpress_vulnurabilites Where id=$x" );
				echo $v;			
				?>
			</td>
			<td>
				<?php
				global $wpdb;
				$v=$wpdb->get_var ( "SELECT fixed_in FROM wordpress_vulnurabilites Where id=$x" );
				echo $v;			
				?>
			</td>
        </tr>
    <?php };?>
    </tbody>
</table>

<table class="pl_vul">
<caption><h2>Plugin Vulnerabilities</h2></caption>
    <thead>
        <tr>
            <th>Title</th>
            <th>Plugin Name</th>
			<th>Plugin Version</th>
            <th>Reference</th>
            <th>Vuln type</th>
			<th>Fixed in</th>
			
        </tr>
    </thead>
    <tbody>
	<?php 
	global $wpdb;
	$count=$wpdb->get_var ( "SELECT COUNT(*) FROM plugins_vulnerabilites" );
	for ($t = 1; $t <= $count; $t++) {?>
        <tr>
            <td>
				<?php
				global $wpdb;
				$v=$wpdb->get_var ( "SELECT title FROM plugins_vulnerabilites Where id=$t" );
				echo $v;			
				?>
			</td>
			<td>
				<?php
				global $wpdb;
				$v=$wpdb->get_var ( "SELECT plugin_name FROM plugins_vulnerabilites Where id=$t" );
				echo $v;			
				?>
			</td>
			<td>
				<?php
				global $wpdb;
				$v=$wpdb->get_var ( "SELECT plugin_version FROM plugins_vulnerabilites Where id=$t" );
				echo $v;			
				?>
			</td>
			<td>
				<?php
				global $wpdb;
				$v=$wpdb->get_var ( "SELECT reference FROM plugins_vulnerabilites Where id=$t" );
				echo $v;			
				?>
			</td>
			<td>
				<?php
				global $wpdb;
				$v=$wpdb->get_var ( "SELECT vuln_type FROM plugins_vulnerabilites Where id=$t" );
				echo $v;			
				?>
			</td>
			<td>
				<?php
				global $wpdb;
				$v=$wpdb->get_var ( "SELECT fixed_in FROM plugins_vulnerabilites Where id=1" );
				echo $v;			
				?>
			</td>
        </tr>
	<?php };?>  
    </tbody>
</table>
</div>
<div id="footer">
	<!--<div id="about"><p>Statistical data of this chart provided by The <a href="http://www.netapplications.com/">Net Applications</a></p></div>
	<div id="author"><p>Code by <a href="http://www.ohsean.net">Sean</a> | find me on <a href="http://www.facebook.com/#!/profile.php?id=100001036031905">Facebook</a></p></div>-->
</div>
</div>
</body>
</html>