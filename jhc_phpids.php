<?php
$plugin['version'] = '0.2.7';
$plugin['name'] = 'jhc_phpids';
$plugin['author'] = 'Jorge Hoya';
$plugin['author_uri'] = 'http://www.nosoynadie.net/';
$plugin['description'] = 'PHPIDS for TXP';
$plugin['order'] = 5;

// Plugin types:
// 0 = regular plugin; loaded on the public web side only
// 1 = admin plugin; loaded on both the public and admin side
// 2 = library; loaded only when include_plugin() or require_plugin() is called

/* 
Changelog:
0.2.7
	Email configuration
0.2.6
	Adapted to work with PHPIDS v0.7
	It's necessary doing some modifications on database. See Wiki: http://code.google.com/p/jhc-textpattern-plugins/wiki/jhc_phpids
0.2.5
	Fixed bugs on update function: previous check for existance of curl's functions.
	Fixed problems into navigation of phpids detections page.
	Adjust the configuration variables on system tables and on administration panel.
	The options of what should be analyzed by PHPIDS are moved to database and they are showed on administration panel.
0.2.4
	Check for new PHPIDS updates
0.2.3
	Control over random fields on the comments form
0.2.2
	Online update from official website of filters file (default_filter.xml) and Converter.php from oficial website.
0.2.1
	Modification on intrussions table: ALTER TABLE `textp_intrusions` ADD `tags` VARCHAR( 255 ) NULL AFTER `ip` 

TO-DO:
+ Use PHP Quick Profiler???

*/
$plugin['type'] = 1; 
if (!defined('txpinterface')) @include_once('out\zem_tpl.php');
if (0) {
?>
# --- BEGIN PLUGIN HELP ---
h1. PHPIDs para Textpattern (TXP)
This is an implementation of "PHPIDS":http://phpids.org for "Textpattern":http://www.textpattern.org
# --- END PLUGIN HELP ---
<?php
}

# --- BEGIN PLUGIN CODE ---

// pensar en como quitarlas al ya no usar PHPIDS
if (!isset($prefs['jhc_phpids_save_cache'])) { set_pref('jhc_phpids_save_cache', '1', 'publish', 0, 'yesnoradio', 360); }
if (!isset($prefs['jhc_phpids_save_file'])) { set_pref('jhc_phpids_save_file', '0', 'publish', 0, 'yesnoradio', 370); }
if (!isset($prefs['jhc_phpids_send_email'])) { set_pref('jhc_phpids_send_email', '0', 'publish', 0, 'yesnoradio', 380); }
if (!isset($prefs['jhc_phpids_allow_code_on_comments'])) { set_pref('jhc_phpids_allow_code_on_comments', '0', 'publish', 0, 'yesnoradio', 390); }
if (!isset($prefs['jhc_phpids_list_pageby'])) { set_pref('jhc_phpids_list_pageby', 25, 'publish', 0, 'text_input', 359); }
if (!isset($prefs['jhc_phpids_check_update'])) { set_pref('jhc_phpids_check_update', '1', 'publish', 0, 'yesnoradio', 395); }
if (!isset($prefs['jhc_phpids_check_REQUEST'])) { set_pref('jhc_phpids_check_REQUEST', '1', 'publish', 0, 'yesnoradio', 396); }
if (!isset($prefs['jhc_phpids_check_POST'])) { set_pref('jhc_phpids_check_POST', '1', 'publish', 0, 'yesnoradio', 397); }
if (!isset($prefs['jhc_phpids_check_GET'])) { set_pref('jhc_phpids_check_GET', '1', 'publish', 0, 'yesnoradio', 398); }
if (!isset($prefs['jhc_phpids_check_COOKIE'])) { set_pref('jhc_phpids_check_COOKIE', '1', 'publish', 0, 'yesnoradio', 398); }
// Email config
if (!isset($prefs['jhc_phpids_email_subject'])) { set_pref('jhc_phpids_email_subject', 'PHPIDS detected an intrusion attempt!', 'publish', 0, 'text_input', 400); }
if (!isset($prefs['jhc_phpids_email_header'])) { set_pref('jhc_phpids_email_header', 'From: <PHPIDS> info@php-ids.org', 'publish', 0, 'text_input', 401); }
if (!isset($prefs['jhc_phpids_email_envelope'])) { set_pref('jhc_phpids_email_envelope', '', 'publish', 0, 'text_input', 402); }
if (!isset($prefs['jhc_phpids_email_safemode'])) { set_pref('jhc_phpids_email_safemode', '1', 'publish', 0, 'yesnoradio', 403); }
if (!isset($prefs['jhc_phpids_email_urlencode'])) { set_pref('jhc_phpids_email_urlencode', '1', 'publish', 0, 'yesnoradio', 404); }
if (!isset($prefs['jhc_phpids_email_allowed_rate'])) { set_pref('jhc_phpids_email_allowed_rate', '15', 'publish', 0, 'text_input', 404); }
if (!isset($prefs['jhc_phpids_email_recipients'])) { set_pref('jhc_phpids_email_recipients', 'jorge@nosoynadie.net', 'publish', 0, 'text_input', 404); }

function jhc_phpids($atts){

	global $txpcfg, $prefs;
	set_include_path(
	   get_include_path()
	   . PATH_SEPARATOR
	   . $prefs['path_to_site'] . ''
	);

	// Configuration using preferences
	$IDSCache = ( isset($prefs['jhc_phpids_save_cache']) ) ? (bool)$prefs['jhc_phpids_save_cache'] : 1; // Record a log into database
	$IDSFileLog = ( isset($prefs['jhc_phpids_save_file']) ) ? (bool)$prefs['jhc_phpids_save_file'] : 0; // Record a log on filesystem
	$IDSEmail = ( isset($prefs['jhc_phpids_send_email']) ) ? (bool)$prefs['jhc_phpids_send_email'] : 0; // Send an email

	// what PHPIDS should analize
	$checkRequest = ( isset($prefs['jhc_phpids_check_REQUEST']) ) ? (bool)$prefs['jhc_phpids_check_REQUEST'] : 0;
	$checkGet = ( isset($prefs['jhc_phpids_check_GET']) ) ? (bool)$prefs['jhc_phpids_check_GET'] : 0;
	$checkPost = ( isset($prefs['jhc_phpids_check_POST']) ) ? (bool)$prefs['jhc_phpids_check_POST'] : 0;
	$checkCookie = ( isset($prefs['jhc_phpids_check_COOKIE']) ) ? (bool)$prefs['jhc_phpids_check_COOKIE'] : 0;

	require_once 'IDS/Init.php';
	try {

		$request = array();
		$request = array_merge ( $request, array('REQUEST' => $_REQUEST));
		if ($checkGet) $request = array_merge ( $request, array('GET' => $_GET));
		if ($checkPost) $request = array_merge ( $request, array('POST' => $_POST));
		if ($checkCookie) $request = array_merge ( $request, array('COOKIE' => $_COOKIE));
		
		//trace_add('[PHPIDS init]');
		$init = IDS_Init::init();		
		//trace_add('[PHPIDS loading configuration settings]');
		// General configuration
		$init->config['General']['base_path'] = '';
		$init->config['General']['use_base_path'] = true;
		$init->config['General']['filter_type'] = 'xml';
		$init->config['General']['filter_path'] = $prefs['path_to_site'] . '/IDS/default_filter.xml';
		$init->config['General']['scan_keys'] = false;
		$init->config['General']['tmp_path'] = $prefs['path_to_site'] . '/IDS/tmp';
		$init->config['General']['HTML_Purifier_Path'] = 'IDS/vendors/htmlpurifier/HTMLPurifier.auto.php';
		$init->config['General']['HTML_Purifier_Cache'] = 'IDS/vendors/htmlpurifier/HTMLPurifier/DefinitionCache/Serializer';
		
		$init->config['General']['html'][] = '__wysiwyg';
		$init->config['General']['json'][] = '__jsondata';
		
		// configuration of Exceptions
		$init->config['General']['exceptions'] = array();		
		if (@txpinterface == 'admin')
			$init->config['General']['exceptions'] = array 
			(
				'POST.Form', 'POST.Excerp', 'POST.Body', 'POST.html', 'POST.message', 'POST.store', 'POST.caption', 'POST.css', 'POST.plugin', 'POST.plugin64', 
				'REQUEST.Form', 'REQUEST.Excerp', 'REQUEST.html', 'REQUEST.Body', 'REQUEST.caption', 'REQUEST.css', 'REQUEST.message',
				'COOKIE.__utma', 
				'COOKIE.__utmb',
				'COOKIE.__utmc',
				'COOKIE.__utmz',
				'POST.message',
				'REQUEST.__utma',
				'REQUEST.__utmb',
				'REQUEST.__utmc',
				'REQUEST.__utmz',
				'POST.tempdir',
				'REQUEST.tempdir',
			);
		if ( isset($prefs['jhc_phpids_allow_code_on_comments']) and (bool) $prefs['jhc_phpids_allow_code_on_comments'] == true )
		{		
			/**
			When we send the comment (first time) the variable is POST.message
			When we send the definitive comment, variable isn't POST.message it's POST.random_value . "random_value" is calculated into comment.php.
			We have to include it on PHPIDS exceptions.
			We do that because the text "code" type  wrote on comment form is detected like an attack.
			/**/
			$arrDiscuss = array();
			# mysql4 compatible
			$rs = safe_rows_start('secret', 'txp_discuss_nonce', ' UNIX_TIMESTAMP() - UNIX_TIMESTAMP(issue_time) <= 3600', false);
			if ($rs)
			{
				while ($a = nextRow($rs))
				{
					extract(doSpecial($a));
					$arrDiscuss[] = 'POST.'.md5('message'.$secret);
				}
			}
			$init->config['General']['exceptions'] = array_merge ($init->config['General']['exceptions'], $arrDiscuss);
			unset($arrDiscuss, $rs);
		}
		
		//  configuration of Logging
		$init->config['Logging']['path'] = $prefs['path_to_site'] . '/IDS/tmp/phpids_log.txt';
		$init->config['Logging']['wrapper'] = "mysql:host=" .$txpcfg['host']. ";port=3306;dbname=" . $txpcfg['db'];
		$init->config['Logging']['user'] = $txpcfg['user'];
		$init->config['Logging']['password'] = $txpcfg['pass'];
		$init->config['Logging']['table'] = $txpcfg['table_prefix'] . 'intrusions';
		
		// configuration of Caching
		$init->config['Caching']['caching'] = 'database';
		$init->config['Caching']['wrapper'] = $init->config['Logging']['wrapper'];
		$init->config['Caching']['user'] = $txpcfg['user'];
		$init->config['Caching']['password'] = $txpcfg['pass'];
		$init->config['Caching']['table'] = $txpcfg['table_prefix'] .  'cache';
		$init->config['Caching']['expiration_time'] = '600';
		$init->config['Caching']['path'] = 'IDS/tmp/default_filter.cache';
		
		// Email config
		$init->config['Logging']['recipients'] = $prefs['jhc_phpids_email_recipients'];
		$init->config['Logging']['subject'] = $prefs['jhc_phpids_email_subject'];
		$init->config['Logging']['header'] = $prefs['jhc_phpids_email_header'];
		$init->config['Logging']['envelope'] = $prefs['jhc_phpids_email_envelope'];
		$init->config['Logging']['safemode'] = $prefs['jhc_phpids_email_safemode'];
		$init->config['Logging']['urlencode'] = $prefs['jhc_phpids_email_urlencode'];
		$init->config['Logging']['allowed_rate'] = $prefs['jhc_phpids_email_allowed_rate'];

		$ids = new IDS_Monitor($request, $init);
		$result = $ids->run();

		if (!$result->isEmpty()) 
		{
			// Take a look at the result object
			require_once 'IDS/Log/Composite.php';
			$compositeLog = new IDS_Log_Composite();
			if ( $IDSFileLog )
			{
				require_once 'IDS/Log/File.php';
				$compositeLog->addLogger(IDS_Log_File::getInstance($init));
			}
			if ($IDSCache)
			{
				require_once 'IDS/Log/Database.php';
				$compositeLog->addLogger( IDS_Log_Database::getInstance($init) );
			}
			if ($IDSEmail)
			{
				require_once 'IDS/Log/Email.php';
				$compositeLog->addLogger( IDS_Log_Email::getInstance($init) );
			}
			$compositeLog->execute($result);
			txp_die('System Fail', '500');
			//header('Location: ' . site_url(), TRUE, 302);
		}
	} 
	catch (Exception $e)
	{
		// sth went terribly wrong - maybe the filter rules weren't found?
		txp_die('An error occured: %s' . $e->getMessage(), '500');
	}
}

function jhc_phpids_admin_table()
{
	global $article_list_pageby, $event, $step, $prefs;
	
	$step = clean_url ($step);
	pagetop('jhc_phpids_admin_table '.gTxt('preferences'), '');
	switch ( strtolower ( $step ) ) {
		case 'empty':
			if ( jhc_phpids_empty_table() ) echo '<p style="text-align:center;">Operation completed successfully.</p>';
		break;
		case 'create':
			if ( jhc_phpids_create_tables() ) echo '<p style="text-align:center;">Creation completed successfully.</p>';
		break;
		case 'updat':
			if ( jhc_phpids_update_filters() ) echo '<p style="text-align:center;">Update completed successfully.</p>';
		break;
		case 'exp':
			if ( jhc_phpids_export_data() ) echo '<p style="text-align:center;">Export completed successfully.</p>';
		break;
	}
			
	extract(gpsa(array('page', 'sort', 'dir', 'crit', 'search_method')));
	if ($sort === '') $sort = get_pref('jhc_phpids_article_sort_column', 'name');
	if ($dir === '') $dir = get_pref('jhc_phpids_article_sort_column', 'asc');
	$dir = ($dir == 'desc') ? 'desc' : 'asc';

	if (!in_array($sort, array('impact', 'name', 'value', 'page', 'ip', 'origin', 'created'))) $sort = 'name';
	$sort_sql   = $sort.' '.$dir;

	set_pref('jhc_phpids_article_sort_column', $sort, 'list', 2, '', 0, PREF_PRIVATE);
	set_pref('jhc_phpids_article_sort_dir', $dir, 'list', 2, '', 0, PREF_PRIVATE);
	
	$switch_dir = ($dir == 'desc') ? 'asc' : 'desc';
	$total = getCount('intrusions', '1=1');
	$prefs["jhc_phpids_list_pageby"] = isset($prefs["jhc_phpids_list_pageby"]) ? $prefs["jhc_phpids_list_pageby"] : 25;
	$limit = min($prefs["jhc_phpids_list_pageby"], 200);

	list($tmpPage, $offset, $numPages) = pager($total, $limit, $page);
	$rs = safe_rows_start('*', 'intrusions', '1 = 1 order by '.$sort_sql.' limit '.$offset.', '.$limit);
	if ($rs)
	{
		echo '<form action="index.php" method="post" name="longform" onsubmit="return verify(\''.gTxt('are_you_sure').'\')">'.
			'<ul id="opt">';
		if ( safe_query ( 'SELECT * FROM `'. safe_pfx('cache'). '` LIMIT 0,1' , false) ) 
			echo '<li>' . eLink( 'jhc_phpids_admin_table', 'empty', '', '', 'Clean tables') . '</li>';
		else
			echo '<li>' . eLink( 'jhc_phpids_admin_table', 'create', '', '', 'Create tables') . '</li>';
		echo '<li>' .eLink( 'jhc_phpids_admin_table', 'updat', '', '', 'Update filters') . '</li>'.
			'<li>' .eLink( 'jhc_phpids_admin_table', 'exp', '', '', 'Export data') . '</li>'.
			'</ul>'.
			'<br />'.
		startTable('tblIdsList','','','', '95%').
		tr(
			column_head('Impact', 'impact', 'jhc_phpids_admin_table', true, $switch_dir, '', '', ('impact' == $sort) ? $dir : '').
			column_head('Variable', 'name', 'jhc_phpids_admin_table', true, $switch_dir, '', '', ('name' == $sort) ? $dir : '').
			column_head('Tags', 'tags', 'jhc_phpids_admin_table', true, $switch_dir, '', '', ('tags' == $sort) ? $dir : '').
			column_head('Valor', 'value', 'jhc_phpids_admin_table', true, $switch_dir, '', '', ('value' == $sort) ? $dir : '').
			column_head('Pagina', 'page', 'jhc_phpids_admin_table', true, $switch_dir, '', '', ('page' == $sort) ? $dir : '').
			column_head('IP de origen', 'ip', 'jhc_phpids_admin_table', true, $switch_dir, '', '', ('ip' == $sort) ? $dir : '').
			column_head('IP con proxy', 'ip2', 'jhc_phpids_admin_table', true, $switch_dir, '', '', ('ip2' == $sort) ? $dir : '').
			column_head('IP atacada', 'origin', 'jhc_phpids_admin_table', true, $switch_dir, '', '', ('origin' == $sort) ? $dir : '').
			column_head('Fecha', 'created', 'jhc_phpids_admin_table', true, $switch_dir, '', '', ('created' == $sort) ? $dir : '').
			hCell()
		);

		while ($a = nextRow($rs))
		{
			extract(doSpecial($a));

			echo tr(
				td($impact).
				td($name).
				td($tags).
				td($value, '600').
				td($page).
				td('<a href="http://www.maxmind.com/app/locate_demo_ip?ips='.$ip.'" target="_blank">' .$ip. '</a>').
				td('<a href="http://www.maxmind.com/app/locate_demo_ip?ips='.$ip2.'" target="_blank">' .$ip2. '</a>').
				td($origin).
				td($created)
			);
		}

		echo endTable().
			'<script>$("#tblIdsList").css("width", "100%");</script>'.
			'</form>'.
			'<div id="'.$event.'_navigation" class="txp-navigation">'.
				nav_form('jhc_phpids_admin_table', $tmpPage, $numPages, $sort, $dir, $crit, $search_method, $total, $limit).
			'</div>';		
		// check for new version
		if ( isset($prefs["jhc_phpids_check_update"]) and $prefs["jhc_phpids_check_update"] == true ) _jhc_check_new_version();
	}
}

function jhc_phpids_empty_table()
{
	return safe_query('TRUNCATE TABLE ' .safe_pfx('intrusions'). '', false);
}

function jhc_phpids_create_tables()
{
	// cache table
	$out = false;
	if (
		safe_query 
		( 'CREATE TABLE IF NOT EXISTS `'.safe_pfx('cache').'` ('.
			' `type` varchar(32) NOT NULL DEFAULT "",'.
			' `data` text NOT NULL,'.
			' `created` datetime NOT NULL DEFAULT "0000-00-00 00:00:00",'.
			' `modified` datetime NOT NULL DEFAULT "0000-00-00 00:00:00"'.
			' ) ENGINE=MyISAM DEFAULT CHARSET=latin1' 
		, false)
	)
	{
		// intrussions table
		$out = 
			safe_query 
			( 
			'CREATE TABLE IF NOT EXISTS `'.safe_pfx('intrusions').'` ('.
			' `id` int(11) unsigned NOT NULL AUTO_INCREMENT,'.
			' `name` varchar(128) NOT NULL DEFAULT "",'.
			' `value` text NOT NULL,'.
			' `page` varchar(255) NOT NULL DEFAULT "",'.
			' `tags` varchar(128) DEFAULT NULL,'.
			' `ip` varchar(15) NOT NULL DEFAULT "",'.
			' `ip2` varchar(15) NOT null, ',
			' `impact` int(11) unsigned NOT NULL DEFAULT "0",'.
			' `origin` varchar(15) NOT NULL DEFAULT "",'.
			' `created` datetime NOT NULL DEFAULT "0000-00-00 00:00:00",'.
			' PRIMARY KEY (`id`)'.
			' ) ENGINE=MyISAM' 
			, false);
	}
	return $out;
}

function jhc_phpids_update_filters()
{
	global $prefs;
	$arrDocs = array 
	(
		'filters' => array 
		(
			$prefs['path_to_site'] . '/IDS/default_filter.xml', 
			'https://dev.itratos.de/projects/php-ids/repository/raw/trunk/lib/IDS/default_filter.xml'
		)
		,
		'converter' => array
		(
			$prefs['path_to_site'] . '/IDS/Converter.php',
			'https://dev.itratos.de/projects/php-ids/repository/raw/trunk/lib/IDS/Converter.php'
		)
	);
	return ( _jhc_phpids_update_file($arrDocs['filters']) && _jhc_phpids_update_file($arrDocs['converter']) ) ? TRUE : FALSE;
}

function _jhc_phpids_update_file ($arrData)
{

	$salida= false;	
	if (empty($arrData)) return $salida;
	
	$salida2 = '';
	$move = ( is_windows() == TRUE ) ? 'move' : 'mv';
	if ( is_windows() ) $file = str_replace ('/', '\\', $arrData[0]);
	else $file = str_replace ('\\', '/', $arrData[0]);
	$salida2 = _jhc_download_file($arrData[1]);
	if ( strlen ($salida2) > 100 )
	{
		# backup
		shell_exec ($move . ' "' . $file . '" "'. $file.'_cs.php"');
		if ( @file_put_contents ( $file, $salida2, LOCK_EX) === FALSE )
		{
			# restore file
			//_jhc_phpids_restore_file ($file, $isWindows);
			_jhc_phpids_restore_file ($file, is_windows());
		}
		else { chmod ( $file, 0604); $salida = true; }
	}
	return $salida;
}

function _jhc_download_file($urlFile)
{
	// hay que comprobar que tenemos habilitado CURL
	$salida = '';
	if ( function_exists ( 'curl_init' ) )
	{
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $urlFile);
		curl_setopt($ch, CURLOPT_HEADER, FALSE);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE); # don't check SSL certificate
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE); # don't check SSL certificate
		ob_start();
		if(curl_exec($ch) === false) {echo 'Curl error: ' . curl_error($ch);}
		else { $salida = ob_get_contents(); }
		ob_end_clean();
		curl_close($ch);
	}
	return $salida;
}

function _jhc_phpids_restore_file ($file, $isWindows)
{
	$move = ( $isWindows == TRUE ) ? 'move' : 'mv';
	if (file_exists ($file) && file_exists ($file.'_cs.php'))
	{
		shell_exec ($move . ' "'. $file.'_cs.php" "' . $file . '"');
		chmod ( $file, 0604);
	}
}

function jhc_phpids_export_data()
{
	$file = _jhc_phpids_create_temp_file( is_windows() );
	return _jhc_phpids_down_file($file);
}

function _jhc_phpids_create_temp_file($isWindows)
{
	global $prefs;
	$file = '';
	$bar = ( $isWindows == TRUE ) ? '\\' : '/';
	$step = '[@#@]';
	$rs = safe_rows_start('*', 'intrusions', '1 = 1 order by 1');
	if ($rs)
	{
		// creating the file
		echo$file = $prefs["tempdir"]. $bar. mt_rand().'.csv';
		if ( $f = @fopen($file, "w+") )
		{
			$line = 'impact' . $step . 'variable' . $step . 'tags' . $step. 'value' . $step . 'page' . $step . 'ip' . $step . 'origin' . $step . 'date'. "\n";
			fwrite($f, $line, strlen ($line));
			while ($a = nextRow($rs))
			{
				extract(doSpecial($a));
				$line = $impact . $step . $name . $step . $tags . $step. $value . $step . $page . $step . $ip . $step . $origin . $step . $created. "\n";
				fwrite($f, $line, strlen ($line));
			}
			fclose($f);
		}
	}
	return $file;
}
    /**
     * Download a remote file
     *
     * @param  $file -> file to download
     * @return none
     */
function _jhc_phpids_down_file($file)
{
	// check existance of file
	if (file_exists ($file))
	{
		header("Content-type: application/force-download");
		header('Content-Description: File Transfer');
		header('Content-Type: application/octet-stream');
        header("Content-Disposition: attachment; filename=".basename($file));
		header('Content-Transfer-Encoding: binary');
		header('Expires: 0');
		header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
		header('Pragma: public');
        header("Content-Length: ".filesize($file));
		ob_clean();
		flush();
        readfile($file);
		exit;
	}
	else return false;
}
    /**
     * Check for new PHPIDS version
     *
     * @param  none
     * @return none
     */
function _jhc_check_new_version()
{
	require_once "IDS/Version.php";
	$url = 'https://dev.itratos.de/projects/php-ids/repository/raw/trunk/lib/IDS/Version.php';
	/**/
	$salida2 = '';
	$salida2 = _jhc_download_file($url);
	if ( strlen( $salida2 ) > 100 )
	{
		// finding the new version
		$patron = '@const version(\s)*=(\s)*\'(.*)\'@i';
		preg_match_all($patron, $salida2, $arr);
		//print_r ( $arr);
		if ( isset($arr[3][0]) and !empty($arr[3][0]))
		{
			if ( $arr[3][0] > 0 and IDS_Version::VERSION < $arr[3][0] ) echo '<p style="text-align:center;font-size:1.4em; margin:1em;">Your PHPIDS version is (' .IDS_Version::VERSION.') and there\'s a new version (<span style="color:#990000;">' . $arr[3][0] . '</span>). <a href="http://www.phpids.org/">Upgrade it</a>, please!</p>';
		}
	}
	/**/
}

if (@txpinterface == 'admin') {
	add_privs('jhc_phpids_admin_table', '1,2');
	register_callback("jhc_phpids", "admin_side"); 
	register_tab("extensions", "jhc_phpids_admin_table", "PHPIDS");
	register_callback("jhc_phpids_admin_table", "jhc_phpids_admin_table");
}
register_callback("jhc_phpids", "pretext");

// --- END PLUGIN CODE ---

/*
Installation:

   1. Download latest version of the plugin and the IDS.zip file Download
   2. Unzip the file IDS.zip into 'IDS' subfolder of your Textpattern installation root directory.
   3. Login into admin panel, install the plugin. When you do that, a new subtab of Extensiones, named PHPIDS, will appear.
   4. On PHPIDS subtab, use 'Create tables' link for running the process to create necessary tables for logging dangerous requests.
   5. Run this demo request:

      http://url_to_your_site/?id=1<script>alert('hello')</script>

If PHPIDS is on, you must recieve an 500 error (internal server error) from your page. The information about this 'attack' will be displayed on PHPIDS subtab on admin panel. For more information about PHPIDS configuration you must go to it's official Website: PHPIDS

Enjoy!! 

*/

?>
