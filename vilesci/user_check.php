<?php
/* Copyright (C) 2013 FH Technikum-Wien
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 *
 * Authors: Andreas Oesterreicher <andreas.oesterreicher@technikum-wien.at> 
 *
 */
/**
 * Prueft wie viele User aus der Datenbank im LDAP vorhanden/nicht vorhanden sind
 */
require_once('../../../config/vilesci.config.inc.php');
require_once('../../../include/functions.inc.php');
require_once('../../../include/basis_db.class.php');

require_once('ldap.class.php');

ini_set('display_errors','1');
error_reporting(E_ALL);

$db = new basis_db();

//LDAP Verbindung herstellen
$ldap = new ldap();
//$ldap->debug=true;
if(!$ldap->connect('starttls')) // (starttls | ldaps | plain)
	die($ldap->errormsg);

$qry = "SELECT  
			vorname, nachname, uid, gebdatum, (SELECT matrikelnr FROM public.tbl_student WHERE student_uid=tbl_benutzer.uid) as matrikelnr
		FROM
			public.tbl_benutzer
			JOIN public.tbl_person USING(person_id)
		WHERE
			tbl_benutzer.aktiv
		AND uid NOT IN('administrator','_DummyLektor')
		";

$vorhanden=array();
$fehlend=array();

if($result = $db->db_query($qry))
{
	while($row = $db->db_fetch_object($result))
	{
		$user = array();
		$user['vorname']=$row->vorname;
		$user['nachname']=$row->nachname;
		$user['uid']=$row->uid;
		$user['gebdatum']=$row->gebdatum;
		$user['matrikelnr']=$row->matrikelnr;

		//Suchen ob der User bereits vorhanden ist
		if(!$dn = $ldap->GetUserDN($row->uid))
			$fehlend[]=$user;
		else
			$vorhanden[]=$user;
	}
}
echo '<br>Vorhanden: '.count($vorhanden);
echo '<br>Fehlend:'.count($fehlend);
echo '<br><br>';
var_dump($fehlend);

$ldap->unbind();
?>
