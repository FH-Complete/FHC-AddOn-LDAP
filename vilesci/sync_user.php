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
 * Sync_user
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
$ldap->debug=true;
if(!$ldap->connect('starttls'))
	die($ldap->errormsg);


$qry = "SELECT
			vorname, nachname, uid
		FROM
			public.tbl_benutzer
			JOIN public.tbl_person USING(person_id)
		WHERE
			tbl_benutzer.aktiv";

if($result = $db->db_query($qry))
{
	while($row = $db->db_fetch_object($result))
	{
		//Suchen ob der User bereits vorhanden ist
		if(!$dn = $ldap->GetUserDN($row->uid))
		{
			//Passwort genierieren
			$passwort = 'Pa55W0r7';

			//OpenLDAP
			$data = array();
			$data['cn'] = $row->uid;
			$data['givenName'] = $row->vorname;
			$data['sn'] = $row->nachname;
			$data['mail'] = $row->uid.'@'.DOMAIN;
			$data['objectclass'] = array("top","person","inetOrgPerson");
			$data['uid'] = $row->uid;
			$data['userpassword']=$passwort;
			$dn = 'cn='.$row->uid.','.LDAP_BASE_DN;

			//Active Directory
			/*

			//Active Directory will das Passwort in doppelten Hochkomma und UTF16LE codiert
			$utf16_passwort = 	mb_convert_encoding('"'.$passwort.'"', "UTF-16LE", "UTF-8");

			$data = array();
			$data['cn'] = $uid;
			$data['objectclass'] = array("top","person","organizationalPerson","user");
			$data['sn'] = $row->nachname;
			$data['givenName'] = $row->vorname;
			$data['displayName'] = $row->vorname." ".$row->nachname;
			$data['name'] = $row->vorname." ".$row->nachname;
			$data['mail'] = $row->uid.'@'.DOMAIN;
			$data["sAMAccountName"] = $row->uid;


			//Passwort und UserAccountControl kann nicht beim Anlegen direkt gesetzt werden
			//Es muss nach dem Anlegen des Users gesetzt werden
			*/

			if(!$ldap->Add($dn, $data))
			{
				echo "<br>Fehler beim Anlegen von $row->uid: ".$ldap->errormsg;
				continue;
			}
			else
			{

				/* Nur fuer Active Directory

				// Moegliche Fehlerquellen beim setzten des Passworts:
				// - Richtigen BIND User verwenden
				// - im AD muss das setzen des Passwortes aktiviert sein
				// - Damit das Passwort gesetzt werden darf, muss die Verbindung zum AD verschluesselt sein (mind 127 Bit)
				//   Dazu muss am AD ein SSL Zertifikat installiert werden
				// - Passwort muss der Passwort Policy des AD entsprechen (Sonderzeichen, Gross-/Kleinschreibung etc, mind. 6 Zeichen)
				// - Passwort muss korrekt UTF16LE kodiert sein und unter doppelten Hochkomma stehen

				// Useraccountcontrol gibt den Status des Accounts an.
				// Per default sind diese deaktiviert (514)
				// 512 = Normal Account
				// 66048 = Aktiv, Passwort lauft nicht ab
				// http://support.microsoft.com/kb/305144/en-us

				$data = array();
				$data['useraccountcontrol'][0]='66048';
				$data['unicodepwd']=$utf16_passwort;
				if(!$ldap->Modify($dn, $data))
				{
					echo "<br>Fehler beim Setzten von UserAccountControl und Passwort von $row->uid: ".$ldap->errormsg;
					continue;
				}
				*/

				echo "<br>$row->uid erfolgreich angelegt";
			}
		}

		//Gruppenzuordnungen
		/*
		$qry = "SELECT
					distinct gruppe_kurzbz
				FROM
					public.tbl_benutzergruppe
					JOIN public.tbl_gruppe USING(gruppe_kurzbz)
				WHERE
					uid=".$db->db_add_param($row->uid)."
					AND tbl_gruppe.aktiv";

		if($result_gruppe = $db->db_query($qry))
		{
			if($row_gruppe = $db->db_fetch_object($result_gruppe))
			{
				// Bei Gruppenzuordnungen wird der User zur Gruppe hinzugefuegt
				// nicht umgekehrt!
				// Group DN muss angepasst werden!
				$group_dn = "cn=$row->gruppe_kurzbz,ou=Group,dc=academic,dc=local";
				if($ldap->AddGroup($group_dn,$row->uid))
					echo "\n<br>Gruppe hinzugefuegt";
				else
					echo "\n<br>Fehler:".$ldap->errormsg;
			}
		}
		*/

	}
}

$ldap->unbind();
?>
