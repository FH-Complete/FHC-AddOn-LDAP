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

class ldap
{
	public $ldap_conn;
	public $debug=false;
	public $errormsg='';


	/**
	 * Stellt eine Verbindung zum LDAP Directory her
	 * @param $type Art der Verbindung (starttls | ldaps | plain)
	 * @param $ldap_server IP oder Name des LDAP Servers (ohne ldap:// davor)
	 * @param $ldap_bind_user DN des Users mit dem die Verbindung hergestellt werden soll (null fuer simple bind)
	 * @param $ldap_bind_password Passwort des ldap_bind_users (null fuer simple bind)
	 * @return true wenn erfolgreich, false im Fehlerfall
	 */
	public function connect($ldap_server=LDAP_SERVER, $ldap_port=LDAP_PORT, $ldap_bind_user=LDAP_BIND_USER, $ldap_bind_password=LDAP_BIND_PASSWORD, $starttls=LDAP_STARTTLS)
	{
		$this->debug("LDAP Connect $ldap_server::$ldap_port - starttls:".$starttls);
		if($this->debug)
			ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL,7);

		$this->ldap_conn = ldap_connect($ldap_server, $ldap_port);

	    ldap_set_option($this->ldap_conn, LDAP_OPT_PROTOCOL_VERSION, 3);
	    ldap_set_option($this->ldap_conn, LDAP_OPT_REFERRALS, 0);

		if($starttls)
		{
			if(!ldap_start_tls($this->ldap_conn))
			{
				$this->errormsg='StartTLS fehlgeschlagen'.ldap_error($this->ldap_conn);
				return false;
			}
		}

		if(!$result=@ldap_bind($this->ldap_conn, $ldap_bind_user, $ldap_bind_password))
		{
			if(ldap_errno($this->ldap_conn)==49) // Passwort falsch
				$this->errormsg = 'Das von Ihnen eingegebene Passwort ist falsch.';
			else
				$this->errormsg = 'Fehler beim Verbinden zum LDAP Server:'.ldap_error($this->ldap_conn);
			return false;
		}
		return true;
	}


	/**
	 * Sucht einen User im LDAP
	 * Wenn dieser gefunden wird, wird seine DN zurueckgeliefert, sonst false
	 * @param $username UID des Users
	 */
	public function GetUserDN($username, $base_dn=LDAP_BASE_DN, $search_filter=LDAP_USER_SEARCH_FILTER)
	{
		if (($res_id = ldap_search($this->ldap_conn, $base_dn, $search_filter."=$username")) == false)
		{
			$this->errormsg='LDAP Suche fehlgeschlagen';
			return false;
		}

		if (ldap_count_entries($this->ldap_conn, $res_id) == 0)
		{
			// User im LDAP noch nicht vorhanden
			$this->errormsg='User wurde nicht gefunden';
			return false;
		}

		if (ldap_count_entries($this->ldap_conn, $res_id) > 1)
		{
			// Mehrere Suchergebnisse gefunden
			$this->errormsg='LDAP Suchergebnis nicht eindeutig';
			return false;
		}

		if (ldap_count_entries($this->ldap_conn, $res_id) == 1)
		{
			// 1 Eintrag gefunden
			$entry = ldap_get_entries($this->ldap_conn, $res_id);
			return $entry[0]['dn'];
		}
	}
	
	/**
	 * Fuegt einen User zu einer LDAP Gruppe hinzu
	 * @param $group_dn DN der Gruppe (zB "cn=systementwicklung,dc=technikum-wien,dc=at")
	 * @param $username UID des Users
	 */
	public function AddGroupMember($group_dn, $username)
	{	
		$data = array('memberUID' => $username);

		if(ldap_mod_add ($this->ldap_conn, $group_dn, $data)) 
		    return true;
		else
		{
		    $this->errormsg= " Fehler beim Hinzufügen zur LDAP-Gruppe: ".ldap_error($this->ldap_conn);
			return false;
		}
	}

	/**
	 * Loescht einen User aus einer Gruppe
	 * @param $group_dn DN der Gruppe (zB "cn=systementwicklung,dc=technikum-wien,dc=at")
	 * @param $username UID des Users
	 */
	public function DeleteGroupMember($group_dn, $username)
	{	
		$data = array('memberUID' => $username);

		if(ldap_mod_del ($this->ldap_conn, $group_dn, $data)) 
		    return true;
		else
		{
		    $this->errormsg= " Fehler beim Entfernen von LDAP-Gruppe: ".ldap_error($this->ldap_conn);
			return false;
		}
	}

	/**
	 * Aendert ein Attribut im LDAP
	 * @param $dn DN des Eintrages der geaendert werden soll
	 * @param $data object mit den Daten die geaendert werden sollen
	 */
	public function Modify($dn, $data)
	{	
		if(ldap_modify($this->ldap_conn, $dn, $data)) 
		    return true;
		else
		{
		    $this->errormsg= " Fehler beim Aendern des LDAP eintrages: ".ldap_error($this->ldap_conn);
			return false;
		}
	}

	/**
	 * Legt einen neuen Eintrag an
	 * @param $ou_dn DN der OU in dem der Eintrag erstellt werden soll (zB "ou=People,dc=technikum-wien,dc=at")
	 * @param $data array mit den zu setzenden Daten
	 */
	public function Add($dn, $data)
	{
		if(!ldap_add($this->ldap_conn, $dn, $data))
		{
			$this->errormsg='Fehler beim Anlegen des Eintrages:'.ldap_error($this->ldap_conn);
			return false;
		}
		else
		{
			return true;
		}
	}

	/**
	 * Trennt die Verbindung zum LDAP Server
	 */
	public function unbind()
	{
		if(!ldap_unbind($this->ldap_conn))
		{
			debug("Unbind Fehlgeschlagen");
			return false;
		}
		else
			return true;
	}

	/**
	 * Gibt eine Debug Meldung aus wenn debugging aktiviert ist
	 */
	public function debug($msg)
	{
		if($this->debug)
			echo 'DEBUG: '.$msg.'<br>';
	}

	public function getGroups($base_dn=LDAP_BASE_DN, $groupfilter='objectClass=posixGroup')
	{
		if (($res_id = ldap_search($this->ldap_conn, $base_dn, '(&('.$groupfilter.')(cn=*))')) == false)
		{
			$this->errormsg='LDAP Suche fehlgeschlagen';
			return false;
		}

		$entry = ldap_get_entries($this->ldap_conn, $res_id);
		return $entry;
	}
	public function getGroupMember($gruppenname, $base_dn=LDAP_BASE_DN, $groupfilter='objectClass=posixGroup')
	{
		if (($res_id = ldap_search($this->ldap_conn, $base_dn, '(&('.$groupfilter.')(name='.$gruppenname.'))')) == false)
		{
			$this->errormsg='LDAP Suche fehlgeschlagen';
			return false;
		}

		$entry = ldap_get_entries($this->ldap_conn, $res_id);
		return $entry;		
	}
}

?>
