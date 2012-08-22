<?php
/**
 * Handle ldap authentication functionality
 *
 *
 * LICENSE: This source file is subject to version 3.01 of the GPL license
 * that is available through the world-wide-web at the following URI:
 * http://www.gnu.org/licenses/gpl.html.  If you did not receive a copy of
 * the GPL License and are unable to obtain it through the web, please
 *

 * @category   authentication
 * @package    phpMyFramework
 * @author     Original Author <jason.gerfen@gmail.com>
 * @copyright  2010 Jason Gerfen
 * @license    http://www.gnu.org/licenses/gpl.html  GPL License 3
 * @version    0.1
 */
 /* source: http://forrst.com/posts/PHP_OpenLDAP_Class-ggn */
class OpenLDAP {

  protected static $instances = array();

  protected $server;
  protected $config;

  protected $handle;
  protected $bound;

  public static function get($server, $options) {
    if (!array_key_exists($server, self::$instances)) {
      $instance = new OpenLDAP($server, $options);
      $instances[$server] = $instance;
    }
    return $instances[$server];
  }


  protected function __construct($server, array $options = array()) {
    if (function_exists('ldap_connect')) {
      $this->server = $server;
      $this->config = $options;
    }
    else {
      echo 'The ldap exensions are not available.';
      unset(self::$instances);
      exit;
    }
  }

  public function bind($dn, $password) {
    return ldap_bind($this->getHandle(), $dn, $password);
  }

  public function authenticate($username, $password) {
    if (empty($username) || empty($password)) { return false; }
    if ($rootdn = $this->config('rootdn') && !empty($rootdn)) {
      $this->bound = $this->bind($rootdn, $this->config('rootpw'));
      // TODO [OP 2012-08-22] Search for user
    }
    else {
      $binddn = str_replace('%username%', $username, $this->config('binddn'));
      $this->bound = $this->bind($binddn, $password);
    }
    if ($this->bound) {
      $dn = $this->getUserDn($username);
      $groups = $this->getuserGroups($dn);
      return $groups;
    }
  }

  public function search($base_dn, $filter, $scope = 'sub',
                         $attributes = null, $attrsonly = 0,
                         $sizelimit = 0, $timelimit = 0,
                         $deref = LDAP_DEREF_NEVER) {
    if (!$attributes) { $attributes = array(); }
    switch ($scope) {
      case 'base' :
        return ldap_read($this->getHandle(), $base_dn, $filter, $attributes,
                         $attrsonly, $sizelimit, $timelimit, $deref);
        break;

      case 'one' :
        return ldap_list($this->getHandle(), $base_dn, $filter, $attributes,
                         $attrsonly, $sizelimit, $timelimit, $deref);
        break;

      case 'sub' :
        return ldap_search($this->getHandle(), $base_dn, $filter, $attributes,
                         $attrsonly, $sizelimit, $timelimit, $deref);
        break;
    }
  }

  public function results($data) {
    return ldap_get_entries($this->getHandle(), $data);
  }

  public function config($param) {
    if (array_key_exists($param, $this->config)) {
      return $this->config[$param];
    }
  }

  protected function getHandle() {
    if (!$this->handle) {
      $this->connect();
    }
    return $this->handle;
  }

  protected function connect() {
    $this->handle = ldap_connect($this->server, $this->config['port']);
    $this->setOptions();
  }

  protected function setOptions() {
    ldap_set_option($this->handle, LDAP_OPT_PROTOCOL_VERSION, $this->config['protocol']);
    ldap_set_option($this->handle, LDAP_OPT_REFERRALS, $this->config['referrals']);
    ldap_set_option($this->handle, LDAP_OPT_TIMELIMIT, $this->config['timelimit']);
    ldap_set_option($this->handle, LDAP_OPT_NETWORK_TIMEOUT, $this->config['timeout']);
  }

  protected function getUserDn($username) {
    $result = $this->search($this->config('usertree'),
                            str_replace('%username%', $username, $this->config('userfilter')),
                            'sub',
                            array('dn'));
    if ($result) {
      $entries = ldap_get_entries($this->getHandle(), $result);
      return $entries[0]['dn'];
    }
  }

  protected function getUserGroups($dn) {
    $group_config = $this->config('group');
    $result = $this->search($group_config['tree'],
                            str_replace('%userdn%', $dn, $group_config['filter']));
    if ($result) {
      $entries = ldap_get_entries($this->getHandle(), $result);
      $groups = array();
      $count = $entries['count'];
      for ($i = 0; $i < $count; $i++) {
        $groups[] = $entries[$i]['cn'][0];
      }
      return $groups;
    }

  }

  private function errors($handle) {
    return ldap_error($resource)." => ".ldap_errno($resource);
  }

/*
  private function __destruct() {
    if (isset($this->handle)) {
      ldap_free_result($this->handle);
      ldap_unbind($this->handle);
    }
    return;
  }
  */
}