<?php
class LdapUser extends sfGuardSecurityUser {

  public static function doCheckPassword($username, $password) {
    $config = sfYaml::load(sfConfig::get('sf_config_dir').'/LDAPAuth.yml');
    $config = $config['openldap'];
    $openldap = OpenLDAP::get($config['server'], $config['param']);
    $auth = $openldap->authenticate($username, $password);
    if ($auth) {
//      sfContext::getInstance()->getUser()->setAttribute('groups', $auth, 'openldap');
      return self::checkGroups($auth);
    }
    return $auth;
  }

  public function signIn($user, $remember = false, $con = null) {
    $this->user = $user;
    $this->setAttribute('username', $user->getUsername(), 'sfGuardSecurityUser');
    $this->setAuthenticated(true);
    // TODO [OP 2012-08-21] Make this an option.
    // TODO [OP 2012-08-21] Also allow the option to save a sfGuardUser instance
    $this->getGuardUser()->setIsSuperAdmin(true);
  }

  public function signOut() {
    if ($this->isAuthenticated()) {
      $this->getGuardUser()->setIsSuperAdmin(false);
    }
    parent::signOut();
  }

  public function getGuardUser() {
    if (!$this->user && $username = $this->getAttribute('username', null, 'sfGuardSecurityUser')) {
      $user = new sfGuardUser();
      $user->setUsername($username);
//      $this->setGroups($user);
      $user->setIsSuperAdmin(true);
      $this->user = $user;
    }

    return $this->user;
  }

  protected static function checkGroups($ldap_groups) {
    $config = sfYaml::load(sfConfig::get('sf_config_dir').'/LDAPAuth.yml');
    $required = $config['openldap']['param']['group']['required'];
    return self::checkGroup($ldap_groups, $required, true);
  }

  protected static function checkGroup($groups, $required, $and = true) {
    if (!is_array($required)) { return in_array($required, $groups); }
    $ok = false;
    foreach ($required as $membership) {
      $_ok = self::checkGroup($groups, $membership, !$and);
      if ($and && !$_ok) { return false; }
      if (!$and && $_ok) { return true; }
    }
    return $and;
  }

  // TODO [OP 2012-08-21] This can only work if a sfGuardUser instance is created.
  protected function setGroups($user) {
    $ldap_groups = $this->getAttribute('groups', null, 'openldap');
    $config = sfYaml::load(sfConfig::get('sf_config_dir').'/LDAPAuth.yml');
    $mappings = $config['openldap']['param']['group']['mapping'];
    foreach ($mappings as $group => $ldap_group) {
      if (in_array($ldap_group, $ldap_groups)) {
        $user->addGroupByName($group);
      }
    }
  }
}