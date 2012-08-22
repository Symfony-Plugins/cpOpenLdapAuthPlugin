<?php

class testTask extends sfBaseTask {

  protected function configure() {
    $this->addArguments(array(
       new sfCommandArgument('username', sfCommandArgument::REQUIRED, 'Username'),
       new sfCommandArgument('password', sfCommandArgument::REQUIRED, 'password')
    ));

    $this->addOptions(array(
      new sfCommandOption('application', null, sfCommandOption::PARAMETER_REQUIRED, 'The application name'),
      new sfCommandOption('env', null, sfCommandOption::PARAMETER_REQUIRED, 'The environment', 'dev'),
      new sfCommandOption('connection', null, sfCommandOption::PARAMETER_REQUIRED, 'The connection name', 'doctrine')
    ));

    $this->namespace        = 'ldap';
    $this->name             = 'test';
    $this->briefDescription = '';
    $this->detailedDescription = <<<EOF
The [test|INFO] task does things.
Call it with:

  [php symfony test|INFO]
EOF;
  }

  protected function execute($arguments = array(), $options = array()) {
    $config =   sfYaml::load(sfConfig::get('sf_config_dir').'/LDAPAuth.yml');
    $config = $config['openldap'];
    echo print_r($config, true);
/*
    $ldap = ldap_connect($config['servers'], $config['port']);
    ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, $config['protocol']);
    $this->logSection('debug', 'protocol in config: ' . $config['protocol']);
    $protocol;
    ldap_get_option($ldap, LDAP_OPT_PROTOCOL_VERSION, $protocol);
    $this->logSection('debug', 'protocol: ' . $protocol);
    if (ldap_bind($ldap, 'uid=' . $arguments['username'] . ',' . $config['base-dn'], $arguments['password'])) {
      $this->logSection('debug', 'Bound!');
    }
    else {
      $this->logSection('debug', ldap_error($ldap));
    }
    if (ldap_bind($ldap, sprintf($config['login-pattern'], $arguments['username']), $arguments['password'])) {
      $this->logSection('debug', 'Bound!');
    }
    ldap_unbind($ldap);
*/
    $ldap = OpenLDAP::instance($config);
    /*
    if ($ldap->bind($arguments['username'], $arguments['password'])) {
      $this->logSection('debug', 'Bound!');
    } */
    $auth = $ldap->authenticate($arguments['username'], $arguments['password']);
    $this->logSection('debug', 'authenticate: ' . $auth);


  }
}
