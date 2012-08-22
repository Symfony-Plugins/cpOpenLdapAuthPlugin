<?php
class LdapUserValidator extends sfValidatorBase {

  public function configure($options = array(), $messages = array()) {
    $this->addOption('username_field', 'username');
    $this->addOption('password_field', 'password');
    $this->addOption('throw_global_error', false);

    $this->setMessage('invalid', 'The username and/or password is invalid.');
  }

  protected function doClean($values) {
    $username = isset($values[$this->getOption('username_field')]) ? $values[$this->getOption('username_field')] : '';
    $password = isset($values[$this->getOption('password_field')]) ? $values[$this->getOption('password_field')] : '';

    $user = new sfGuardUser;
    $user->setUsername($username);
    $user->setSalt('unused');
    $user->setPassword('unused');

    if ($user->checkPassword($password)) {
      return array_merge($values, array('user' => $user));
    }
    else {
    }

    if ($this->getOption('throw_global_error')) {
      throw new sfValidatorError($this, 'invalid');
    }

    throw new sfValidatorErrorSchema($this, array($this->getOption('username_field') => new sfValidatorError($this, 'invalid')));
  }


}