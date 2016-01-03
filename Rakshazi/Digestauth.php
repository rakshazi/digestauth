<?php

namespace Rakshazi;

/**
 * Simple library with realisation of HTTP digest auth on PHP.
 *
 * Usage:<br />
 * <code>
 * $auth = new \Rakshazi\Digestauth;
 * $auth->setUsers(array('admin' => 'password'))->setRealm("It's optional")->enable();
 * </code>
 * @license BSD-4
 * @author Nikita Cherniy
 * @link https://github.com/rakshazi/digestauth
 */
class Digestauth {

    protected $data;
    protected $users;
    protected $realm;

    /**
     * Set users logins and passwords
     *
     * @param array $users Eg: array('login' => 'password', 'login2' => 'password2')
     *
     * @return \Rakshazi\Digestauth
     */
    public function setUsers($users = array())
    {
        $this->users = $users;

        return $this;
    }

    /**
     * Set realm (Optional)
     *
     * @param string $realm
     *
     * @return \Rakshazi\Digestauth
     */
    public function setRealm($realm = "Restricted area")
    {
        $this->realm = $realm;

        return $this;
    }

    /**
     * Enable digest auth on this page.
     *
     * @return bool LoggedIn
     */
    public function enable()
    {
        if (empty($_SERVER['PHP_AUTH_DIGEST'])) {
            $this->send401Headers();
            return false;
        }

        if (!$userExists = $this->analyze()) {
            return false;
        }

        return $this->check();
    }

    /**
     * Analyze (parse) passed data
     *
     * @return bool False if wrong credentials passed
     */
    protected function analyze()
    {
        // protect against missing data
        $needed_parts = array('nonce'=>1, 'nc'=>1, 'cnonce'=>1, 'qop'=>1, 'username'=>1, 'uri'=>1, 'response'=>1);
        $data = array();
        $keys = implode('|', array_keys($needed_parts));

        preg_match_all(
            '@('.$keys.')=(?:([\'"])([^\2]+?)\2|([^\s,]+))@',
            $_SERVER['PHP_AUTH_DIGEST'],
            $matches,
            PREG_SET_ORDER
        );

        foreach ($matches as $m) {
            $data[$m[1]] = $m[3] ? $m[3] : $m[4];
            unset($needed_parts[$m[1]]);
        }

        $data = $needed_parts ? false : $data;

        if (!$data || !isset($this->users[$data['username']])) {
            return false;
        }

        $this->data = $data;

        return true;
    }

    /**
     * Check passed data
     *
     * @return bool Is user logged in
     */
    protected function check()
    {
        $A1 = md5($this->data['username'] . ':' . $this->realm . ':' . $this->users[$this->data['username']]);
        $A2 = md5($_SERVER['REQUEST_METHOD'].':'.$this->data['uri']);
        $valid_response = md5(
            $A1.':'.$this->data['nonce'].':'.
            $this->data['nc'].':'.$this->data['cnonce'].':'.
            $this->data['qop'].':'.$A2
        );

        if ($this->data['response'] != $valid_response) {
            return false;
        }

        return true;
    }

    /**
     * Generate auth header for each request
     *
     * @return string Header
     */
    protected function getAuthHeader()
    {
        $header = 'WWW-Authenticate: ';
        $header.= 'Digest realm="'.$this->realm.'",';
        $header.= 'qop="auth"';
        $header.= 'nonce="'.uniqid(true).'",';
        $header.= 'opaque="'.md5($this->realm).'"';

        return $header;
    }

    /**
     * Set 401 Unauthorized header if user pressed "Cancel" button in auth dialog box
     */
    protected function send401Headers()
    {
        header('HTTP/1.1 401 Unauthorized');
        header($this->getAuthHeader());
    }
}
