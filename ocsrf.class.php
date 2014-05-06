<?
/**
 * OWASP Cross Site Request Forgery Implementation
 * By Jason Bauman
 */
class OCSRF
{
    public static function generate_token()
    {
        $token = array();
        $token["name"] = "CSRFGuard_".mt_rand(0,mt_getrandmax());
        if (function_exists("hash_algos") and in_array("sha512",hash_algos()))
        {
            $token["token"] = hash("sha512",mt_rand(0,mt_getrandmax()));
        }
        else
        {
            $token["token"] = ' ';
            for ($i = 0; $i < 128; ++$i)
            {
                $r = mt_rand(0,35);
                if ($r < 26)
                {
                    $c = chr(ord('a') + $r);
                }
                else
                { 
                    $c = chr(ord('0') + $r - 26);
                } 
                $token["token"] .= $c;
            }
        }
        
        self::store_in_session($token["name"], $token["token"]);
        $input = '<input type="hidden" name="CSRFName" value="'.$token["name"].'">';
        $input .= '<input type="hidden" name="CSRFToken" value="'.$token["token"].'">';
        return $input;
    }
    
    public static function validate_token($unique_form_name, $token_value)
    {
        $token = self::get_from_session($unique_form_name);
        if ($token === false)
        {
            return true;
        }
        elseif ($token === $token_value)
        {
            $result = true;
        }
        else
        { 
            $result = false;
        } 
        self::unset_session($unique_form_name);
        return $result;
    }
    
    public static function protect()
    {
        $result = true;
        if (count($_POST))
        {
            if ( !isset($_POST['CSRFName']) or !isset($_POST['CSRFToken']) )
            {
                $result = false;
                //trigger_error("No CSRFName found, probable invalid request.",E_USER_ERROR);   
            } 
            $name = $_POST['CSRFName'];
            $token = $_POST['CSRFToken'];
            if (!self::validate_token($name, $token))
            { 
                $result = false;
                //trigger_error("Invalid CSRF token.",E_USER_ERROR);
            }
        }
        return $result;
    }

    protected static function store_in_session($key,$value) 
    { 
        if (isset($_SESSION)) 
        { 
            $_SESSION[$key]=$value; 
        } 
    }
      
    protected static function unset_session($key)
    { 
        $_SESSION[$key]=' '; unset($_SESSION[$key]);
    }
    
    protected static function get_from_session($key)
    {
        if (isset($_SESSION)) 
        { 
            return isset($_SESSION[$key])?$_SESSION[$key]:true; 
        } 
        else 
        {  
            return false; 
        } 
    }

}

?>