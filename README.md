ocsrf
=====

This is my Implementation of OWasp's CSRF code.
Please feel free to comment or make suggestions so I can improve this code.


usage
=====

````php
<?php
  require_once(ocsrf.class.php);
  session_start();

  if (!OCSRF::protect())
  {
    // Do something in the event of suspected CSRF 
  } else {
    // Process Submitted Form Data
  }
?>

<form method="POST">
  <? echo OCSRF::generate_token(); ?>
  ...
</form>

````
