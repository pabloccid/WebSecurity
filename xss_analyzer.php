<?php
error_reporting(E_ALL);
ini_set("display_errors", 1);

// CLASE QUE EJECUTA HILOS 
class ThreadURL extends Worker {
  private $url;
  private $i;
  private $id_ejecucion;
  private $cookie;
  
  public function __construct($i, $url, $id_ejecucion, $cookie){  
//     echo "<br>inicializando $i"." - TIME ".date("H:i:s:u");     
    $this->i=$i;
    $this->cookie=$cookie;
    $this->url=$url;
    $this->id_ejecucion=$id_ejecucion;
    
  }
  
  public function run(){
//     echo "<br>DETECTAR XSS ".$this->cookie." - TIME ".date("H:i:s:u");
    if($this->url){
      echo"<br><b><u>THREAD ".$this->i."</u></b><br>";
      detectar_xss($this->url, $this->id_ejecucion, $this->cookie);
    }
//     echo "<br>TERMINA  ".$this->i." - TIME ".date("H:i:s:u");
  }
}

/* 
   GENERA STRINGS DE TODAS LAS CONVINACIONES POSIBLES CON UNA LONGITUD MAXIMA 
   DE str_size CARACTERES 
*/
function generar_strings(&$set, &$results, $str_size, $n = 0){
  if($n<$str_size){
    $n++;
//     echo $n." | $str_size <br>";
    for ($i = 0; $i < count($set); $i++){
      $results[] = $set[$i];
      $tempset = $set;
      array_splice($tempset, $i, 1);
      $tempresults = array();
      
      generar_strings($tempset, $tempresults, $str_size, $n);
      foreach ($tempresults as $res){
          $results[] = $set[$i] . $res;
      }
    }
  }      
}

// EJECUTA REQUEST GET 
function get_request($new_url, $cookie){
//     echo "cookie: $cookie";
//    echo htmlspecialchars("<br>DESP--$new_url--<br>");
  $ch = curl_init($new_url);
  curl_setopt_array($ch, array(
                                CURLOPT_COOKIE         => $cookie,
                                CURLOPT_HEADER         => 0,
                                CURLOPT_RETURNTRANSFER => true,
                                CURLOPT_SSL_VERIFYPEER => false
  ));
  $content = curl_exec($ch);
  $code = curl_getinfo ($ch, CURLINFO_HTTP_CODE);
  curl_close($ch);
  if(substr($code, 0, 1) == 4) return false;
  return $content;
}

// EJECUTA REQUEST POST
function post_request($new_url,$cookie,$data){
  $fields_string = "";
  foreach($data as $key=>$value){ 
    $fields_string .= $key.'='.$value.'&'; 
  }
  rtrim($fields_string, '&');
 
  $ch = curl_init($new_url);
  curl_setopt($ch, CURLOPT_COOKIE, $cookie);
  curl_setopt($ch, CURLOPT_HEADER, 1);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
  curl_setopt($ch, CURLOPT_POST, true);
  curl_setopt($ch, CURLOPT_POSTFIELDS, $fields_string);
  $content = curl_exec($ch);
  $code = curl_getinfo ($ch, CURLINFO_HTTP_CODE);
  curl_close($ch);
  if(substr($code, 0, 1) == 4) return false;
  return $content;
}

/* 
   ANALIZA VULNERABILIDAD, A PARTIR DE LA RESPUESTA, EL SCRIPT QUE SE TRATO DE 
   INYECTAR, EL NOMBRE DE LA VARIABLE CON LA QUE SE INTENTO Y EL TAG EN EL QUE 
   TIENE QUE BUSCAR
*/ 
function analizarVulnerabilidad($new_content, $script, $name, $node){    
  $dom = new DomDocument;
  libxml_use_internal_errors(true);
  $dom->loadHTML($new_content); 
  $dom->normalizeDocument();
  $input_tags = $dom->getElementsByTagName($node);
//   echo "<br>".$input_tags->length;
  for ($o = 0; $o < $input_tags->length; $o++){
    if(strpos($script, $input_tags->item($o)->C14N()) === false){
    
    }else{
      return 1;
    } 
  }
  return 0;
}

/*
   HACE EL UPDATE DEL REGISTRO CORRESPONDIENTE, COMPLETANDO CON EL NOMBRE LA 
   VARIABLE QUE DETECTO COMO VULNERABLE
*/
function actualizarVulnerabilidad($id_ejecucion, $url, $name, $conn){
  $sql = "UPDATE xss_analysis_det SET vulnerable=CONCAT(vulnerable,'$name, ') 
          WHERE id_ejecucion=$id_ejecucion AND URL LIKE '$url'";
  
  if ($conn->query($sql) === TRUE){
  } else {
  }
}

/* 
   HACE EL INSERT DE LA EJECUCION PARA OBTENER UN ID DE EJECUCION
*/
function insertar_ejecucion($conn){
  $sql = "INSERT INTO xss_analysis (id, fecha)
  VALUES ('', '".date("Y-m-d")."')";
  
  if ($conn->query($sql) === TRUE) {
    return $conn->insert_id;
  } else {
    return 0;
  }
}

/*
   HACE EL INSERT DE LA URL ANALIZADA, PARA NO ANALIZAR DOS VECES LA MISMA URL
   EN LA MISMA EJECUCION. LUEGO ESTE REGISTRO ES UPDATEADO CON LOS INPUT 
   VULNERABLES
*/
function insertar_url_analizada($id_ejecucion, $url, $conn){    
  $sql = "INSERT INTO xss_analysis_det (id, id_ejecucion, url)
  VALUES ('', '$id_ejecucion', '$url')";
  
  if ($conn->query($sql) === TRUE){
    return 1;
  } else {
    return 0;
  }  
}


/*
   FUNCION PRINCIPAL, SE EJECUTA POR CADA URL A ANALIZAR.
   VARIABLE follow_links DETERMINA SI SIGUE URLs ENCONTRADAS EN LA RESPUESTA.
*/
function detectar_xss($url, $id_ejecucion, $cookie, $domain="", $follow_links = false){
  GLOBAL $maxthreads;
  $config_content = file_get_contents('http://localhost/config.xml');
  $xml = simplexml_load_string($config_content);
  $db_host = $xml->db_host;
  $db_name = $xml->db_name;
  $db_user = $xml->db_user;
  $db_pass = $xml->db_pass;
  $conn = new mysqli($db_host, $db_user, $db_pass,$db_name);
  if ($conn->connect_error){
      die("Connection failed: " . $conn->connect_error);
  }   
  $results = $conn->query("SELECT 1 FROM xss_analysis_det WHERE id_ejecucion = $id_ejecucion AND url = '$url'");
  $rows = $results->fetch_row();
  echo "<b>$url:</b><br>";            
  if($rows == 0){
    $content = get_request($url, $cookie);
    if($content != false){
   
//     echo "llegue";      

      if(insertar_url_analizada($id_ejecucion, $url, $conn) == 0){
        die("No se pudo insertar");
      }
      
/* OBTENGO TODOS LOS NAME Y ID QUE APARECEN EN EL CODIGO */ 
      preg_match_all("#(name|id)[[:space:]]*\=[[:space:]]*[\"|\']{1}(\w+)[\"|\']{1}#", $content, $coincidencias);
      
      $results = array();
      $chars = 'abcdefghijklmnopqrstuwxyz_'; //your string
      $str_size = 2;
      $chars = str_split($chars); //converted to array
      generar_strings($chars, $results, $str_size);
      $results = array_merge($coincidencias[2], $results);
          
      foreach ($results as $n => $name){
//         echo "Intentar: ".$name."<br>";
        $script_list = array(array("script" => "'><script>alert(\"".$name."\")</script>", "node" => "script"), array("script" => "<script>alert(\"".$name."\")</script>", "node" => "script"), array("script" => "<body onload='<script>alert(\"".$name."\")</script>'>", "node" => "body"));  
        $k = 0;       
        $vulnerable = 0;
        foreach($script_list as $n => $a_script){
  //                   die("$vulnerable ada $k das".count($script_list));
          $script = $a_script['script'];
          $node = $a_script['node']; 
          if(strpos($url, '?') === false){
            $new_url=$url.'?';
          }else{
            $new_url=$url.'&';
          }
          $new_url.="$name=$script";
  //                   echo htmlspecialchars("<br>ANTES--$new_url--<br>");   
          $new_content = get_request($new_url, $cookie);
          if($new_content != "")
            $vulnerable = analizarVulnerabilidad($new_content, $script, $name, $node);
          if($vulnerable == 0){  
            $data=array($name => $script);       
            $new_content = post_request($url, $cookie, $data);
            if($new_content != "")
              $vulnerable = analizarVulnerabilidad($new_content, $script, $name, $node);
          }
          if($vulnerable == 1){
            actualizarVulnerabilidad($id_ejecucion, $url, $name, $conn);
            echo "$name vulnerable<br>";
            break;
          }
        }
        if($vulnerable == 0){
          echo "$name no vulnerable<br>";
        }
//         echo "<br>";
      }



/* ENTRAR A LINKS */
      if($follow_links == true){
        $j = 0;
        $pool = new Pool((integer)$maxthreads);
        echo "<br><br>";
        preg_match_all("#(http|https|ftp|ftps)\:\/\/\b$domain/[^<>'\"[:space:]]+#", $content, $matches);
        foreach ($matches[0] as $v){
          echo "coincido: " . htmlspecialchars($v) . "<br>";
          $j++;
//           echo "submit $j<br>";
          $pool->submit(new ThreadURL($j, $v, $id_ejecucion,(string)$cookie));
        }
        $pool->shutdown();
//         echo "chau pool"; 
        
      }
      
    }else{
      echo "No encontrado<br><br>";
      
    }
    $conn->close();
  }else{
    echo "Ya analizado<br><br>";  
  }
  
  
}
/* FIN detectar_xss */
/* FIN funciones */

/* MAIN PART */          
 if(isset($_POST["Submit"])){
 
  $url = $_POST["url"];
  $cookie = $_POST["cookie"];
  $maxthreads = $_POST["maxthreads"]; 
  $parse = parse_url($url);
  $domain = $parse['host'];
  
  $config_content = file_get_contents('http://localhost/config.xml');
  $xml = simplexml_load_string($config_content);
  $db_host = $xml->db_host;
  $db_name = $xml->db_name;
  $db_user = $xml->db_user;
  $db_pass = $xml->db_pass;
  
  $conn = new mysqli($db_host, $db_user, $db_pass,$db_name);
  if ($conn->connect_error){
      die("Connection failed: " . $conn->connect_error);
  }      
  $id_ejecucion = insertar_ejecucion($conn); 
  if($id_ejecucion == 0){
    die("Error: ".$conn->error);
  }                                          
  $conn->close();
  
  echo"<br><b><u>MAIN THREAD</u></b><br>";
  echo "Domain: ".$domain."<br><br>";
  
  detectar_xss($url, $id_ejecucion, $cookie, $domain, true);
}else{
  echo "<form action='xss_analyzer_pool.php' method='post' id='confirm' onsubmit=\"return confirm('Está seguro que quiere continuar?');\"> 
        URL<br><input type='text' name='url' required><br>                        
        Threads Maximos<br><input type='text' name='maxthreads' required><br>    
        Cookies<br><textarea name='cookie'></textarea><br><br>                        
        <input type='submit' value='Analizar Vulnerabilidad' name='Submit'>
        </form>";
}


?>