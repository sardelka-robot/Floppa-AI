<?php
declare(strict_types=1);
/**
 * Google OAuth 2.0 Authorization Code flow for Floppa AI.
 * Place beside index.php and config.php.
 */
ini_set('session.use_strict_mode','1');
$https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
session_set_cookie_params(['lifetime'=>60*60*24*30,'path'=>'/','secure'=>$https,'httponly'=>true,'samesite'=>'Lax']);
session_start();
require __DIR__.'/config.php';

function oauth_fail(string $msg, int $code=400): never {
    http_response_code($code);
    header('Content-Type: text/plain; charset=utf-8');
    exit($msg);
}
function oauth_db(): PDO {
    static $pdo=null;
    if ($pdo instanceof PDO) return $pdo;
    $pdo=new PDO('mysql:host='.DB_HOST.';dbname='.DB_NAME.';charset=utf8mb4',DB_USER,DB_PASS,[
      PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,
      PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC,
      PDO::ATTR_EMULATE_PREPARES=>false
    ]);
    return $pdo;
}
if (!defined('GOOGLE_CLIENT_ID') || !defined('GOOGLE_CLIENT_SECRET') ||
    GOOGLE_CLIENT_ID === 'PASTE_GOOGLE_CLIENT_ID' ||
    GOOGLE_CLIENT_SECRET === 'PASTE_NEW_ROTATED_CLIENT_SECRET') {
    oauth_fail('Заполните GOOGLE_CLIENT_ID и GOOGLE_CLIENT_SECRET в config.php.',500);
}
$scheme = $https ? 'https' : 'http';
$host = $_SERVER['HTTP_HOST'] ?? '';
if (!preg_match('/^[a-z0-9.-]+(?::[0-9]+)?$/i',$host)) oauth_fail('Invalid host',400);
$redirectUri = $scheme.'://'.$host.'/google_auth.php';

if (isset($_GET['error'])) oauth_fail('Google отменил или отклонил авторизацию. Вернитесь на сайт и попробуйте снова.',400);

if (isset($_GET['code'])) {
    $state=(string)($_GET['state']??'');
    if (empty($_SESSION['google_oauth_state']) || !hash_equals($_SESSION['google_oauth_state'],$state)) {
        unset($_SESSION['google_oauth_state']);
        oauth_fail('Проверка OAuth state не пройдена. Начните вход заново.',400);
    }
    unset($_SESSION['google_oauth_state']);
    $code=(string)$_GET['code'];
    $post=http_build_query([
      'code'=>$code,'client_id'=>GOOGLE_CLIENT_ID,'client_secret'=>GOOGLE_CLIENT_SECRET,
      'redirect_uri'=>$redirectUri,'grant_type'=>'authorization_code'
    ]);
    $ch=curl_init('https://oauth2.googleapis.com/token');
    curl_setopt_array($ch,[CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$post,CURLOPT_RETURNTRANSFER=>true,CURLOPT_CONNECTTIMEOUT=>15,CURLOPT_TIMEOUT=>25,CURLOPT_HTTPHEADER=>['Content-Type: application/x-www-form-urlencoded']]);
    $raw=curl_exec($ch); $status=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); $curlErr=curl_error($ch); curl_close($ch);
    if ($raw===false || $status!==200) { error_log('Google token exchange failed: '.$status.' '.$curlErr); oauth_fail('Не удалось подтвердить вход Google. Попробуйте позже.',502); }
    $tokens=json_decode($raw,true);
    $idToken=(string)($tokens['id_token']??'');
    if ($idToken==='') oauth_fail('Google не вернул ID token.',502);

    // Google tokeninfo validates the token signature and issuer. We additionally verify audience and claims.
    $ch=curl_init('https://oauth2.googleapis.com/tokeninfo?id_token='.rawurlencode($idToken));
    curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_CONNECTTIMEOUT=>15,CURLOPT_TIMEOUT=>25]);
    $claimsRaw=curl_exec($ch); $claimsStatus=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); $curlErr=curl_error($ch); curl_close($ch);
    if ($claimsRaw===false || $claimsStatus!==200) { error_log('Google tokeninfo failed: '.$claimsStatus.' '.$curlErr); oauth_fail('Не удалось проверить профиль Google.',502); }
    $claims=json_decode($claimsRaw,true);
    $aud=(string)($claims['aud']??'');
    $iss=(string)($claims['iss']??'');
    $email=strtolower(trim((string)($claims['email']??'')));
    $sub=trim((string)($claims['sub']??''));
    $name=trim((string)($claims['name']??''));
    $emailVerified=filter_var($claims['email_verified']??false,FILTER_VALIDATE_BOOLEAN);
    $exp=(int)($claims['exp']??0);
    if ($aud!==GOOGLE_CLIENT_ID || !in_array($iss,['accounts.google.com','https://accounts.google.com'],true) ||
        !$emailVerified || !filter_var($email,FILTER_VALIDATE_EMAIL) || $sub==='' || $exp<time()) {
        oauth_fail('Google-профиль не прошёл проверку. Убедитесь, что email подтверждён.',403);
    }
    if ($name==='') $name=explode('@',$email)[0];
    $name=mb_substr($name,0,60);

    try {
        $pdo=oauth_db();
        $st=$pdo->prepare('SELECT id,name,email,google_sub FROM users WHERE google_sub=? LIMIT 1');
        $st->execute([$sub]); $u=$st->fetch();
        if (!$u) {
            // Link an existing account only when Google returns its verified matching email.
            $st=$pdo->prepare('SELECT id,name,email,google_sub FROM users WHERE email=? LIMIT 1');
            $st->execute([$email]); $u=$st->fetch();
            if ($u) {
                if (!empty($u['google_sub']) && !hash_equals((string)$u['google_sub'],$sub)) oauth_fail('Этот email уже связан с другим Google-аккаунтом.',409);
                $st=$pdo->prepare('UPDATE users SET google_sub=? WHERE id=?');
                $st->execute([$sub,$u['id']]);
            } else {
                // Existing schema requires password_hash; random unshared hash means Google-only account.
                $randomPassword=password_hash(bin2hex(random_bytes(32)),PASSWORD_DEFAULT);
                $st=$pdo->prepare('INSERT INTO users(name,email,password_hash,google_sub) VALUES(?,?,?,?)');
                $st->execute([$name,$email,$randomPassword,$sub]);
                $u=['id'=>(int)$pdo->lastInsertId(),'name'=>$name,'email'=>$email,'google_sub'=>$sub];
            }
        }
        session_regenerate_id(true);
        $_SESSION['user']=['id'=>(int)$u['id'],'name'=>(string)$u['name'],'email'=>(string)$u['email']];
        $_SESSION['csrf']=bin2hex(random_bytes(32));
        header('Location: index.php',true,303); exit;
    } catch (PDOException $e) {
        error_log('Google OAuth DB error: '.$e->getMessage());
        oauth_fail('Ошибка базы данных при входе через Google. Проверьте SQL-миграцию.',500);
    }
}

// Start OAuth
$state=bin2hex(random_bytes(32));
$_SESSION['google_oauth_state']=$state;
$params=http_build_query([
 'client_id'=>GOOGLE_CLIENT_ID,
 'redirect_uri'=>$redirectUri,
 'response_type'=>'code',
 'scope'=>'openid email profile',
 'state'=>$state,
 'prompt'=>'select_account'
]);
header('Cache-Control: no-store');
header('Location: https://accounts.google.com/o/oauth2/v2/auth?'.$params,true,302);
exit;
