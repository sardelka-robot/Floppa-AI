<?php
declare(strict_types=1);
ini_set('session.use_strict_mode','1');
$https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
session_set_cookie_params([
 'lifetime'=>60*60*24*30,
 'path'=>'/',
 'secure'=>$https,
 'httponly'=>true,
 'samesite'=>'Lax'
]);
ini_set('session.gc_maxlifetime', 60*60*24*30);
session_start();
require __DIR__.'/config.php';

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Content-Security-Policy: default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self';");

function db(): PDO {
 static $pdo=null; if($pdo) return $pdo;
 $dsn='mysql:host='.DB_HOST.';dbname='.DB_NAME.';charset=utf8mb4';
 $pdo=new PDO($dsn,DB_USER,DB_PASS,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC,PDO::ATTR_EMULATE_PREPARES=>false]);
 return $pdo;
}
function json_out($data,int $status=200): never {
 http_response_code($status); header('Content-Type: application/json; charset=utf-8');
 echo json_encode($data,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); exit;
}
function body(): array {
 $v=json_decode(file_get_contents('php://input'),true);
 return is_array($v)?$v:[];
}
function user(): ?array { return $_SESSION['user']??null; }
function need_user(): array { $u=user(); if(!$u) json_out(['error'=>'Сначала войдите в аккаунт'],401); return $u; }
function csrf(): string { if(empty($_SESSION['csrf'])) $_SESSION['csrf']=bin2hex(random_bytes(32)); return $_SESSION['csrf']; }
function check_csrf(): void {
 $t=$_SERVER['HTTP_X_CSRF_TOKEN']??'';
 if(!$t||!hash_equals(csrf(),$t)) json_out(['error'=>'Сессия устарела. Обновите страницу и повторите.'],419);
}

const MAX_ATTACHMENTS = 5;
const MAX_FILE_BYTES = 6 * 1024 * 1024;
const MAX_TOTAL_FILE_BYTES = 12 * 1024 * 1024;
const MAX_TEXT_FILE_BYTES = 512 * 1024;

function attachment_rules(): array {
 return [
  'image/jpeg'=>'image','image/jpg'=>'image','image/png'=>'image','image/webp'=>'image','image/gif'=>'image',
  'application/pdf'=>'pdf',
  'text/plain'=>'text','text/markdown'=>'text','text/csv'=>'text','text/xml'=>'text',
  'application/json'=>'text','application/javascript'=>'text','text/javascript'=>'text',
  'text/html'=>'text','text/css'=>'text','text/x-python'=>'text','text/x-java-source'=>'text',
  'text/x-c++src'=>'text','text/x-csrc'=>'text','application/x-httpd-php'=>'text',
 ];
}
function extension_mime(string $name): string {
 $ext=strtolower(pathinfo($name,PATHINFO_EXTENSION));
 $map=['jpg'=>'image/jpeg','jpeg'=>'image/jpeg','png'=>'image/png','webp'=>'image/webp','gif'=>'image/gif','pdf'=>'application/pdf',
 'txt'=>'text/plain','md'=>'text/markdown','markdown'=>'text/markdown','csv'=>'text/csv','xml'=>'text/xml','json'=>'application/json',
 'js'=>'application/javascript','ts'=>'application/javascript','html'=>'text/html','htm'=>'text/html','css'=>'text/css','py'=>'text/x-python',
 'java'=>'text/x-java-source','c'=>'text/x-csrc','h'=>'text/x-csrc','cpp'=>'text/x-c++src','cc'=>'text/x-c++src','cxx'=>'text/x-c++src',
 'hpp'=>'text/x-c++src','php'=>'application/x-httpd-php'];
 return $map[$ext]??'';
}
function clean_attachment_name(string $name): string {
 $name=preg_replace('/[^\pL\pN._()\- ]/u','_',basename($name))??'file';
 return mb_substr($name,0,180);
}
function build_attachment_parts(array $attachments): array {
 if(count($attachments)>MAX_ATTACHMENTS)json_out(['error'=>'Можно прикрепить не более 5 файлов за сообщение.'],422);
 $rules=attachment_rules();$total=0;$parts=[];$labels=[];
 foreach($attachments as $file){
  if(!is_array($file))json_out(['error'=>'Некорректное вложение.'],422);
  $name=clean_attachment_name((string)($file['name']??'file'));$mime=strtolower(trim((string)($file['type']??'')));
  if(!isset($rules[$mime]))$mime=extension_mime($name);
  $kind=$rules[$mime]??null;$size=(int)($file['size']??0);$data=(string)($file['data']??'');
  if(!$kind)json_out(['error'=>"Файл «{$name}» имеет неподдерживаемый формат. Разрешены изображения, PDF и текстовые файлы."],422);
  if($size<1||$size>MAX_FILE_BYTES)json_out(['error'=>"Файл «{$name}» слишком большой. Максимальный размер — 6 МБ."],422);
  $raw=preg_replace('/^data:[^;]+;base64,/','',$data);$raw=preg_replace('/\s+/','',$raw??'');
  if($raw===''||strlen($raw)>($size*2+2048))json_out(['error'=>"Не удалось прочитать файл «{$name}»."],422);
  $bytes=base64_decode($raw,true);
  if($bytes===false||strlen($bytes)!==$size)json_out(['error'=>"Повреждённые данные файла «{$name}»."],422);
  $total+=strlen($bytes);if($total>MAX_TOTAL_FILE_BYTES)json_out(['error'=>'Суммарный размер вложений не должен превышать 12 МБ.'],422);
  if($kind==='image'){
   $info=@getimagesizefromstring($bytes);
   if(!$info||empty($info['mime'])||!isset($rules[$info['mime']])||$rules[$info['mime']]!=='image')json_out(['error'=>"Файл «{$name}» не является корректным изображением."],422);
   $parts[]=['inline_data'=>['mime_type'=>$info['mime'],'data'=>base64_encode($bytes)]];
  }elseif($kind==='pdf'){
   if(substr($bytes,0,5)!=='%PDF-')json_out(['error'=>"Файл «{$name}» не является корректным PDF."],422);
   $parts[]=['inline_data'=>['mime_type'=>'application/pdf','data'=>base64_encode($bytes)]];
  }else{
   if($size>MAX_TEXT_FILE_BYTES)json_out(['error'=>"Текстовый файл «{$name}» слишком большой. Максимум — 512 КБ."],422);
   $text=@mb_convert_encoding($bytes,'UTF-8','UTF-8,Windows-1252,ISO-8859-1');
   if(str_contains($text,"\0"))json_out(['error'=>"Файл «{$name}» не похож на текстовый файл."],422);
   $parts[]=['text'=>"Вложенный текстовый файл: {$name}\n---\n{$text}\n---"];
  }
  $labels[]=$name;
 }
 return [$parts,$labels];
}
function gemini_generate(array $contents): string {
 $payload=[
  'system_instruction'=>['parts'=>[['text'=>FLOPPA_SYSTEM_PROMPT]]],
  'contents'=>$contents,
  'generationConfig'=>['temperature'=>0.7,'maxOutputTokens'=>(int)($GLOBALS['GEMINI_MAX_OUTPUT_TOKENS']??4096)]
 ];
 $url='https://generativelanguage.googleapis.com/v1beta/models/'.rawurlencode(GEMINI_MODEL).':generateContent?key='.rawurlencode(GEMINI_API_KEY);
 if(!function_exists('curl_init')) json_out(['error'=>'На хостинге не включён PHP cURL. Обратитесь в поддержку InfinityFree.'],503);
 $ch=curl_init($url);
 curl_setopt_array($ch,[CURLOPT_POST=>true,CURLOPT_HTTPHEADER=>['Content-Type: application/json'],CURLOPT_POSTFIELDS=>json_encode($payload,JSON_UNESCAPED_UNICODE),CURLOPT_RETURNTRANSFER=>true,CURLOPT_CONNECTTIMEOUT=>15,CURLOPT_TIMEOUT=>90]);
 $response=curl_exec($ch); $err=curl_error($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
 if($response===false){error_log('Gemini transport: '.$err);json_out(['error'=>'Хостинг не смог соединиться с Gemini API. Возможно, InfinityFree блокирует исходящие подключения.'],502);}
 $data=json_decode($response,true);
 if($code<200||$code>=300){$msg=$data['error']['message']??'Gemini API вернул ошибку';error_log('Gemini HTTP '.$code.': '.$msg);json_out(['error'=>'Ошибка Gemini API (HTTP '.$code.'). Проверьте ключ, модель и доступ к API в config.php.'],502);}
 $GLOBALS['GEMINI_LAST_TOKENS']=(int)($data['usageMetadata']['promptTokenCount']??0)+(int)($data['usageMetadata']['candidatesTokenCount']??0);
 $answer=trim((string)($data['candidates'][0]['content']['parts'][0]['text']??''));
 if($answer==='') json_out(['error'=>'Gemini не вернул текст. Попробуйте переформулировать запрос.'],502);
 return $answer;
}
function history_contents(int $chatId, ?int $excludeAssistantId=null): array {
 $sql='SELECT id,role,content FROM messages WHERE chat_id=?';
 $params=[$chatId];
 if($excludeAssistantId!==null){$sql.=' AND id<>?';$params[]=$excludeAssistantId;}
 $sql.=' ORDER BY id DESC LIMIT 20';
 $st=db()->prepare($sql);$st->execute($params);$rows=array_reverse($st->fetchAll());
 $contents=[];
 foreach($rows as $r) $contents[]=['role'=>$r['role']==='assistant'?'model':'user','parts'=>[['text'=>$r['content']]]];
 return $contents;
}
function api_call(): never {
 $action=$_GET['api']??''; $method=$_SERVER['REQUEST_METHOD'];
 if($method==='POST') check_csrf();
 if($action==='session' && $method==='GET'){ $day=date('Y-m-d');if(($_SESSION['guest_day']??'')!==$day){$_SESSION['guest_day']=$day;$_SESSION['guest_used']=0;$_SESSION['guest_history']=[];} json_out(['user'=>user()?['id'=>user()['id'],'name'=>user()['name'],'email'=>user()['email']]:null,'csrf'=>csrf(),'guest'=>['used'=>(int)($_SESSION['guest_used']??0),'limit'=>5000,'remaining'=>max(0,5000-(int)($_SESSION['guest_used']??0))]]); }
 if($action==='register' && $method==='POST'){
  $b=body();$name=trim((string)($b['name']??''));$email=strtolower(trim((string)($b['email']??'')));$pass=(string)($b['password']??'');
  if(mb_strlen($name)<2||mb_strlen($name)>60||!filter_var($email,FILTER_VALIDATE_EMAIL)||strlen($pass)<10||strlen($pass)>200)json_out(['error'=>'Введите имя, корректный email и пароль от 10 символов.'],422);
  try{$st=db()->prepare('INSERT INTO users(name,email,password_hash) VALUES(?,?,?)');$st->execute([$name,$email,password_hash($pass,PASSWORD_DEFAULT)]);}catch(PDOException $e){if($e->getCode()==='23000')json_out(['error'=>'Этот email уже зарегистрирован.'],409);error_log($e->getMessage());json_out(['error'=>'Не удалось создать аккаунт.'],500);}
  session_regenerate_id(true);$_SESSION['user']=['id'=>(int)db()->lastInsertId(),'name'=>$name,'email'=>$email];$_SESSION['csrf']=bin2hex(random_bytes(32));json_out(['ok'=>true,'csrf'=>csrf()]);
 }
 if($action==='login' && $method==='POST'){
  $b=body();$email=strtolower(trim((string)($b['email']??'')));$pass=(string)($b['password']??'');
  $st=db()->prepare('SELECT id,name,email,password_hash FROM users WHERE email=? LIMIT 1');$st->execute([$email]);$u=$st->fetch();
  if(!$u||!password_verify($pass,$u['password_hash']))json_out(['error'=>'Неверный email или пароль.'],401);
  session_regenerate_id(true);$_SESSION['user']=['id'=>(int)$u['id'],'name'=>$u['name'],'email'=>$u['email']];$_SESSION['csrf']=bin2hex(random_bytes(32));json_out(['ok'=>true,'csrf'=>csrf()]);
 }
 if($action==='logout' && $method==='POST'){$_SESSION=[];if(ini_get('session.use_cookies')){$p=session_get_cookie_params();setcookie(session_name(),'',time()-42000,$p['path'],$p['domain'],$p['secure'],$p['httponly']);}session_destroy();json_out(['ok'=>true]);}
 if($action==='guest-send' && $method==='POST'){
  if(user()) json_out(['error'=>'Вы уже вошли в аккаунт.'],409);
  $b=body();$text=trim((string)($b['message']??''));$attachments=$b['attachments']??[];
  if(($text===''&&empty($attachments))||mb_strlen($text)>20000)json_out(['error'=>'Сообщение пустое или слишком длинное (максимум 20 000 символов).'],422);
  $day=date('Y-m-d');
  if(($_SESSION['guest_day']??'')!==$day){$_SESSION['guest_day']=$day;$_SESSION['guest_used']=0;$_SESSION['guest_history']=[];}
  $used=(int)($_SESSION['guest_used']??0);$limit=5000;
  if($used >= $limit)json_out(['error'=>'Вы использовали дневной гостевой лимит 5 000 токенов. Зарегистрируйтесь или войдите, чтобы продолжить.','quota'=>['used'=>$used,'limit'=>$limit,'remaining'=>0]],429);
  [$fileParts,$labels]=build_attachment_parts(is_array($attachments)?$attachments:[]);
  $contents=$_SESSION['guest_history']??[];
  $parts=[['text'=>$text!==''?$text:'Проанализируй прикреплённые файлы.'],...$fileParts];
  $contents[]=['role'=>'user','parts'=>$parts];
  $inputBytes=0;foreach($contents as $item){foreach(($item['parts']??[]) as $part){$inputBytes+=strlen((string)($part['text']??''));}}
  $estimatedInput=(int)ceil($inputBytes/4);if($estimatedInput >= ($limit-$used))json_out(['error'=>'Остатка гостевого лимита недостаточно для этого запроса. Зарегистрируйтесь или попробуйте завтра.','quota'=>['used'=>$used,'limit'=>$limit,'remaining'=>max(0,$limit-$used)]],429);
  $GLOBALS['GEMINI_MAX_OUTPUT_TOKENS']=max(1,min(4096,$limit-$used-$estimatedInput));
  $answer=gemini_generate($contents);
  unset($GLOBALS['GEMINI_MAX_OUTPUT_TOKENS']);
  // Conservative token estimate (roughly 1 token per 4 UTF-8 bytes); enforce on server.
  $inputBytes=0;foreach($contents as $item){foreach(($item['parts']??[]) as $part){$inputBytes+=strlen((string)($part['text']??''));}}
  $turnTokens=(int)($GLOBALS['GEMINI_LAST_TOKENS']??0);
  if($turnTokens<1)$turnTokens=(int)ceil($inputBytes/4)+(int)ceil(strlen($answer)/4);
  if($used+$turnTokens>$limit){$turnTokens=max(0,$limit-$used);}
  $_SESSION['guest_used']=$used+$turnTokens;
  $contents[]=['role'=>'model','parts'=>[['text'=>$answer]]];
  $_SESSION['guest_history']=array_slice($contents,-20);
  json_out(['answer'=>$answer,'message_id'=>0,'attachments'=>$labels,'quota'=>['used'=>$_SESSION['guest_used'],'limit'=>$limit,'remaining'=>max(0,$limit-$_SESSION['guest_used'])]]);
 }
 if($action==='guest-reset' && $method==='POST'){$_SESSION['guest_history']=[];json_out(['ok'=>true]);}
 $u=need_user();$uid=(int)$u['id'];
 if($action==='chats' && $method==='GET'){$st=db()->prepare('SELECT id,title,updated_at FROM chats WHERE user_id=? ORDER BY updated_at DESC, id DESC');$st->execute([$uid]);json_out(['chats'=>$st->fetchAll()]);}
 if($action==='chat' && $method==='GET'){$id=(int)($_GET['id']??0);$st=db()->prepare('SELECT id,title FROM chats WHERE id=? AND user_id=?');$st->execute([$id,$uid]);$c=$st->fetch();if(!$c)json_out(['error'=>'Чат не найден'],404);$m=db()->prepare('SELECT id,role,content,created_at FROM messages WHERE chat_id=? ORDER BY id');$m->execute([$id]);json_out(['chat'=>$c,'messages'=>$m->fetchAll()]);}
 if($action==='chat' && $method==='POST'){$b=body();$title=trim((string)($b['title']??'Новый чат'));$title=mb_substr($title?:'Новый чат',0,120);$st=db()->prepare('INSERT INTO chats(user_id,title) VALUES(?,?)');$st->execute([$uid,$title]);json_out(['id'=>(int)db()->lastInsertId()]);}
 if($action==='rename-chat' && $method==='POST'){
   $b=body();$id=(int)($b['id']??0);$title=trim((string)($b['title']??''));
   if(!$id||$title===''||mb_strlen($title)>120)json_out(['error'=>'Название должно содержать от 1 до 120 символов.'],422);
   $st=db()->prepare('UPDATE chats SET title=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?');$st->execute([$title,$id,$uid]);
   if(!$st->rowCount()){ $check=db()->prepare('SELECT id FROM chats WHERE id=? AND user_id=?');$check->execute([$id,$uid]);if(!$check->fetch())json_out(['error'=>'Чат не найден'],404); }
   json_out(['ok'=>true,'title'=>$title]);
  }
  if($action==='delete-chat' && $method==='POST'){$id=(int)(body()['id']??0);$st=db()->prepare('DELETE FROM chats WHERE id=? AND user_id=?');$st->execute([$id,$uid]);json_out(['ok'=>true]);}
 if($action==='delete-all' && $method==='POST'){$st=db()->prepare('DELETE FROM chats WHERE user_id=?');$st->execute([$uid]);json_out(['ok'=>true]);}
 if($action==='send' && $method==='POST'){
  $b=body();$chatId=(int)($b['chat_id']??0);$text=trim((string)($b['message']??''));$attachments=$b['attachments']??[];
  if(!$chatId||($text===''&&empty($attachments))||mb_strlen($text)>20000)json_out(['error'=>'Сообщение пустое или слишком длинное (максимум 20 000 символов).'],422);
  $st=db()->prepare('SELECT id FROM chats WHERE id=? AND user_id=?');$st->execute([$chatId,$uid]);if(!$st->fetch())json_out(['error'=>'Чат не найден'],404);
  $count=db()->prepare('SELECT COUNT(*) FROM messages WHERE chat_id=?');$count->execute([$chatId]);if((int)$count->fetchColumn()>100)json_out(['error'=>'В этом чате достигнут лимит сообщений. Создайте новый чат.'],429);
  [$fileParts,$labels]=build_attachment_parts(is_array($attachments)?$attachments:[]);
  $storedText=$text;
  if($labels)$storedText.=($storedText!==''?"\n\n":'').'Вложения: '.implode(', ',$labels);
  $ins=db()->prepare('INSERT INTO messages(chat_id,role,content) VALUES(?,?,?)');$ins->execute([$chatId,'user',$storedText]);
  $contents=history_contents($chatId);
  if($fileParts){
   $lastIndex=count($contents)-1;
   if($lastIndex>=0 && $contents[$lastIndex]['role']==='user'){
    $contents[$lastIndex]['parts']=[['text'=>$text!==''?$text:'Проанализируй прикреплённые файлы.'],...$fileParts];
   }
  }
  $answer=gemini_generate($contents);
  $ins->execute([$chatId,'assistant',$answer]);$messageId=(int)db()->lastInsertId();
  $up=db()->prepare("UPDATE chats SET title=CASE WHEN title='Новый чат' THEN ? ELSE title END,updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?");$up->execute([mb_substr($text!==''?$text:$labels[0],0,55),$chatId,$uid]);
  json_out(['answer'=>$answer,'message_id'=>$messageId,'attachments'=>$labels]);
 }
 if($action==='regenerate' && $method==='POST'){
  $b=body();$chatId=(int)($b['chat_id']??0);if(!$chatId)json_out(['error'=>'Не указан чат.'],422);
  $st=db()->prepare('SELECT id FROM chats WHERE id=? AND user_id=?');$st->execute([$chatId,$uid]);if(!$st->fetch())json_out(['error'=>'Чат не найден'],404);
  $last=db()->prepare("SELECT id,role,content FROM messages WHERE chat_id=? ORDER BY id DESC LIMIT 2");$last->execute([$chatId]);$rows=$last->fetchAll();
  if(!$rows||$rows[0]['role']!=='assistant')json_out(['error'=>'В этом чате пока нечего перегенерировать.'],422);
  $assistantId=(int)$rows[0]['id'];$contents=history_contents($chatId,$assistantId);
  $attachments=$b['attachments']??[];
  if(is_array($attachments)&&$attachments){
   [$fileParts,$labels]=build_attachment_parts($attachments);
   $lastIndex=count($contents)-1;
   if($lastIndex>=0&&$contents[$lastIndex]['role']==='user')$contents[$lastIndex]['parts']=[['text'=>trim((string)$contents[$lastIndex]['parts'][0]['text'])],...$fileParts];
  }
  $answer=gemini_generate($contents);
  $up=db()->prepare('UPDATE messages SET content=? WHERE id=? AND chat_id=?');$up->execute([$answer,$assistantId,$chatId]);
  $touch=db()->prepare('UPDATE chats SET updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?');$touch->execute([$chatId,$uid]);
  json_out(['answer'=>$answer,'message_id'=>$assistantId]);
 }
 json_out(['error'=>'Неизвестный запрос'],404);
}
if(isset($_GET['api'])) { try{api_call();}catch(Throwable $e){error_log((string)$e);json_out(['error'=>'Внутренняя ошибка сервера. Проверьте настройки базы данных.'],500);} }
?><!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#101014">
<title>Floppa AI</title>
<link rel="icon" type="image/png" href="/favicon.png">
<link rel="shortcut icon" type="image/png" href="/favicon.png">
<meta name="description" content="Floppa AI — бесплатная нейросеть для общения, кода, учёбы и повседневных задач. Задавайте любые вопросы, получайте помощь с программированием и просто общайтесь без ограничений.">
<meta name="keywords" content="Floppa AI, Клайв, нейросеть, бесплатная нейросеть, ИИ ассистент, чат с ИИ, помощь с кодом, AI ассистент">
<meta name="author" content="Floppa AI">
<meta name="robots" content="index, follow">
<meta property="og:type" content="website">
<meta property="og:title" content="Floppa AI — бесплатная нейросеть для общения и кода">
<meta property="og:description" content="Задавайте любые вопросы, получайте помощь с кодом и общайтесь с Floppa AI бесплатно.">
<meta property="og:url" content="https://Floppa.ct.ws/">
<meta property="og:site_name" content="Floppa AI">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="Floppa AI — бесплатная нейросеть">
<meta name="twitter:description" content="Бесплатная нейросеть для общения, кода и учёбы.">
<style>
:root{--bg:#101014;--panel:#17171d;--panel2:#202027;--line:#2a2a33;--text:#f4f3f8;--muted:#9998a6;--purple:#ffffff;--purple2:#ffffff;--indigo:#ffffff;--icon:#c8c5d5}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 Inter,system-ui,-apple-system,Segoe UI,sans-serif;height:100dvh}button,input,textarea{font:inherit}button{cursor:pointer;color:inherit;border:0}.app{display:none;height:100dvh;display:flex;overflow:hidden}.sidebar{width:270px;flex-shrink:0;background:#131318;border-right:1px solid var(--line);display:flex;flex-direction:column;padding:18px 13px;gap:12px}.sidebar.closed{display:none}.brand{display:flex;align-items:center;justify-content:space-between;font-size:26px;font-weight:850;letter-spacing:-.7px;padding:4px 10px 15px}.brandcopy{display:flex;align-items:baseline;gap:5px}.brandcopy span{color:inherit}.sidebar-head{display:flex;align-items:center;justify-content:space-between;gap:10px}.sidebar-close{width:34px;height:34px;border-radius:10px;background:transparent;border:1px solid transparent;color:#aaa7b3;display:grid;place-items:center}.sidebar-close:hover{background:var(--panel2);border-color:var(--line);color:#fff}.sidebar-close svg{width:18px;height:18px;stroke:currentColor}.newchat,.navbtn{display:flex;align-items:center;gap:10px;padding:12px 13px;border-radius:12px;background:transparent;text-align:left;color:#dedde5;width:100%}.newchat{display:flex;align-items:center;gap:8px;background:#fff;color:#111;font-weight:700;justify-content:center}.newchat svg{width:17px;height:17px;stroke:currentColor}.newchat:hover{background:#ededed}.historylabel{font-size:12px;color:var(--muted);padding:14px 10px 3px;text-transform:uppercase;letter-spacing:1px}.history{overflow:auto;flex:1}.chatitem{display:flex;align-items:center;gap:7px;padding:10px;border-radius:9px;color:#c5c4ce;cursor:pointer;font-size:14px}.chatitem:hover,.chatitem.active{background:var(--panel2);color:white}.chatitem span{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1}.chatitem button{background:transparent;color:#777;padding:2px 4px}.sidebarbottom{border-top:1px solid var(--line);padding-top:10px}.userline{display:flex;align-items:center;gap:10px;padding:10px;color:#ccc;font-size:13px}.avatar{width:30px;height:30px;border-radius:50%;background:#3a244f;color:#e7cfff;display:grid;place-items:center;font-weight:700}.main{flex:1;min-width:0;display:flex;flex-direction:column;position:relative}.topbar{height:60px;border-bottom:1px solid var(--line);display:flex;align-items:center;padding:0 22px;gap:12px}.mobilebrand{display:none;align-items:center;font-weight:850;font-size:24px;letter-spacing:-.8px}.mobilebrand span{color:inherit}.topright{display:none}.topbrand{font-size:18px;font-weight:850;letter-spacing:-.6px;white-space:nowrap;order:1;margin-left:0}.topbrand:after{content:"•";display:inline-block;color:var(--muted);font-size:19px;margin:0 12px;vertical-align:1px}.topchat-title{font-size:15px;font-weight:600;color:#c7c5d0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:min(42vw,420px);min-width:0;flex:0 1 auto;margin-left:0;padding:0;border:0;order:2}.topbar>.navbtn{order:0}.mobilebrand{order:1}.mobilebrand:after{content:"•";display:inline-block;color:var(--muted);font-size:19px;margin:0 9px;vertical-align:1px}.chat-edit{background:transparent;color:#8f8d99;padding:4px 5px;border-radius:7px;display:grid;place-items:center}.chat-edit:hover{background:#33323b;color:#fff}.chat-edit svg{width:15px;height:15px;stroke:currentColor}.logout-btn{display:flex;align-items:center;justify-content:center;gap:9px;background:linear-gradient(135deg,#352126,#291b20);border:1px solid #63343d;color:#ffb4bd;border-radius:12px;padding:10px 15px;font-weight:700;min-width:110px;transition:background .15s,border-color .15s,transform .15s}.logout-btn:hover{background:#49252d;border-color:#92505b;transform:translateY(-1px)}.logout-btn svg{width:17px;height:17px;stroke:currentColor}.messages{flex:1;overflow:auto;padding:28px 18px 150px}.welcome{min-height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding-bottom:70px}.welcome h1{font-size:clamp(27px,4vw,40px);line-height:1.15;letter-spacing:-1.5px;margin:0 0 12px}.welcome h1 span{color:inherit}.welcome p{color:var(--muted);margin:0}.msgwrap{max-width:820px;margin:0 auto 26px;display:flex;gap:12px}.msgbody{min-width:0;overflow-wrap:anywhere;padding-top:2px;max-width:100%}.msgbody.usertext{white-space:pre-wrap;background:#24232c;padding:12px 15px;border-radius:16px;margin-left:auto;max-width:85%}.msgwrap.user{justify-content:flex-end}.msgwrap.user .msgavatar{display:none}.msgcontent{min-width:0;overflow-wrap:anywhere}.msgcontent h1,.msgcontent h2,.msgcontent h3{line-height:1.25;margin:1.05em 0 .5em}.msgcontent h1{font-size:1.55em}.msgcontent h2{font-size:1.32em}.msgcontent h3{font-size:1.12em}.msgcontent p{margin:.55em 0}.msgcontent ul,.msgcontent ol{margin:.5em 0;padding-left:1.4em}.msgcontent li{margin:.22em 0}.msgcontent blockquote{margin:.7em 0;padding:.2em 0 .2em 13px;border-left:3px solid #fff;color:#c9c7d1}.msgcontent table{border-collapse:collapse;width:max-content;max-width:100%;margin:.8em 0;font-size:.94em}.msgcontent th,.msgcontent td{border:1px solid var(--line);padding:7px 10px;text-align:left}.msgcontent th{background:var(--panel2)}.msgcontent a{color:#d4aaff;text-decoration:underline}.inline-code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:#25242c;border:1px solid #34333d;border-radius:5px;padding:.1em .35em;font-size:.92em}.codewrap{position:relative;margin:12px 0;border:1px solid #30303a;border-radius:12px;background:#0d0d11;overflow:hidden}.codehead{display:flex;justify-content:space-between;align-items:center;padding:7px 10px;background:#17171d;border-bottom:1px solid #30303a;color:#92909d;font-size:11px}.codecopy{background:transparent;color:#aaa7b4;padding:3px 7px;border-radius:6px}.codecopy:hover{background:#292832;color:white}.codewrap pre{margin:0;padding:13px 14px;overflow:auto;-webkit-overflow-scrolling:touch;font:13px/1.55 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;white-space:pre;tab-size:2}.codewrap code{font:inherit}.tok-keyword{color:#d8a7ff}.tok-string{color:#a8d8a8}.tok-number{color:#e7c48b}.tok-comment{color:#7f8290}.tok-function{color:#8fc8ff}.actionbar{display:flex;gap:5px;margin-top:10px;opacity:.95}.actionbar button{width:34px;height:34px;display:grid;place-items:center;background:#18181e;border:1px solid #2e2d37;color:#8f8d99;border-radius:9px;transition:background .15s,border-color .15s,color .15s,transform .12s}.actionbar button svg{width:16px;height:16px;stroke:currentColor}.actionbar button:hover{background:#24232c;border-color:#494653;color:#eee;transform:translateY(-1px)}.actionbar button.active{color:#e4cfff;background:#2a2035;border-color:#fff}.attachments-preview{display:flex;flex-wrap:wrap;gap:7px;padding:8px 4px 4px}.attachment-chip{display:flex;align-items:center;gap:7px;background:#202027;border:1px solid #35343e;border-radius:11px;padding:5px 7px;max-width:min(100%,280px);font-size:12px;color:#d8d6df}.attachment-chip img{width:36px;height:36px;object-fit:cover;border-radius:7px}.attachment-chip .file-icon{width:36px;height:36px;border-radius:7px;background:#17171d;border:1px solid #34333d;display:grid;place-items:center;color:#bdb9c8}.attachment-chip .file-icon svg{width:18px;height:18px}.attachment-chip .remove-attachment{width:26px;height:26px;display:grid;place-items:center;background:#2a2931;border:1px solid #3b3944;color:#aaa;padding:0;border-radius:7px}.attachment-chip .remove-attachment svg{width:13px;height:13px}.attachment-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:7px}.attachment-badge{display:inline-flex;align-items:center;gap:5px;font-size:11px;color:#aaa7b3;background:#24232c;border:1px solid #34333d;border-radius:8px;padding:4px 7px}.attachment-badge svg{width:12px;height:12px;flex:0 0 auto}.composer-area{position:absolute;bottom:0;left:0;right:0;padding:16px max(18px,calc((100% - 850px)/2)) 18px;background:linear-gradient(transparent,var(--bg) 24%)}.composer{max-width:850px;margin:auto;border:1px solid #35353e;background:#1b1b21;border-radius:26px;padding:11px 12px 10px;box-shadow:0 10px 34px #0006}.composer:focus-within{border-color:#55555f}.composer textarea{width:100%;resize:none;max-height:180px;min-height:42px;background:transparent;color:var(--text);border:0;outline:0;padding:8px 9px 7px;font-size:15px}.composer textarea::placeholder{color:#85838d}.composerbottom{display:flex;align-items:center;justify-content:space-between;gap:12px;padding-top:7px}.hint{font-size:11px;color:#6f6e78;padding:0 8px;text-align:center;flex:1;min-width:0}.composer-tools{display:flex;align-items:center;gap:8px}.attachbtn,.send{width:40px;height:40px;flex:0 0 40px;border-radius:12px;background:#202027;border:1px solid #34333d;color:#aaa7b3;display:grid;place-items:center;box-shadow:none;transition:background .15s,border-color .15s,color .15s,transform .12s}.attachbtn svg,.send svg{width:18px;height:18px}.attachbtn:hover,.send:hover{background:#292931;border-color:#55555f;color:#fff;transform:translateY(-1px)}.send.ready{background:#fff;color:#111;border-color:#fff}.send.ready:hover{background:#f0f0f0;color:#111}.send:focus-visible,.attachbtn:focus-visible{outline:2px solid #fff;outline-offset:2px}.send:active,.attachbtn:active{transform:scale(.96)}.send:disabled{opacity:.4;cursor:default;transform:none}.fileinput{display:none}.authscreen{position:fixed;inset:0;background:#0d0d11;z-index:10;display:flex;align-items:center;justify-content:center;padding:20px}.authcard{width:min(420px,100%);background:var(--panel);border:1px solid var(--line);border-radius:22px;padding:28px}.authcard h2{margin:0 0 6px}.authcard p{color:var(--muted);margin:0 0 20px}.authcard input{width:100%;background:#101015;border:1px solid var(--line);border-radius:12px;padding:13px;color:white;margin:7px 0;outline-color:var(--purple)}.primary{width:100%;background:#fff;color:#111;padding:13px;border-radius:12px;margin-top:12px;font-weight:750}.switchauth{display:block;margin:15px auto 0;background:transparent;color:#fff}.settings{position:fixed;inset:0;background:#0009;z-index:8;display:none;align-items:center;justify-content:center;padding:18px}.modal{width:min(440px,100%);background:var(--panel);border:1px solid var(--line);border-radius:20px;padding:22px}.modalhead{display:flex;justify-content:space-between;align-items:center}.modalhead h2{margin:0}.close{background:transparent;font-size:24px;color:var(--muted)}.settingrow{padding:17px 0;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:14px}.settingrow select{background:#25242c;color:white;border:1px solid var(--line);padding:9px;border-radius:9px}.danger{color:#ff8b8b;background:#3a2025;padding:10px 13px;border-radius:10px}.toast{position:fixed;z-index:30;left:50%;bottom:88px;transform:translateX(-50%) translateY(8px);background:#f5f5f7;color:#151518;border:1px solid #ffffff;border-radius:9px;padding:8px 12px;display:none;width:max-content;max-width:min(360px,calc(100% - 28px));font-size:13px;line-height:1.35;font-weight:600;text-align:center;box-shadow:0 8px 24px #0008;opacity:0;transition:opacity .16s ease,transform .16s ease}.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}.typing{color:var(--muted);font-size:13px}.closeMenuBtn{display:none}.topbar .navbtn svg{width:19px;height:19px;stroke:currentColor}.sidebar-overlay{display:none;position:fixed;inset:0;background:#0008;z-index:5}.navbtn svg{width:18px;height:18px;stroke:currentColor;flex:0 0 auto}.avatar{width:30px;height:30px;border-radius:50%;background:#3a244f;color:#e7cfff;display:grid;place-items:center;font-weight:700}.avatar svg{width:18px;height:18px;stroke:currentColor}@media(max-width:700px){.topbrand{display:none}.topchat-title{max-width:42vw;margin-left:auto;padding:0;border:0;font-size:14px;order:2}.mobilebrand{order:1;font-size:18px}.mobilebrand:after{margin:0 7px}.sidebar{position:fixed;z-index:6;left:-290px;top:0;bottom:0;transition:left .2s;width:280px;box-shadow:10px 0 40px #0007}.sidebar.open{left:0}.sidebar.closed{display:flex;left:-290px}.sidebar-close{display:grid}.sidebar-overlay.show{display:block}.topbar{height:56px;padding:0 14px}.mobilebrand{display:flex}.topright{display:none}.messages{padding:22px 14px 145px}.composer-area{padding:12px 12px max(12px,env(safe-area-inset-bottom))}.composer{border-radius:19px}.welcome{padding-bottom:40px}.welcome p{font-size:14px}.msgwrap{gap:9px}.msgbody.usertext{max-width:92%}.hint{display:none}.actionbar{opacity:1}.send,.attachbtn{width:40px;height:40px;flex-basis:40px}.composerbottom{gap:10px}.send{margin-left:auto}.msgcontent table{display:block;overflow-x:auto}.codewrap pre{font-size:12px}.send{width:40px;height:40px}}
/* Header order fix: brand, separator, chat title immediately after it */
.topbar{justify-content:flex-start!important;gap:6px!important}
.topbrand{order:1!important;margin-left:0!important;flex:0 0 auto!important}.topbrand:after{margin-left:6px!important;margin-right:4px!important}
.topchat-title{order:2!important;margin-left:0!important;flex:0 1 auto!important;max-width:min(42vw,420px)!important}
.mobilebrand{order:1!important;flex:0 0 auto!important}
@media(max-width:700px){.topchat-title{order:2!important;margin-left:0!important;flex:0 1 auto!important;max-width:42vw!important}.mobilebrand{margin-right:0!important}.mobilebrand:after{margin-left:6px!important;margin-right:4px!important}}
</style></head><body>
<div class="app" id="appRoot"><aside class="sidebar" id="sidebar"><div class="sidebar-head"><div class="brand"><div class="brandcopy">Floppa <span>AI</span></div></div><button class="sidebar-close" id="sidebarClose" type="button" aria-label="Закрыть боковую панель" title="Закрыть боковую панель"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18"/></svg></button></div><button class="newchat" id="newChat"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg><span>Новый чат</span></button><div class="historylabel">История</div><div class="history" id="history"></div><div class="sidebarbottom"><button class="navbtn" id="settingsBtn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3.5l1.1 1.9 2.2.5 1.7-1.2 2 2-1.2 1.7.5 2.2 1.9 1.1v2.8l-1.9 1.1-.5 2.2 1.2 1.7-2 2-1.7-1.2-2.2.5-1.1 1.9H9.2l-1.1-1.9-2.2-.5-1.7 1.2-2-2 1.2-1.7-.5-2.2L1 14.5v-2.8l1.9-1.1.5-2.2L2.2 6.7l2-2 1.7 1.2 2.2-.5 1.1-1.9H12z"/><circle cx="10.6" cy="13.1" r="3.1"/></svg> Настройки</button><div class="userline"><div class="avatar" id="avatar">?</div><span id="userName">Гость</span></div><button class="navbtn" id="loginBtn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 17l5-5-5-5"/><path d="M15 12H4"/><path d="M14 4h4a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-4"/></svg> Войти / Регистрация</button></div></aside><div class="sidebar-overlay" id="sidebarOverlay"></div><main class="main"><header class="topbar"><button class="navbtn" id="menuBtn" aria-label="Открыть меню" title="Открыть меню" style="width:auto;padding:6px 9px"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16"/></svg></button><div class="topbrand">Floppa AI</div><div class="topchat-title" id="activeChatTitle" title="Текущий чат"></div><div class="mobilebrand">Floppa <span>AI</span></div><div class="topright" id="quotaLabel">Ваш интеллектуальный собеседник</div></header><section class="messages" id="messages"><div class="welcome" id="welcome"><h1>Чем могу <span>помочь</span>?</h1><p>Задайте вопрос, обсудим идею или создадим что-то вместе.</p></div></section><div class="composer-area"><div class="composer"><div class="attachments-preview" id="attachmentsPreview"></div><textarea id="prompt" rows="1" placeholder="Напишите сообщение Floppa AI…"></textarea><div class="composerbottom"><input class="fileinput" id="fileInput" type="file" multiple accept="image/jpeg,image/png,image/webp,image/gif,application/pdf,text/plain,text/markdown,text/csv,text/xml,application/json,application/javascript,text/javascript,text/html,text/css,text/x-python,text/x-java-source,text/x-c++src,text/x-csrc,application/x-httpd-php"><button class="attachbtn" id="attachBtn" type="button" aria-label="Прикрепить файл" title="Прикрепить файл"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20.2 11.4l-7.9 7.9a5 5 0 0 1-7.1-7.1l8.1-8.1a3.6 3.6 0 0 1 5.1 5.1l-8.1 8.1a2.1 2.1 0 0 1-3-3l7.4-7.4"/></svg></button><div class="hint">Floppa AI может ошибаться. Проверяйте важную информацию.</div><button class="send" id="send" aria-label="Отправить" title="Отправить"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12h14"/><path d="M13 6l6 6-6 6"/></svg></button></div></div></div></main></div>
<div class="authscreen" id="auth" style="display:none"><div class="authcard"><h2 id="authTitle">Войти в Floppa AI</h2><p id="authDesc">Общайтесь бесплатно в гостевом режиме или войдите, чтобы сохранять историю.</p><button class="primary" id="guestStart" type="button">Продолжить как гость · 5 000 токенов в день</button><button class="switchauth" id="authLoginStart" type="button">Войти / Создать аккаунт</button><a class="primary" id="googleLogin" href="google_auth.php" style="display:block;text-align:center;text-decoration:none;margin:12px 0;background:#fff;color:#111">Продолжить с Google</a><div style="text-align:center;color:var(--muted);font-size:12px;margin:8px 0">или через email</div><form id="authForm" style="display:none"><input id="authName" placeholder="Ваше имя" autocomplete="name" style="display:none"><input id="authEmail" type="email" placeholder="Email" autocomplete="email" required><input id="authPassword" type="password" placeholder="Пароль (минимум 10 символов)" autocomplete="current-password" minlength="10" required><button class="primary" id="authSubmit">Войти</button></form><button class="switchauth" id="switchAuth">Создать аккаунт</button><button class="switchauth" id="closeAuth" style="display:none">Закрыть</button></div></div>
<div class="settings" id="settings"><div class="modal"><div class="modalhead"><h2>Настройки</h2><button class="close" id="closeSettings">×</button></div><div class="settingrow"><span>Язык интерфейса</span><select id="language"><option value="ru">Русский</option><option value="en">English</option></select></div><div class="settingrow"><span>Документация Floppa AI</span><a class="navbtn" href="https://floppa.ct.ws/documentation.txt" target="_blank" rel="noopener noreferrer" style="width:auto;text-decoration:none;white-space:nowrap">Открыть</a></div><div class="settingrow"><span>Удалить все мои чаты</span><button class="danger" id="deleteAll">Удалить</button></div><div class="settingrow"><span>Выйти из аккаунта</span><button class="logout-btn" id="logout"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 17l5-5-5-5"/><path d="M15 12H4"/><path d="M14 4h4a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-4"/></svg><span>Выйти</span></button></div></div></div><div class="toast" id="toast"></div>
<script>
let csrf='',currentUser=null,currentChat=null,chats=[],registerMode=false,busy=false,selectedFiles=[],lastTurnAttachments=[];
const $=id=>document.getElementById(id);
async function api(action,method='GET',data=null){let opt={method,headers:{'Content-Type':'application/json'}};if(method==='POST'){opt.headers['X-CSRF-Token']=csrf;opt.body=JSON.stringify(data||{});}let r=await fetch('?api='+action+(action==='chat'&&method==='GET'?'&id='+encodeURIComponent(data.id):''),opt);let j=await r.json();if(!r.ok)throw Error(j.error||'Ошибка запроса');return j}
function toast(s){const el=$('toast');el.textContent=String(s||'');el.style.display='block';requestAnimationFrame(()=>el.classList.add('show'));clearTimeout(window.__toast);window.__toast=setTimeout(()=>{el.classList.remove('show');setTimeout(()=>{if(!el.classList.contains('show'))el.style.display='none'},180)},2600)}
function escapeHTML(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function inlineMarkdown(s){s=s.replace(/`([^`\n]+)`/g,'<code class="inline-code">$1</code>');s=s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g,(m,t,u)=>{if(!/^(https?:\/\/|mailto:)/i.test(u))return t;return '<a href="'+u.replace(/"/g,'%22')+'" target="_blank" rel="noopener noreferrer">'+t+'</a>'});s=s.replace(/\*\*([^*\n]+)\*\*/g,'<strong>$1</strong>').replace(/__([^_\n]+)__/g,'<strong>$1</strong>');s=s.replace(/(?<!\*)\*([^*\n]+)\*(?!\*)/g,'<em>$1</em>').replace(/(?<!_)_([^_\n]+)_(?!_)/g,'<em>$1</em>');return s}
function highlightCode(code,lang){let raw=String(code),tokens=[];
 raw=raw.replace(/(\/\*[\s\S]*?\*\/|\/\/[^\n]*|#[^\n]*$|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)/gm,m=>{let i=tokens.length;tokens.push({kind:/^(\/\*|\/\/|#)/.test(m)?'comment':'string',value:m});return '\uE000'+String.fromCharCode(0xE100+i)+'\uE001'});
 let s=escapeHTML(raw);
 s=s.replace(/\b(\d+(?:\.\d+)?)\b/g,'<span class="tok-number">$1</span>');
 s=s.replace(/\b(const|let|var|function|return|if|else|for|while|do|class|new|public|private|protected|static|void|int|float|double|bool|string|true|false|null|None|def|import|from|in|and|or|not|try|except|finally|throw|extends|implements|using|namespace|include|SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|CREATE|TABLE|async|await|echo)\b/g,'<span class="tok-keyword">$1</span>');
 s=s.replace(/\b([A-Za-z_$][\w$]*)(?=\s*\()/g,'<span class="tok-function">$1</span>');
 s=s.replace(/\uE000([\uE100-\uE1FF])\uE001/g,(m,c)=>{let t=tokens[c.charCodeAt(0)-0xE100];return '<span class="tok-'+t.kind+'">'+escapeHTML(t.value)+'</span'});
 return '<code class="'+((lang||'')?'language-'+escapeHTML(lang.toLowerCase()):'')+'">'+s+'</code>'}
function renderMarkdown(md){
 let text=escapeHTML(md||'').replace(/\r\n?/g,'\n'),blocks=[];
 text=text.replace(/```([A-Za-z0-9_+#.-]*)\n?([\s\S]*?)```/g,(m,l,c)=>{let id=blocks.length;blocks.push('<div class="codewrap"><div class="codehead"><span>'+(l||'code')+'</span><button class="codecopy" type="button" data-copy-code="'+id+'">Копировать</button></div><pre>'+highlightCode(c.replace(/\n$/,''),l)+'</pre></div>');return '\u0000CODE'+id+'\u0000'});
 const lines=text.split('\n'),out=[];let list=null,table=null,quote=[];
 const flushList=()=>{if(list){out.push((list.type==='ol'?'<ol>':'<ul>')+list.items.join('')+(list.type==='ol'?'</ol>':'</ul>'));list=null}};
 const flushQuote=()=>{if(quote.length){out.push('<blockquote>'+quote.map(x=>'<p>'+inlineMarkdown(x)+'</p>').join('')+'</blockquote>');quote=[]}};
 const flushTable=()=>{if(table){let h=table[0],rows=table.slice(2);out.push('<div style="overflow-x:auto"><table><thead><tr>'+h.map(x=>'<th>'+inlineMarkdown(x.trim())+'</th>').join('')+'</tr></thead><tbody>'+rows.map(r=>'<tr>'+r.map(x=>'<td>'+inlineMarkdown(x.trim())+'</td>').join('')+'</tr>').join('')+'</tbody></table></div>');table=null}};
 for(let i=0;i<lines.length;i++){let line=lines[i];
  if(/^\u0000CODE\d+\u0000$/.test(line.trim())){flushList();flushQuote();flushTable();out.push(blocks[Number(line.trim().match(/\d+/)[0])]);continue}
  if(!line.trim()){flushList();flushQuote();flushTable();continue}
  let tm=line.match(/^\|(.+)\|$/);if(tm){let cells=tm[1].split('|');if(!table)table=[];table.push(cells);continue}
  if(table&&!tm){flushTable()}
  let h=line.match(/^(#{1,3})\s+(.+)$/);if(h){flushList();flushQuote();out.push('<h'+h[1].length+'>'+inlineMarkdown(h[2])+'</h'+h[1].length+'>');continue}
  let q=line.match(/^>\s?(.*)$/);if(q){flushList();flushQuote();quote.push(q[1]);continue}
  let li=line.match(/^(\s*)[-*+]\s+(.+)$/);if(li){flushQuote();if(!list||list.type!=='ul') {flushList();list={type:'ul',items:[]}}list.items.push('<li>'+inlineMarkdown(li[2])+'</li>');continue}
  let oi=line.match(/^(\s*)\d+[.)]\s+(.+)$/);if(oi){flushQuote();if(!list||list.type!=='ol'){flushList();list={type:'ol',items:[]}}list.items.push('<li>'+inlineMarkdown(oi[2])+'</li>');continue}
  flushList();flushQuote();out.push('<p>'+inlineMarkdown(line)+'</p>');
 }
 flushList();flushQuote();flushTable();return out.join('').replace(/\u0000CODE(\d+)\u0000/g,(m,i)=>blocks[Number(i)]||'')}
async function copyText(text){try{await navigator.clipboard.writeText(text);return true}catch(_){let ta=document.createElement('textarea');ta.value=text;ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.select();let ok=false;try{ok=document.execCommand('copy')}catch(__){}ta.remove();if(!ok)throw Error('Не удалось скопировать текст.');return true}}
function likeKey(chat,id){return 'Floppa-like:'+chat+':'+id}
function isLiked(id){return id&&localStorage.getItem(likeKey(currentChat,id))==='1'}
function iconSvg(name){
 const common='viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"';
 const icons={
  copy:`<svg ${common}><rect x="9" y="9" width="10" height="10" rx="2"/><path d="M6 15H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v1"/></svg>`,
  regenerate:`<svg ${common}><path d="M20 11a8 8 0 0 0-14.9-3.9L3 9"/><path d="M3 4v5h5"/><path d="M4 13a8 8 0 0 0 14.9 3.9L21 15"/><path d="M21 20v-5h-5"/></svg>`,
  download:`<svg ${common}><path d="M12 3v11"/><path d="M7.5 10.5L12 15l4.5-4.5"/><path d="M5 20h14"/></svg>`,
  like:`<svg ${common}><path d="M7 10v10H4a2 2 0 0 1-2-2v-6a2 2 0 0 1 2-2h3z"/><path d="M7 20h8.2a2.5 2.5 0 0 0 2.4-1.8l1.7-6A2.5 2.5 0 0 0 16.9 9H14l.5-3.1A2.5 2.5 0 0 0 12 3.5L7 10"/></svg>`,
  liked:`<svg ${common} fill="currentColor"><path d="M7 10v10H4a2 2 0 0 1-2-2v-6a2 2 0 0 1 2-2h3z"/><path d="M7 20h8.2a2.5 2.5 0 0 0 2.4-1.8l1.7-6A2.5 2.5 0 0 0 16.9 9H14l.5-3.1A2.5 2.5 0 0 0 12 3.5L7 10"/></svg>`,
  share:`<svg ${common}><path d="M14 5l5 5-5 5"/><path d="M19 10H9a5 5 0 0 0-5 5v4"/></svg>`
 };
 return icons[name]||'';
}
function createActionBar(messageId,text){
 let bar=document.createElement('div');bar.className='actionbar';
 bar.innerHTML='<button type="button" data-action="copy" title="Копировать" aria-label="Копировать">'+iconSvg('copy')+'</button><button type="button" data-action="regenerate" title="Перегенерировать" aria-label="Перегенерировать">'+iconSvg('regenerate')+'</button><button type="button" data-action="download" title="Скачать TXT" aria-label="Скачать TXT">'+iconSvg('download')+'</button><button type="button" data-action="like" title="Нравится" aria-label="Нравится">'+iconSvg(isLiked(messageId)?'liked':'like')+'</button><button type="button" data-action="share" title="Поделиться" aria-label="Поделиться">'+iconSvg('share')+'</button>';
 let like=bar.querySelector('[data-action="like"]');if(isLiked(messageId))like.classList.add('active');
 bar.onclick=async e=>{let b=e.target.closest('button');if(!b)return;let a=b.dataset.action;try{if(a==='copy'){await copyText(text);toast('Ответ скопирован')}else if(a==='download'){let blob=new Blob([text],{type:'text/plain;charset=utf-8'}),u=URL.createObjectURL(blob),link=document.createElement('a');link.href=u;link.download='Floppa-answer.txt';link.click();setTimeout(()=>URL.revokeObjectURL(u),500)}else if(a==='like'){if(isLiked(messageId)){localStorage.removeItem(likeKey(currentChat,messageId));b.innerHTML=iconSvg('like');b.classList.remove('active')}else{localStorage.setItem(likeKey(currentChat,messageId),'1');b.innerHTML=iconSvg('liked');b.classList.add('active')}toast('Состояние лайка сохранено')}else if(a==='share'){if(navigator.share)await navigator.share({title:'Floppa AI',text});else{await copyText(text);toast('Поделиться недоступно — текст скопирован')}}else if(a==='regenerate'){await regenerate()}}catch(err){if(err.name!=='AbortError')toast(err.message||'Не удалось выполнить действие')}};return bar
}
function addMessage(role,text,id=null,attachmentNames=[]){let box=$('messages');let welcome=$('welcome');if(welcome)welcome.remove();let wrap=document.createElement('div');wrap.className='msgwrap '+(role==='user'?'user':'');let body=document.createElement('div');body.className='msgbody '+(role==='user'?'usertext':'');if(role==='user'){body.textContent=text;if(attachmentNames.length){let a=document.createElement('div');a.className='attachment-list';for(let n of attachmentNames){let s=document.createElement('span');s.className='attachment-badge';s.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M20.2 11.4l-7.9 7.9a5 5 0 0 1-7.1-7.1l8.1-8.1a3.6 3.6 0 0 1 5.1 5.1l-8.1 8.1a2.1 2.1 0 0 1-3-3l7.4-7.4"/></svg>' + n;a.appendChild(s)}body.appendChild(a)}}else{body.classList.add('msgcontent');body.innerHTML=renderMarkdown(text);if(id)body.appendChild(createActionBar(id,text))}wrap.appendChild(body);box.appendChild(wrap);box.scrollTop=box.scrollHeight;return body}
function renderMessages(messages=[]){
 const box=$('messages');
 box.innerHTML='';
 if(!Array.isArray(messages)||messages.length===0){
  box.innerHTML='<div class="welcome" id="welcome"><h1>Чем могу <span>помочь</span>?</h1><p>Задайте вопрос, обсудим идею или создадим что-то вместе.</p></div>';
  return;
 }
 for(const m of messages){
  const role=m.role==='assistant'?'assistant':'user';
  addMessage(role,String(m.content??''),m.id?Number(m.id):null);
 }
 box.scrollTop=box.scrollHeight;
}
async function refreshChats(){
 if(!currentUser)return;
 const d=await api('chats');
 chats=Array.isArray(d.chats)?d.chats:[];
 const history=$('history');history.innerHTML='';
 for(const c of chats){
  const row=document.createElement('div');row.className='chatitem'+(Number(c.id)===Number(currentChat)?' active':'');
  const label=document.createElement('span');label.textContent=c.title||'Новый чат';
  const edit=document.createElement('button');edit.type='button';edit.className='chat-edit';edit.setAttribute('aria-label','Переименовать чат');edit.title='Переименовать чат';edit.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L9 17l-4 1 1-4Z"/></svg>';
  edit.onclick=async e=>{e.stopPropagation();const title=prompt('Новое название чата:',c.title||'Новый чат');if(title===null)return;const clean=title.trim();if(!clean){toast('Название не может быть пустым');return}try{await api('rename-chat','POST',{id:Number(c.id),title:clean});if(Number(currentChat)===Number(c.id))$('activeChatTitle').textContent=clean;await refreshChats();toast('Название чата изменено')}catch(err){toast(err.message||'Не удалось переименовать чат')}};
  const del=document.createElement('button');del.type='button';del.textContent='×';del.title='Удалить чат';
  del.onclick=async e=>{e.stopPropagation();if(!confirm('Удалить этот чат?'))return;try{await api('delete-chat','POST',{id:Number(c.id)});if(Number(currentChat)===Number(c.id)){currentChat=null;localStorage.removeItem('Floppa-current-chat');$('activeChatTitle').textContent='';renderMessages()}await refreshChats();toast('Чат удалён')}catch(err){toast(err.message||'Не удалось удалить чат')}};
  row.append(label,edit,del);row.onclick=()=>openChat(c.id);history.appendChild(row);
 }
}
async function openChat(id){
 try{
  const d=await api('chat','GET',{id:Number(id)});
  currentChat=Number(d.chat.id);localStorage.setItem('Floppa-current-chat',String(currentChat));
  renderMessages(d.messages);$('activeChatTitle').textContent=d.chat.title||'Новый чат';closeSidebar();await refreshChats();$('prompt').focus();
 }catch(err){
  localStorage.removeItem('Floppa-current-chat');toast(err.message||'Не удалось открыть чат');
 }
}
async function newChat(){
 if(!currentUser){showAuth(false);return}
 if(busy){toast('Дождитесь завершения текущего запроса');return}
 try{
  const d=await api('chat','POST',{title:'Новый чат'});
  if(!d.id)throw Error('Сервер не вернул идентификатор нового чата.');
  currentChat=Number(d.id);localStorage.setItem('Floppa-current-chat',String(currentChat));lastTurnAttachments=[];
  renderMessages([]);$('activeChatTitle').textContent='Новый чат';await refreshChats();$('prompt').focus();toast('Новый чат создан');
 }catch(err){toast(err.message||'Не удалось создать новый чат')}
}
function renderAttachments(){let box=$('attachmentsPreview');box.innerHTML='';selectedFiles.forEach((f,i)=>{let chip=document.createElement('div');chip.className='attachment-chip';if(f.type.startsWith('image/')){let img=document.createElement('img');img.src=f.data;img.alt=f.name;chip.appendChild(img)}else{let icon=document.createElement('span');icon.className='file-icon';icon.innerHTML=f.type==='application/pdf'?'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M7 3h7l4 4v14H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z"/><path d="M14 3v5h5"/><path d="M8 15h8M8 18h6"/></svg>':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20.2 11.4l-7.9 7.9a5 5 0 0 1-7.1-7.1l8.1-8.1a3.6 3.6 0 0 1 5.1 5.1l-8.1 8.1a2.1 2.1 0 0 1-3-3l7.4-7.4"/></svg>';chip.appendChild(icon)}let name=document.createElement('span');name.textContent=f.name;name.title=f.name;chip.appendChild(name);let rm=document.createElement('button');rm.className='remove-attachment';rm.type='button';rm.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';rm.title='Удалить вложение';rm.onclick=()=>{selectedFiles.splice(i,1);renderAttachments()};chip.appendChild(rm);box.appendChild(chip)})}
function readFile(file){return new Promise((resolve,reject)=>{if(file.size>6*1024*1024)return reject(Error('Файл «'+file.name+'» слишком большой. Максимум — 6 МБ.'));let allowed=['image/jpeg','image/png','image/webp','image/gif','application/pdf','text/plain','text/markdown','text/csv','text/xml','application/json','application/javascript','text/javascript','text/html','text/css','text/x-python','text/x-java-source','text/x-c++src','text/x-csrc','application/x-httpd-php'];let ext=(file.name.split('.').pop()||'').toLowerCase(),map={jpg:'image/jpeg',jpeg:'image/jpeg',png:'image/png',webp:'image/webp',gif:'image/gif',pdf:'application/pdf',txt:'text/plain',md:'text/markdown',markdown:'text/markdown',csv:'text/csv',xml:'text/xml',json:'application/json',js:'application/javascript',ts:'application/javascript',html:'text/html',htm:'text/html',css:'text/css',py:'text/x-python',java:'text/x-java-source',c:'text/x-csrc',h:'text/x-csrc',cpp:'text/x-c++src',cc:'text/x-c++src',cxx:'text/x-c++src',hpp:'text/x-c++src',php:'application/x-httpd-php'},type=allowed.includes(file.type)?file.type:(map[ext]||'');if(!type)return reject(Error('Файл «'+file.name+'» имеет неподдерживаемый формат.'));let r=new FileReader();r.onload=()=>resolve({name:file.name,type:type,size:file.size,data:r.result});r.onerror=()=>reject(Error('Не удалось прочитать файл «'+file.name+'».'));r.readAsDataURL(file)})}
$('fileInput').onchange=async e=>{let incoming=Array.from(e.target.files||[]);$('fileInput').value='';if(selectedFiles.length+incoming.length>5){toast('Можно прикрепить не более 5 файлов.');incoming=incoming.slice(0,5-selectedFiles.length)}for(let f of incoming){try{let item=await readFile(f);if(selectedFiles.reduce((n,x)=>n+x.size,0)+item.size>12*1024*1024)throw Error('Суммарный размер вложений не должен превышать 12 МБ.');selectedFiles.push(item)}catch(err){toast(err.message)}}renderAttachments()};
async function send(){let text=$('prompt').value.trim();if((!text&&!selectedFiles.length)||busy)return;busy=true;$('send').disabled=true;$('attachBtn').disabled=true;let files=selectedFiles.slice();lastTurnAttachments=files.slice();selectedFiles=[];renderAttachments();$('prompt').value='';$('prompt').style.height='auto';addMessage('user',text,null,files.map(f=>f.name));let typing=addMessage('assistant','Floppa думает…');typing.classList.add('typing');try{let d;if(currentUser){if(!currentChat){let c=await api('chat','POST',{title:(text||files[0].name).slice(0,55)});currentChat=c.id;localStorage.setItem('Floppa-current-chat',String(currentChat))}d=await api('send','POST',{chat_id:currentChat,message:text,attachments:files});await refreshChats()}else{d=await api('guest-send','POST',{message:text,attachments:files});updateQuota(d.quota); }typing.classList.remove('typing');typing.classList.add('msgcontent');typing.innerHTML=renderMarkdown(d.answer);if(d.message_id)typing.appendChild(createActionBar(d.message_id,d.answer));}catch(e){typing.textContent='Ошибка: '+e.message;typing.classList.remove('typing');toast(e.message)}finally{busy=false;$('send').disabled=false;$('attachBtn').disabled=false;$('prompt').focus()}}
async function regenerate(){if(busy||!currentChat)return;busy=true;$('send').disabled=true;$('attachBtn').disabled=true;try{let d=await api('regenerate','POST',{chat_id:currentChat,attachments:lastTurnAttachments});let box=$('messages');let nodes=box.querySelectorAll('.msgwrap');let last=nodes[nodes.length-1];if(last){let body=last.querySelector('.msgbody');body.classList.remove('typing');body.classList.add('msgcontent');body.innerHTML=renderMarkdown(d.answer);body.appendChild(createActionBar(d.message_id,d.answer))}else{renderMessages([{role:'assistant',content:d.answer,id:d.message_id}])}await refreshChats()}catch(e){toast(e.message)}finally{busy=false;$('send').disabled=false;$('attachBtn').disabled=false}}
function updateQuota(q){if(!q)return;let rem=Math.max(0,Number(q.remaining)||0);$('quotaLabel').textContent=currentUser?'Ваш интеллектуальный собеседник':('Гостевой режим · осталось '+rem.toLocaleString('ru-RU')+' токенов сегодня');}
function showAuth(reg=false){registerMode=reg;$('auth').style.display='flex';$('authForm').style.display='block';$('switchAuth').style.display='block';$('googleLogin').style.display='block';$('guestStart').style.display='none';$('authLoginStart').style.display='none';$('closeAuth').style.display='block';$('authTitle').textContent=reg?'Создать аккаунт':'Войти в Floppa AI';$('authDesc').textContent=reg?'Создайте аккаунт, чтобы сохранять историю чатов.':'Войдите, чтобы сохранять историю чатов и пользоваться аккаунтом.';$('authName').style.display=reg?'block':'none';$('authName').required=reg;$('authPassword').autocomplete=reg?'new-password':'current-password';$('authSubmit').textContent=reg?'Зарегистрироваться':'Войти';$('switchAuth').textContent=reg?'Уже есть аккаунт? Войти':'Создать аккаунт'}
function updateUser(){$('userName').textContent=currentUser?currentUser.name:'Гость';if(currentUser){$('avatar').textContent=currentUser.name.charAt(0).toUpperCase()}else{$('avatar').textContent='?'}$('loginBtn').style.display=currentUser?'none':'flex';$('newChat').style.opacity=currentUser?'1':'.9'}
$('authForm').onsubmit=async e=>{e.preventDefault();try{let d=await api(registerMode?'register':'login','POST',{name:$('authName').value,email:$('authEmail').value,password:$('authPassword').value});csrf=d.csrf;$('auth').style.display='none';await boot();toast('Готово! Вы вошли в Floppa AI.')}catch(e){toast(e.message)}};
$('guestStart').onclick=async()=>{try{let d=await api('session');csrf=d.csrf;currentUser=null;updateUser();$('auth').style.display='none';$('appRoot').style.display='flex';$('sidebar').classList.remove('closed');renderMessages([]);updateQuota(d.guest);$('userName').textContent='Гость';$('loginBtn').style.display='flex'}catch(e){toast(e.message)}};$('authLoginStart').onclick=()=>showAuth(false);$('switchAuth').onclick=()=>showAuth(!registerMode);$('closeAuth').onclick=()=>{$('auth').style.display='none'};$('loginBtn').onclick=()=>showAuth(false);$('newChat').onclick=newChat;$('send').onclick=send;$('attachBtn').onclick=()=>$('fileInput').click();$('prompt').addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();send()}});$('prompt').addEventListener('input',()=>{$('prompt').style.height='auto';$('prompt').style.height=Math.min($('prompt').scrollHeight,180)+'px'});function closeSidebar(){let s=$('sidebar');s.classList.remove('open');s.classList.add('closed');$('menuBtn').style.display='flex';$('sidebarOverlay').classList.remove('show');document.body.style.overflow=''}function openSidebar(){let s=$('sidebar');s.classList.remove('closed');s.classList.add('open');$('menuBtn').style.display='none';$('sidebarOverlay').classList.add('show');document.body.style.overflow='hidden'}$('menuBtn').onclick=openSidebar;$('sidebarClose').onclick=closeSidebar;$('sidebarOverlay').onclick=closeSidebar;$('settingsBtn').onclick=()=>$('settings').style.display='flex';$('closeSettings').onclick=()=>$('settings').style.display='none';
$('deleteAll').onclick=async()=>{if(!currentUser){toast('Сначала войдите в аккаунт');return}if(confirm('Безвозвратно удалить все ваши чаты?')){try{await api('delete-all','POST');currentChat=null;$('activeChatTitle').textContent='';renderMessages();await refreshChats();$('settings').style.display='none';toast('Все чаты удалены')}catch(e){toast(e.message)}}};
$('logout').onclick=async()=>{try{await api('logout','POST');currentUser=null;currentChat=null;localStorage.removeItem('Floppa-current-chat');$('activeChatTitle').textContent='';chats=[];selectedFiles=[];lastTurnAttachments=[];renderAttachments();renderMessages();$('history').innerHTML='';updateUser();$('settings').style.display='none';$('appRoot').style.display='none';csrf='';boot();toast('Вы вышли из аккаунта')}catch(e){toast(e.message)}};
$('language').onchange=e=>{let en=e.target.value==='en';document.documentElement.lang=en?'en':'ru';$('newChat').querySelector('span').textContent=en?'New chat':'Новый чат';$('history').previousElementSibling.textContent=en?'History':'История';$('prompt').placeholder=en?'Message Floppa AI…':'Напишите сообщение Floppa AI…';let w=$('welcome');if(w){w.querySelector('h1').innerHTML=en?'How can I <span>help</span>?':'Чем могу <span>помочь</span>?';w.querySelector('p').textContent=en?'Ask a question, discuss an idea, or create something together.':'Задайте вопрос, обсудим идею или создадим что-то вместе.'}localStorage.setItem('Floppa-lang',e.target.value)};
async function boot(){
 const d=await api('session');csrf=d.csrf;currentUser=d.user;updateUser();
 if(currentUser){
  $('appRoot').style.display='flex';$('auth').style.display='none';$('sidebar').classList.remove('closed');$('sidebar').classList.remove('open');$('menuBtn').style.display='flex';$('sidebarOverlay').classList.remove('show');
  await refreshChats();
  const saved=Number(localStorage.getItem('Floppa-current-chat')||0);
  const target=saved&&chats.some(c=>Number(c.id)===saved)?saved:(chats[0]?Number(chats[0].id):0);
  if(target)await openChat(target);else{$('activeChatTitle').textContent='';renderMessages([]);}
 }else{$('appRoot').style.display='flex';$('auth').style.display='none';$('sidebar').classList.remove('closed');$('sidebar').classList.remove('open');$('menuBtn').style.display='flex';$('sidebarOverlay').classList.remove('show');$('authForm').style.display='none';$('googleLogin').style.display='none';$('guestStart').style.display='block';$('authLoginStart').style.display='block';$('switchAuth').style.display='none';$('closeAuth').style.display='none';updateQuota(d.guest);renderMessages([])}
}
let lang=localStorage.getItem('Floppa-lang');if(lang){$('language').value=lang;if(lang==='en')$('language').dispatchEvent(new Event('change'))}boot().catch(e=>{toast('Не удалось подключиться к серверу: '+e.message);showAuth(false)});
document.addEventListener('click',e=>{let b=e.target.closest('[data-copy-code]');if(!b)return;let wrap=b.closest('.codewrap'),code=wrap.querySelector('pre').innerText;copyText(code).then(()=>toast('Код скопирован')).catch(()=>toast('Не удалось скопировать код'))});
</script></body></html>