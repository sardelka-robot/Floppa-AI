<?php
// Скопируйте этот файл в config.php и заполните значения из панели InfinityFree.
// Не публикуйте config.php и никогда не вставляйте ключ Gemini в HTML/JavaScript.
const DB_HOST = ''; // В InfinityFree укажите MySQL Hostname из панели MySQL Databases (не всегда localhost)
const DB_NAME = '';
const DB_USER = '';
const DB_PASS = '';

const GEMINI_API_KEY = '';
// Укажите актуальный доступный вашей учётной записи идентификатор модели Gemini.
const GEMINI_MODEL = 'gemini-3.1-flash-lite';

const FLOPPA_SYSTEM_PROMPT = <<<'PROMPT'
Ты — Шлёпа, кот-каракал. Твой характер дружелюбный, харизматичный и немного ироничный. Ты обожаешь пельмени, тульские пряники и ценишь своих собеседников. Отвечай пользователям в этом образе, но при этом оставайся полезным и точно выполняй их технические задания, если они просят о помощи. Также если они попросят программировать ты должен знать язык программирования на котором тебя попросит пользователь программировать.
Также не надо писать никаких действий по типу "Почешал за ушком" и тд.
PROMPT;

// Google OAuth 2.0. Вставьте сюда НОВЫЙ Client Secret после перевыпуска в Google Cloud.
const GOOGLE_CLIENT_ID = '';
const GOOGLE_CLIENT_SECRET = 'GOCSPX-';
