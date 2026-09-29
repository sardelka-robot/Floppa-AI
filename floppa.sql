(128, 31, 'assistant', 'Слушай, я не совсем понял, что ты имеешь в виду под «сливы дслеац». Ты хочешь, чтобы я написал код для какого-то «слива» данных, или ты просто решил поупражняться в опечатках?\n\nЕсли ты про программирование, то давай конкретнее. Нужно что-то спарсить с сайта? Или сделать скрипт, который будет выводить список фруктов, включая твои сливы и бананы? \n\nОбъясни задачу по-человечески, как другу Шлёпе. А то я сейчас начну писать код на Python, который будет генерировать бесконечный поток пельменей, и мы оба не поймем, что произошло. Жду уточнений!', '2026-09-29 13:57:57'),
(129, 31, 'user', 'Пицца четыре сына', '2026-09-29 13:58:03'),
(130, 31, 'user', 'Вложения: images (3).jpeg', '2026-09-29 13:58:12'),
(131, 31, 'assistant', 'О, это же классика! Я на этой картинке выгляжу просто великолепно — взгляд пронзительный, уши торчком, всё как полагается настоящему каракалу. И, что самое важное, вокруг меня парят пельмени. Это же просто райское видение! \n\nА вот про «пиццу четыре сына» ты загнул. Видимо, это какой-то хитрый кулинарный шифр. Если ты имеешь в виду «четыре сыра», то должен тебя расстроить: сыр — это хорошо, но пельмени — это святое. \n\nАнализ изображения показывает:\n1. **Объект:** Я, Шлёпа, во всей красе.\n2. **Фон:** Фиолетовый градиент с паттерном из пельменей и, кажется, кусочков пиццы.\n3. **Общее настроение:** Гастрономическое величие и абсолютное спокойствие.\n\nЕсли ты хочешь, чтобы я написал код, который будет выводить эту картинку на сайте, или, например, сделал интерактивный тест «Какой ты пельмень сегодня», — только скажи. Я готов к любым свершениям, особенно если они связаны с едой. \n\nНу что, будем что-то программировать или продолжим любоваться моим портретом?', '2026-09-29 13:58:24');

-- --------------------------------------------------------

--
-- Структура таблицы `users`
--

CREATE TABLE `users` (
  `id` int(10) UNSIGNED NOT NULL,
  `name` varchar(60) NOT NULL,
  `email` varchar(254) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `google_sub` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Дамп данных таблицы `users`
--

INSERT INTO `users` (`id`, `name`, `email`, `password_hash`, `created_at`, `google_sub`) VALUES
--
-- Индексы сохранённых таблиц
--

--
-- Индексы таблицы `chats`
--
ALTER TABLE `chats`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_chats_user_updated` (`user_id`,`updated_at`,`id`);

--
-- Индексы таблицы `messages`
--
ALTER TABLE `messages`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_messages_chat_id` (`chat_id`,`id`);

--
-- Индексы таблицы `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_users_email` (`email`),
  ADD UNIQUE KEY `uq_users_google_sub` (`google_sub`);

--
-- AUTO_INCREMENT для сохранённых таблиц
--

--
-- AUTO_INCREMENT для таблицы `chats`
--
ALTER TABLE `chats`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=32;

--
-- AUTO_INCREMENT для таблицы `messages`
--
ALTER TABLE `messages`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=132;

--
-- AUTO_INCREMENT для таблицы `users`
--
ALTER TABLE `users`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- Ограничения внешнего ключа сохраненных таблиц
--

--
-- Ограничения внешнего ключа таблицы `chats`
--
ALTER TABLE `chats`
  ADD CONSTRAINT `fk_chats_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Ограничения внешнего ключа таблицы `messages`
--
ALTER TABLE `messages`
  ADD CONSTRAINT `fk_messages_chat` FOREIGN KEY (`chat_id`) REFERENCES `chats` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
