# laboratory work №2

В даній лабораторній роботі були реалізовані потокові шифри RC4, Salsa20 та 5 потокових шифрів для AES. Усі алгоритми були реалізовані на мові програмування Swift. Для реалізації алгоритмів [RC4](StreamingCiphers/StreamingCiphers/RC4.swift) та [Salsa20](StreamingCiphers/StreamingCiphers/Salsa20.swift) були створені окремі краси, що мають таку ж назву. Ці класи приймають ключ при ініціалізації та мають два публічні методи:
```swift
func encode(data: Data) -> Data
func decode(data: Data) -> Data
```
Об'єкт Data це масив байтів.

Для реалізації 5 потокових режимів був створений клас [BlockCipher](StreamingCiphers/StreamingCiphers/BlockCipher.swift), він приймає ключ при ініціалізації об'єкта та один з п'яти режимів, цей клас має такий же публічний інтерфейс, що і класи RC4 та Salsa20.

Була порівняна швидкодія кожного з реалізованих алгоритмів (потокові режими використовували алгоритм AES з довжиною ключа в 128 біт), кожен алгоритм шифрував та дешифрував 10 МБ тексту, результати наведені у таблиці:
Метод \ Алгоритм | RC4 | Salsa20 | ECB | CBC | CFB | OFB | CTR
--- | --- | --- | --- | --- | --- | --- | ---
Час шифрування у секундах | 0.91 с | 0.17 с | 27.40 с | 28.51 с | 45.50 с | 26.23 с | 26.60 с
Час дешифрування у секундах | 0.91 с | 0.16 с | 25.45 с | 26.70 с | 45.40 с | 26.30 с | 26.24 с
