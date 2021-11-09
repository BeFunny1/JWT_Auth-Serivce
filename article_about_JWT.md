# JWT.
> Эта статья не ставит своей целью покрыть теоретической базой весь стандарт; её лейтмотив, скорее, в способах реализации технологии и её использовании.

----------

## Краткий экускурс.
> **JWT**- JSON Web Token, открытый стандарт для создания токенов доступа¹, основанный на формате `JSON`. Как правило, используется для передачи данных для аутентификации в клиент-серверных приложениях. Токены создаются сервером, подписываются секретным ключом и передаются клиенту, который в дальнейшем использует данный токен для подтверждения своей личности.   

    ¹ ключ, предназначенный для идентификации его владельца и безопасного доступа к информационным ресурсам.

* Структура:

    JWT-токен делится на три составляющие: `header`, `payload`, `signature`. 
    
    Первые две представляют из себя `json`, закодированный при помощи base64 для компактности.

    * **Header**.

        Обычно состоит из двух частей: `alg`(алгоритм подписи)¹ и `typ`(тип токена- `JWT`) и в расшифрованном виде выглядит, например, так:

        ```json
        {
            "alg": "HS256",
            "typ": "JWT"
        }
        ```

        Этот же `json`, но закодированный при помощи base64, имеет вид: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`.

        ¹ - обычно используется HS256 или RS256, но стандарт [предполагает](https://datatracker.ietf.org/doc/html/rfc7518#section-3) и другие алгоритмы шифрования подписи.
    
    * **Payload**.
        Полезная нагрузка токена: тут можно хранить всю информацию, необходимую для идентификации пользователя на стороне сервера. Помимо всевозможных ключей `json`-а, которые можете придумать вы, есть и список тех, что зарезервированы стандартом, но необязательных в использовании:

        * `iss`- issuer, эмитент/издатель токена;
        * `sub`- subject, субъект, которому выдан токен(прим., email пользователя);
        * `aud`- audience, получатели, которым предназначается данный токен;
        * `exp`- expiration time, время, когда токен станет невалидным;
        * `nbf`- not before, время, начиная с которого токен должен считать валидным;
        * `iat`- issued at, время, в которое был выдан токен;
        * `jti`- JWT ID, уникальный идентификатор токена.

        Пример:
        ```json
        {
            "my_data": "something info",
            "sub": "befunny@doubletapp.ai"
        }
        ```
        base64: `eyJteV9kYXRhIjoic29tZXRoaW5nIGluZm8iLCJzdWIiOiJiZWZ1bm55QGRvdWJsZXRhcHAuYWkifQ`.
    
    * **Signature**.

        Создаётся по следующему принципу:

        ```
        signature = HMAC_SHA256(secret, base64urlEncoding(header) + '.' + base64urlEncoding(payload))
        ```
        Закодированные при помощи base64 `header` и `payload` конкатинируются в одну строку при помощи разделителя- точки, получившуюся строку кодируют при помощи выбранного алгоритма.

        - Что такое `secret`? - ключ для дешифровки и проверки подписи, основным требованием к которому является устойчивость к брутфорсу; обычно генерируется при помощи hex.

    Конечный токен представляет из себя строку, состоящую из всех ранее описанных частей, разделённых точкой; что-то вроде этого:

    `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiZWZ1bm55QGRvdWJsZXRhcHAuYWkiLCJtZXNzYWdlIjoiSGVsbG8sIFdvcmxkISJ9.SLWhxwA7thgppfbAd5kmHCdqgBjiySBFkqMvwwW1dfg`


* Почему это работает?  

    Весь фокус в криптографии и том, что для проверки подлинности токена нам нужно лишь расшфировать его подпись на стороне сервера с помощью секрета и сравнить получшившееся с `base64urlEncoding(header) + '.' + base64urlEncoding(payload)`. 

    * Недобропорядочный пользователь решил докинуть лишнего в свой токен или поменять субъекта, которому он был выдан? На стороне сервера токен будет признан невалидным из-за несовпадения фактического `payload` и того, что закодирован в подписи; запрос будет отклонён сервером.

----------

## Использование и реализация.
> В качестве базы jwt будет использоваться `pyjwt`, самая популярная питонячья библиотека для кодирования и декодирования JSON Web Tokens.   
В качестве web-фреймворка- `fast-api`. 


### *JWT-токены для самых маленьких.*

Минимальный сценарий использования JWT-токенов следующий:

* Пользователь регистрируется в системе.
* Ему выдаётся `token`.
* Каждый следующий свой запрос клиент делает со следующим заголовком:
    
    ```
    AUTHORIZATION: Bearer <token>
    ```
    
* Сервер, получая запрос с таким заголовком, проверяет его валидность и, в случае успеха, отвечает на запрос.

Реализация же немногим сложнее. По сути, требуется лишь два действия:

* Сгенерировать токен:

    ```python
    token = jwt.encode({'email': email}, JWT_SECRET, algorithm='HS256')    
    ```
    
* Проверить его валидность при получении запроса, что можно вынести в отдельную middleware, а не дублировать код из ручки в ручку:

    ```python
    async def check_token(request: Request, call_next):
        # Достаём токен из заголовка
        authentication_header = request.headers.get('authentication')
        
        # Проверяем, что токен != None
        if authentication_header is None:
            return error_response(error='AuthError', error_description='Access-token header is not set')

        # Проверяем его на наличие/соответствие форме
        if 'Bearer ' not in authentication_header:
            return error_response(error='AuthError', error_description='JWT-token must have the form "Bearer <TOKEN>"', status_code=403)

        # Убираем лишнее  
        clear_token = authentication_header.replace('Bearer ', '')
        try:
            # Проверяем подпись
            jwt.decode(clear_token, JWT_SECRET, algorithms=["HS256", "RS256"])
        # В случае невалидности возвращаем ошибку
        except InvalidTokenError as e:
            return error_response(error='AuthError', error_description=str(e), status_code=403)
        
        # Если всё прошло хорошо, выполняем запрос
        return await call_next(request)
    ```
    * Зачем дописывать 'Bearer ' к токену, если он отбрасывается? Так [исторически сложилось](https://security.stackexchange.com/a/120244).
    
Это достаточно заурядный способ использования JWT, но всё же не лишённый права на существование. У него есть как плюсы, так и минусы.

| Плюсы  | Минусы |
|:-------------:|:-------------:|
| Простота | Токен выдаётся один раз и используется всегда, если некто перехватит его, то получит безграничный доступ к данным |
| На стороне сервера не нужно ничего хранить  | Единственный способ отозвать токен одного пользователя- поменять секрет, поломав токены всех пользователей. |

Попробуем решить проблему с долговечностью токена. Для этого назначим ему время истечения срока действия.

* Модернизируем код генерации токена:   

    ```python
    # Время жизни токена
    TOKEN_TTL = 60 * 15
    current_timestamp = convert_to_timestamp(datetime.now(tz=timezone.utc))
    expiration_time = current_timestamp + TOKEN_TTL
    token = jwt.encode({'email': email, 'exp': expiration_time}, JWT_SECRET, algorithm='HS256')
    ```

* В коде middleware ничего менять не нужно, т.к. мы используем зарезервированный ключ `exp`, верификация которого происходит силами библиотеки `pyjwt`.

И вот, кажется, проблема решена: токены теперь живут 15 минут, а после протухают и наш подходит стал немного безопаснее. Однако, пользователю точно не понравится проходить процесс авторизации каждые 15 минут, чтобы получить новый токен.

### *Access и Refresh токены.*

Решим проблему необходимости реаутентификации двумя типами токенов.

`Access Token`- токен доступа к информации, обычно имеет короткое время жизни в несколько минут.     
`Refresh Token`- токен обновления, по которому можно получить новую пару токенов; срок жизни измеряется днями.

Сценарий:

* Пользователь регистрируется и получает пару токенов: `access` и `refresh`.
* Все свои запросы сопровождает `access`-токеном и получает ответ.
* Когда срок жизни `access`-токена начинает подходить к концу, пользователь отсылает свой `refresh`-токен серверу и получает новую пару токенов.

- Что будет, если истечёт `refresh`-токен? Пользователь будет вынужен пройти процесс авторизации, чтобы подтвердить свою личность и получить новую пару токенов.


При таком подходе у конечного пользователя будет бесперебойный доступ к контенту без постоянной потребности в реаутентификации и с относительно малым ущербом от возможного перехвата `access`-токена злоумышленником(из-за малого времени жизни) для разработчика.

Реализация:

* До этого токены создавались по достаточно простой схеме. Сейчас же логика должна стать сильно сложнее. Разберёмся, по какому принципу токены будут создаваться сейчас.    
Разберём метод подписи токена:


    ```python
    def __sign_token(self,
        type: str, subject: str,
        payload: Dict[str, Any]={},
        ttl: timedelta=None
    ):
        """
        Keyword arguments:
        type -- тип токена(access/refresh);
        subject -- субъект, на которого выписывается токен;
        payload -- полезная нагрузка, которую хочется добавить в токен;
        ttl -- время жизни токена
        """
        # Берём текущее UNIX время
        current_timestamp = convert_to_timestamp(datetime.now(tz=timezone.utc))
            
        # Собираем полезную нагрузку токена:
        data = dict(
            # Указываем себя в качестве издателя
            iss='befunny@auth_service',
            sub=subject,
            type=type,
            # Рандомно генерируем идентификатор токена(UUID)
            jti=self.__generate_jti(),
            # Временем выдачи ставим текущее
            iat=current_timestamp, 
            # Временем начала действия токена ставим текущее или то, что было передано в payload
            nbf=payload['nbf'] if payload.get('nbf') else current_timestamp
        )
        # Добавляем exp- время, после которого токен станет невалиден, если был передан ttl
        data.update(dict(exp=data['nbf'] + int(ttl.total_seconds()))) if ttl else None
        # Изначальный payload обновляем получившимся словарём
        payload.update(data)
    return jwt.encode(payload, self._config.secret, algorithm=self._config.algorithm)
    ```

    * Внимательный читатель заметит, что пару абзацев выше в `payload` клали `email` пользователя, а сейчас этого нет. Дело в том, что на смену ключу `email` пришёл ключ `sub`, зарезервированный стандартом. Почему так? Потому что логичнее использовать `sub`, т.к. его поведение и смысл заложен в стандарте, а `email` скорее особенность реализации.

* При регистрации возвращаем пользователю пару токенов:

    ```python
    @auth_api.post('/register', response_model=AuthOutput)
    async def register(body: AuthInput):
        ...
        
        user = await AuthenticatedUser.create(
            login=body.login,
            password_hash=hash_password(body.password),
        )
        
        access_token = jwt_auth.generate_access_token(subject=user.login)
        refresh_token = jwt_auth.generate_refresh_token(subject=user.login)
        
        return AuthOutput(access_token=access_token, refresh_token=refresh_token)    
    ```

* При запросе пользователя проверяем валидность middleware, указанной выше, с одним изменением:

    ```python
    async def check_access_token(request: Request, call_next):
        authentication_header = ...
        
        if authentication_header is None:
            ...

        if 'Bearer ' not in authentication_header:
            ...
            
        clear_token = ...
        try:
            payload = ...
            # Проверяем тип токена, чтобы не было возможности пользоваться refresh-токеном в качестве долгоживующего access-токена
            if payload['type'] != 'access':
                return error_response(error='AuthError', error_description='A refresh-token was passed, but access-token was expected', status_code=403)
        except InvalidTokenError as e:
            ...

        return await call_next(request)
    ```

* При обновлении токена:

    ```python
    @auth_api.put('/update_tokens', response_model=UpdateTokensOutput)
    async def update_tokens(body: UpdateTokensInput):
        # Проверяем на валидность
        payload, error = try_decode_token(jwt_auth, body.refresh_token)
        if error:
            return error
        
        # Проверяем на соответствие типу
        if payload['type'] == 'access':
            return error_response(error='InvalidToken', error_description='A refresh-token was passed, but access-token was expected')
        
        user = await AuthenticatedUser.filter(login=payload['sub']).first()
        
        # Выпускаем новые токены
        access_token = jwt_auth.generate_access_token(subject=user.login)
        refresh_token = jwt_auth.generate_refresh_token(subject=user.login)
        
        return UpdateTokensOutput(access_token=access_token, refresh_token=refresh_token)
    ```

Как-то так у нас появилось сильно больше кода и чуть-чуть больше безопасности. Однако, проблема с безграничным доступом к контенту у зломышленника никуда не делась. Просто, теперь нужно перехватить `refresh`-токен, а не `access`- это сложнее, но не невозможно.

### *Отзыв токенов.*

Решим проблему комплексно- научимся отзывать `refresh`-токены.

* Почему именно их, а не вообще все токены? Отвечу на этот вопрос чуть ниже.

Для этого в базе нужно будет хранить дополнительную модельку:
```python
class IssuedToken(Model):
    subject = fields.ForeignKeyField('models.AuthenticatedUser', related_name='refresh_tokens')
    # Храним только уникальный идентификатор токена, а не весь токен
    jti = fields.CharField(max_length=255, pk=True)
    revoked = fields.BooleanField(default=False)  
```

Сценарий во многом повторяет предыдущий, за одним лишь исключением- теперь мы отзываем все старые `refresh`-токены, выданные пользователю перед тем, как выдать ему новую пару.  

Реализация: 

* Сохраняем jti `refresh`-токена при регистрации: 
    ```python
    @auth_api.post('/register', response_model=AuthOutput)
    async def register(body: AuthInput):
        if await AuthenticatedUser.filter(login=body.login).exists():
            ...
        
        user = await AuthenticatedUser.create(...)
        
        access_token = ...
        refresh_token = ...
        
        await IssuedToken.create(subject=user, jti=jwt_auth.get_jti(refresh_token))
        
        return AuthOutput(access_token=access_token, refresh_token=refresh_token)
    ```

* При обновлении отзываем все выпущенные на пользователя `refresh`-токены и сохраняем jti выпущенного токена в базу:
    ```python
    @auth_api.put('/update_tokens', response_model=UpdateTokensOutput)
    async def update_tokens(body: UpdateTokensInput):
        payload, error = try_decode_token(jwt_auth, body.refresh_token)
        if error:
            return error
        
        if payload['type'] == 'access':
            ...
        
        user = await AuthenticatedUser.filter(login=payload['sub']).first()
        
        await IssuedToken.filter(jti=payload['jti']).update(revoked=True)
        
        access_token = ...
        refresh_token = ...
        
        await IssuedToken.create(subject=user, jti=jwt_auth.get_jti(refresh_token))
        
        return UpdateTokensOutput(access_token=access_token, refresh_token=refresh_token)
    ```
    * На этом можно было бы и остановиться, однако, представим следующую ситуацию:

        1) У *законного* клиента есть **токен обновления 1** , который просочился или украден вредоносным клиентом.
        2) *Законный* клиент использует **токен обновления 1** для получения новой пары токен обновления / токен доступа.
        3) Сервис возвращает **токен обновления 2** / **токен доступа 2**, отзывая прт это предыдущие.
        4) *Вредоносный* клиент пытается использовать **токен обновления 1** для получения токена доступа. 
    
        В текущей реализации *вредоносный* клиент получит ошибку, но стоит ли на этом остановиться, если нам, как серверу, доподлинно известно, что токен пользователя был скомпрометирован?

        [Auth0](https://auth0.com/) использует следующий механизм:

        4) Затем *вредоносный* клиент пытается использовать **токен обновления 1** для получения токена доступа. Сервис распознает, что **токен обновления 1** используется повторно, и немедленно делает недействительным семейство токенов обновления, включая **токен обновления 2**.
        5) Сервис возвращает *вредоносному* клиенту ответ об отказе в доступе.
        6) Срок действия **токена доступа 2** истекает, и *законный* клиент пытается использовать **токен обновления 2** для запроса новой пары токенов. Сервис возвращает *законному* клиенту ответ об отказе в доступе.
        7) Требуется повторная аутентификация.

        Реализуем его, добавив немного кода в тело метода `update_tokens`:
        ```python
        @auth_api.put('/update_tokens', response_model=UpdateTokensOutput)
        async def update_tokens(body: UpdateTokensInput):
            payload, error = try_decode_token(jwt_auth, body.refresh_token)
            if error:
                return error
            
            if payload['type'] == 'access':
                ...
            
            user = await AuthenticatedUser.filter(login=payload['sub']).first()
        
            if await check_revoked(payload['jti']):
                await IssuedToken.filter(subject=user).update(revoked=True)
                return error_response(error='RevokedTokenError', error_description='This token has already been revoked')

            await IssuedToken.filter(jti=payload['jti']).update(revoked=True)
            
            access_token = ...
            refresh_token = ...
            
            await IssuedToken.create(subject=user, jti=jwt_auth.get_jti(refresh_token))
            
            return UpdateTokensOutput(access_token=access_token, refresh_token=refresh_token)
        ```

* Для целостности картины можно также добавить отдельную ручку для отзыва токена:
    ```python
    @auth_api.post('/revoke_token')
    async def revoke_token(body: RevokeTokenInput):
        payload, error = try_decode_token(jwt_auth, body.refresh_token)
        if error:
            return error
    
        if payload['type'] != TokenType.REFRESH:
            return error_response(error='InvalidToken', error_description='A refresh-token was passed, but access-token was expected')

        if await check_revoked(jwt_auth.get_jti(body.refresh_token)):
            return error_response(error='RevokeToken', error_description='This token already revoked')
        
        user = await AuthenticatedUser.filter(login=payload['sub']).first()
        await IssuedToken.filter(subject=user).update(revoked=True)
        return JSONResponse(status_code=200, content={'message': 'Success'})
    ```

И, в целом, это всё, что нам нужно. Токены больше не живут вечно, а протухают со временем; на крайний случай у нас есть возможность отозвать `refresh`-токен, допустим, в случае подозрительной активности. 

Остался лишь один вопрос- почему отзываем только `refresh`-токен? В целом, это просто не везде нужно, т.к. время жизни токена доступа измеряется минутами, за которые мало что сможет произойти. Однако, для чистоты эксперемента, давайте добавим возможность отзывать и `access`-токены:

* Сохраняем jti `access`-токена по аналогии с `refresh`-токеном;
* В местах, где отзываем токены меняем с `filter(jti=jti)` на `filter(subject=user)`, чтобы получилось так:

    ```python
    await IssuedToken.filter(subject=user).update(revoked=True)
    ```
* Не забываем про нейминг, `/revoke_token` -> `/revoke_all_tokens` и пр.;
* И финальный штрих по middleware:
    ```python
    async def check_access_token(request: Request, call_next):
        authentication_header = ...
            
        if authentication_header is None:
            ...
            
        if 'Bearer ' not in authentication_header:
            ...
            
        clear_token = authentication_header.replace('Bearer ', '')
        try:
            payload = ...
            if payload['type'] != 'access':
                ...
        except InvalidTokenError as e:
            return error_response(error='AuthError', error_description=str(e), status_code=403)
            
        if await check_revoked(payload['jti']):
            return error_response(error='AuthError', error_description='This token has revoked', status_code=403)

        return await call_next(request)
    ```

----------

В выводе хочется сказать о том, что JWT достаточно удобный инструмент для проверки аутентификации пользователя. Основные отличия от других токенов в том, что его очень просто расшифровать(не забываем, что `header` и `payload` кодируются base64) и посмотреть, что там в нем есть, но довольно сложно подделать из-за одностороннего хранения ключа для дешифровки; а также в нём очень удобно хранить любую нужную вам информацию.

Ссылка на гитхаб с реализацией всего вышеописанного: [github.com/BeFunny1/JWTAuthSerivce](https://github.com/BeFunny1/JWTAuthSerivce).

Полезные ссылки:
* [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519) - стандарт JSON Web Token;
* [auth0.com](https://auth0.com/docs/security/tokens) - документация о том, как auth0 использует JWT в целях разработки платформы для идентификации пользователей.