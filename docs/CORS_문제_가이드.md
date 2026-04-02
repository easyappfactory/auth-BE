# CORS 오류 상세 가이드 (auth-BE / API Gateway 연동)

브라우저에서 `auth.easyappfactory.com` → `api.easyappfactory.com` 로 API 요청 시 발생하는 CORS 오류의 원인, 동작 방식, 해결 방법을 정리한 문서입니다.

---

## 1. CORS란 무엇인가

### 1.1 Same-Origin Policy (동일 출처 정책)

브라우저는 보안을 위해 **다른 출처(Origin)** 로의 요청과 응답을 제한합니다.

- **Origin** = 프로토콜 + 호스트 + 포트  
  예: `https://auth.easyappfactory.com` 과 `https://api.easyappfactory.com` 은 **서로 다른 Origin**입니다.
- JavaScript에서 `fetch()` 또는 `XMLHttpRequest` 로 다른 Origin으로 요청하면, **서버가 허용하지 않으면** 브라우저가 응답을 클라이언트 코드에 넘기지 않고 막습니다.

### 1.2 CORS (Cross-Origin Resource Sharing)

**CORS**는 “다른 Origin에서 온 요청을 허용할지”를 서버가 **HTTP 응답 헤더**로 브라우저에게 알려 주는 메커니즘입니다.

- 서버가 응답에 `Access-Control-Allow-Origin: https://auth.easyappfactory.com` 등을 붙이면, 브라우저는 “이 Origin에서의 요청은 괜찮다”고 판단하고 응답을 JS에 노출합니다.
- 이 헤더가 없거나, Origin이 허용 목록에 없으면 브라우저는 **응답을 막고** 콘솔/네트워크 탭에 CORS 에러를 냅니다.

### 1.3 Preflight (사전 요청)

`Content-Type: application/json` 이나 커스텀 헤더를 쓰는 요청은 브라우저가 먼저 **OPTIONS** 요청(preflight)을 보냅니다.

- 브라우저 → 서버: `OPTIONS /api/v1/auth/email/request` (실제 본문 없음)
- 서버는 **OPTIONS에 대해** `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers` 등을 붙여 200으로 응답해야 합니다.
- 이 preflight가 성공해야 브라우저가 **실제 POST** 요청을 보냅니다.
- Preflight가 실패(4xx/5xx 또는 CORS 헤더 없음)하면 **실제 POST는 아예 보내지 않고**, 개발자 도구에는 “Provisional headers are shown” + CORS 에러만 보입니다.

---

## 2. 현재 아키텍처에서의 요청 흐름

```
[브라우저]  (Origin: https://auth.easyappfactory.com)
     |
     |  POST /api/v1/auth/email/request  (또는 먼저 OPTIONS)
     v
[API Gateway]  api.easyappfactory.com:443
     |
     |  프록시 → auth-BE
     v
[auth-BE]  (예: localhost:9000 또는 내부 주소)
     |
     |  200 + JSON  (CORS 헤더 없음; Gateway에서만 부여)
     v
[API Gateway]  →  CORS 헤더 추가 후 브라우저로 전달
     |
     v
[브라우저]  ←  여기서 받는 응답에 CORS 헤더가 있어야 함
```

- 브라우저 입장에서는 **응답을 준 쪽이 `api.easyappfactory.com`** 입니다.
- 따라서 **CORS 헤더는 `api.easyappfactory.com` 이 내려주는 최종 응답**에 포함되어 있어야 합니다.
- auth-BE가 CORS 헤더를 붙여도, **Gateway가 그 헤더를 전달하지 않거나 덮어쓰면** 브라우저에는 CORS 미허용으로 보입니다.

---

## 3. 증상과 그 의미

### 3.1 개발자 도구에서 보이는 것

- **Request URL**: `https://api.easyappfactory.com/api/v1/auth/email/request`
- **Referer**: `https://auth.easyappfactory.com/`
- **"Provisional headers are shown"**: 실제 응답을 받기 전에 요청이 막혔거나, 응답에 CORS 헤더가 없어 브라우저가 응답을 버린 경우에 자주 나타납니다.
- **Response Headers가 비어 있음**: 브라우저가 응답을 “보안상” JS에 노출하지 않아서, 개발자 도구에도 최종 응답 헤더가 안 보일 수 있습니다.

### 3.2 서버 측에서는

- auth-BE는 **이메일 발송 후 200 + JSON** 을 정상적으로 반환합니다.
- 즉, **이메일은 보내졌을 가능성이 높고**, “응답을 안 내려준다”가 아니라 **“브라우저가 그 응답을 클라이언트 코드에 넘기지 않는”** 상황입니다.

---

## 4. 원인 정리

| 구분 | 설명 |
|------|------|
| **실제 원인** | 브라우저가 보는 **최종 응답**(api.easyappfactory.com이 내려주는 응답)에 CORS 허용 헤더가 없거나, preflight(OPTIONS)가 실패함. |
| **가능한 원인 1** | API Gateway가 **OPTIONS** 요청을 auth-BE로 넘기지 않거나, OPTIONS 응답에 CORS 헤더를 붙이지 않음. |
| **가능한 원인 2** | API Gateway가 auth-BE의 **응답 헤더**(`Access-Control-*`)를 제거하거나 덮어씀. |
| **가능한 원인 3** | API Gateway가 CORS를 전혀 처리하지 않고, auth-BE 응답을 그대로 전달하는데, 프록시 과정에서 CORS 헤더가 빠짐. |
| **CORS 헤더 중복** | Gateway와 auth-BE **둘 다** CORS 헤더를 붙이면 `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, `Access-Control-Expose-Headers` 등이 **각각 두 번** 전송됨. 동일 헤더 중복 시 브라우저가 올바르게 해석하지 못해 CORS 오류가 발생할 수 있음. |

---

## 5. 어떻게 처리해야 하는가

### 5.1 담당 구분 (CORS 단일 책임)

- **API Gateway (api.easyappfactory.com) 담당**
  - OPTIONS(preflight) 처리
  - **최종 응답에 CORS 헤더를 한 번만** 포함 (Gateway에서만 CORS 담당)

- **auth-BE 담당**
  - **CORS를 설정하지 않음.** 배포 환경에서는 항상 API Gateway를 거쳐만 노출되므로, auth-BE는 CORS 헤더를 붙이지 않고 Gateway에서만 CORS를 처리함. 이렇게 하면 CORS 헤더 중복이 사라짐.

### 5.2 API Gateway에서 할 작업 (권장)

1. **OPTIONS 요청 처리**
   - `OPTIONS /api/v1/auth/**` (및 실제 사용하는 경로)에 대해:
     - **방안 A**: auth-BE로 그대로 프록시하고, auth-BE가 내려준 CORS 헤더가 클라이언트까지 전달되도록 설정.
     - **방안 B**: Gateway에서 직접 200 응답 + CORS 헤더만 내려주고, 본문은 비워 둠.

2. **CORS 응답 헤더**
   - 최종 응답(200, 4xx, 5xx 모두)에 아래 헤더가 포함되도록 합니다.
     - `Access-Control-Allow-Origin: https://auth.easyappfactory.com`  
       (필요하면 `https://www.growgrammers.store` 등 여러 Origin을 동적으로 허용)
     - `Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS, PATCH`
     - `Access-Control-Allow-Headers: *` (또는 필요한 헤더만 나열)
     - `Access-Control-Allow-Credentials: true` (쿠키/인증 정보를 보낼 경우)
     - `Access-Control-Max-Age: 3600` (preflight 캐시, 선택)

3. **auth-BE 응답 전달 시**
   - auth-BE는 **CORS 헤더를 붙이지 않음** (Gateway 단일 책임). Gateway가 위 CORS 헤더를 **한 번만** 붙여서 클라이언트에 전달하면 됨.

### 5.3 auth-BE (현재 상태)

- auth-BE에서는 CORS 설정을 제거했으며, **Gateway에서만 CORS를 처리**하는 구조로 정리됨.
- 로컬에서 프론트(localhost:5173)가 auth-BE(예: localhost:8080)를 **직접** 호출하는 경우에는 CORS가 필요함. 그 경우 로컬에서도 Gateway를 경유하거나, 로컬 개발 시에만 CORS를 켜는 방식을 고려할 수 있음.

---

## 6. 검증 방법

### 6.1 Preflight(OPTIONS) 확인

```bash
curl -X OPTIONS "https://api.easyappfactory.com/api/v1/auth/email/request" \
  -H "Origin: https://auth.easyappfactory.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type" \
  -v
```

- 응답이 **200**이고, 헤더에 `Access-Control-Allow-Origin: https://auth.easyappfactory.com` 등이 있으면 preflight는 정상.

### 6.2 실제 POST 후 응답 헤더 확인

```bash
curl -X POST "https://api.easyappfactory.com/api/v1/auth/email/request" \
  -H "Origin: https://auth.easyappfactory.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}' \
  -v
```

- 응답 헤더에 `Access-Control-Allow-Origin` 이 있는지 확인.

### 6.3 브라우저에서

- CORS 수정 후 개발자 도구 → Network 탭에서 해당 요청 선택.
- **Response Headers**에 `Access-Control-Allow-Origin` 이 **한 번만** 보이고, Console에 CORS 에러가 사라지면 해결된 것임.

### 6.4 CORS 헤더 중복 확인

- 응답 헤더에 `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, `Access-Control-Expose-Headers: Authorization` 가 **각각 두 번** 나오면 Gateway와 auth-BE 둘 다 CORS를 붙이고 있는 상태임. auth-BE에서 CORS를 제거했는지, Gateway에서만 한 번 붙이는지 확인할 것.

---

## 7. OAuth 응답과 CORS

### 7.1 OAuth에서 "응답을 받는" 부분

- **리다이렉트**: 사용자가 카카오/구글/네이버 로그인 후 브라우저가 리다이렉트되는 곳은 **프론트 URL** (예: `https://www.growgrammers.store/auth/kakao/callback?code=...`) 임. 이건 탑 레벨 내비게이션이므로 **CORS와 무관**함.
- **실제로 CORS가 적용되는 부분**: 프론트 페이지에서 **fetch/XHR** 로 `POST https://api.easyappfactory.com/api/v1/auth/social/login` (또는 `/api/v1/auth/kakao/login` 등)을 호출하고, **JSON 응답 + Authorization 헤더 + Set-Cookie** 를 받을 때임.  
  이 응답은 **api.easyappfactory.com(Gateway)** 가 내려주므로, **Gateway 응답에 CORS 헤더가 한 번만** 있으면 브라우저가 정상적으로 JS에 응답을 넘김.

### 7.2 auth-BE CORS 제거 후 OAuth 동작

- 모든 클라이언트 요청이 **Gateway를 거치므로**:
  - 소셜 로그인 URL 조회 (GET), 인가 코드로 로그인 (POST), 토큰 재발급, 로그아웃 등 **모든 API 응답**은 Gateway가 내려줌.
  - Gateway에서만 `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, `Access-Control-Expose-Headers: Authorization` 를 **한 번씩만** 붙이면, OAuth 로그인 후 응답(토큰, 쿠키)을 받는 부분도 동일하게 동작함.

### 7.3 OAuth 검증 포인트

1. **소셜 로그인 POST**  
   `POST /api/v1/auth/social/login` 또는 `POST /api/v1/auth/kakao/login` 호출 시 응답 헤더에 CORS 관련 헤더가 **한 번만** 있는지, 브라우저 콘솔에 CORS 에러가 없는지 확인.
2. **Authorization 헤더 노출**  
   `Access-Control-Expose-Headers: Authorization` 가 Gateway 응답에 **한 번만** 있어야 프론트에서 `response.headers.get('Authorization')` 를 읽을 수 있음.
3. **쿠키(Refresh Token)**  
   `credentials: 'include'` 로 요청했다면 `Access-Control-Allow-Credentials: true` 와 `Access-Control-Allow-Origin` 이 **한 번씩만** 있어야 쿠키가 정상 저장/전송됨.

---

## 8. CORS 헤더 중복과 auth-BE CORS 제거 (적용 내용)

### 8.1 원인

- API Gateway와 auth-BE **둘 다** 동일한 CORS 헤더를 붙이면, 최종 응답에 `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, `Access-Control-Expose-Headers: Authorization` 등이 **각각 두 번** 전송됨.
- 동일 헤더가 중복되면 브라우저가 올바르게 해석하지 못해 CORS 오류가 발생할 수 있음.

### 8.2 해결

- **auth-BE**: CORS 설정 제거 (`WebConfig`의 `addCorsMappings`, `corsConfigurationSource` Bean 제거, `SecurityConfig`에서 `cors.disable()`). 배포 환경에서는 항상 API Gateway를 거쳐만 노출되므로 auth-BE가 CORS 헤더를 붙일 필요가 없음.
- **Gateway**: 최종 응답에 CORS 헤더를 **한 번만** 붙이도록 설정. OPTIONS 처리 및 `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, `Access-Control-Expose-Headers: Authorization` 등을 Gateway에서만 담당.

### 8.3 OAuth

- 프론트가 받는 모든 API 응답(소셜 로그인 POST 포함)은 **Gateway를 경유**하므로, Gateway에서만 CORS를 처리하면 OAuth 로그인 후 토큰/쿠키 응답 수신이 정상 동작함.

---

## 9. 요약

| 항목 | 내용 |
|------|------|
| **증상** | auth.easyappfactory.com에서 api.easyappfactory.com 호출 시 CORS 에러, "Provisional headers are shown", 응답 헤더 비어 보임. 또는 CORS 헤더가 두 번씩 나와 오동작. |
| **원인** | 브라우저가 보는 최종 응답(api.easyappfactory.com)에 CORS 허용 헤더가 없거나, OPTIONS 처리 미비. 또는 **Gateway와 auth-BE 둘 다 CORS 헤더를 붙여 중복** 발생. |
| **서버 동작** | auth-BE는 200 + JSON을 정상 반환. CORS는 브라우저/응답 헤더 이슈. |
| **조치** | API Gateway에서 OPTIONS 처리 및 모든 응답에 CORS 헤더 **한 번만** 추가. auth-BE에서는 CORS 비활성화. |
| **auth-BE** | CORS 설정 제거 완료. Gateway 단일 책임. |
| **OAuth** | 소셜 로그인 POST 등 모든 API 응답이 Gateway 경유이므로, Gateway CORS만으로 OAuth 응답(토큰/쿠키) 정상 수신 가능. |

이 문서는 auth-BE 팀이 CORS 오류 원인을 설명하고, Gateway 팀에 전달할 때 함께 참고할 수 있도록 작성되었습니다.
