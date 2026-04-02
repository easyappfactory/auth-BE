# API Gateway 연동 가이드 (auth-be 팀용)

auth-be가 API Gateway와 어떻게 연결되는지, 경로·인증 연동 방식을 요약한 문서입니다.

---

## 1. 연결 구조

- 외부 클라이언트는 **`/api` 로 시작하는 요청을 API Gateway(기본 포트 8080)** 로 보냅니다.
- Gateway가 경로에 따라 백엔드로 라우팅합니다.

```
[클라이언트]  →  [API Gateway :8080]  →  [auth-be :9000] (또는 wedding 등)
```

---

## 2. auth-be 로 라우팅되는 경로

| 외부 경로 | Gateway 동작 | 연결 대상 |
|-----------|----------------|-----------|
| `/api/v1/auth/**` | 경로 그대로 전달 (rewrite 없음) | **auth-be** (`AUTH_SERVER_URL`, 기본 9000) |

- Gateway 설정 예: `AUTH_SERVER_URL=http://auth-be호스트:9000` (같은 서버면 `http://localhost:9000`)
- auth-be는 **`/api/v1/auth/...`** 형태 그대로 요청을 받습니다.

---

## 3. 인증 필요 경로에서의 연동 (introspect)

`/api/v1/wedding-editor/**` 등 **인증이 필요한 경로**로 요청이 오면:

1. Gateway가 **auth-be의 introspect API**를 먼저 호출합니다.
2. 호출 경로: `GET {AUTH_SERVER_URL}{AUTH_SERVER_INTROSPECT_PATH}`  
   기본값: `GET {AUTH_SERVER_URL}/api/v1/auth/introspect`
3. Gateway가 클라이언트의 `Authorization` 헤더를 그대로 auth-be에 전달합니다.
4. auth-be가 **2xx + `X-User-Id`, `X-Auth-Provider` 헤더**로 응답하면 Gateway가 이 헤더를 붙여 다운스트림으로 전달합니다.
5. auth-be가 **401/403**을 반환하면 Gateway가 클라이언트에게 401/403을 그대로 반환합니다.

---

## 4. auth-be 측에서 제공하는 것

| 항목 | 내용 |
|------|------|
| 경로 | `/api/v1/auth/**` 로 요청 처리 (Gateway가 path rewrite 하지 않음) |
| Introspect API | `GET /api/v1/auth/introspect` |
| Introspect 요청 | `Authorization` 헤더에 JWT가 담긴 요청을 받음 |
| Introspect 성공 시 | 2xx + 응답 헤더 `X-User-Id`, `X-Auth-Provider` (연동된 경우) |
| Introspect 실패 시 | 401/403 → Gateway가 그대로 클라이언트에 반환 |

---

## 5. 요청 흐름 요약

- **인증 불필요 경로** (예: `GET /api/v1/auth/...` 중 로그인 등)  
  `[외부] → [Gateway :8080] → [auth-be :9000]` 경로 그대로 전달.

- **인증 필요 경로** (예: `/api/v1/wedding-editor/**`)  
  `[외부] → [Gateway :8080] → (1) auth-be introspect 호출 → (2) 성공 시 헤더 전파 후 다운스트림으로 전달`.

상세 구조·필터·에러 코드는 Gateway 팀의 `API-GATEWAY-구조.md` 등을 참고하면 됩니다.
