# 소셜 로그인 API 요청 스펙 (400 에러 방지)

`POST /api/v1/auth/{google|kakao|naver}/login` 호출 시 **요청 바디 필드명/필수값**이 다르면 `@Valid` 검증 실패로 **400 Bad Request**가 발생합니다.  
클라이언트는 아래 스펙과 **완전히 동일한** 필드명을 사용해야 합니다.

## redirect_uri (선택)

- **요청 body**에 `redirectUri`가 들어오면 그 값을 토큰 교환 시 사용합니다.
- **null이거나 비어 있으면** 서버 기본값(환경 변수 `GOOGLE_REDIRECT_URI` / `KAKAO_REDIRECT_URI` / `NAVER_REDIRECT_URI`)을 사용합니다.

---

## Naver 로그인 `POST /api/v1/auth/naver/login`

| 필드 | 타입 | 필수 | 설명 |
|------|------|------|------|
| **authCode** | string | O | Naver OAuth2 인가 코드 (쿼리 `code`) |
| **state** | string | O | 인가 요청 시 보냈던 `state`와 동일한 값 (CSRF 방지) |
| **codeVerifier** | string | O | PKCE용 코드 검증자 |
| **redirectUri** | string | X | 인가 요청 시 사용한 redirect_uri. 없으면 서버 기본값 사용. |

**예시**
```json
{
  "authCode": "네이버에서_받은_인가코드",
  "state": "인가_요청시_사용한_state_값",
  "codeVerifier": "PKCE_코드_검증자",
  "redirectUri": "https://wedding.easyappfactory.com/auth/naver/callback"
}
```

- `code`가 아니라 **`authCode`** 여야 합니다.
- **`state`** 를 빼면 400 발생 (Naver 전용 필수).

---

## Google 로그인 `POST /api/v1/auth/google/login`

| 필드 | 타입 | 필수 | 설명 |
|------|------|------|------|
| **authCode** | string | O | Google OAuth2 인가 코드 |
| **codeVerifier** | string | O | PKCE용 코드 검증자 |
| **redirectUri** | string | X | 인가 요청 시 사용한 redirect_uri. 없으면 서버 기본값 사용. |

**예시**
```json
{
  "authCode": "4/0AfJohXmx...",
  "codeVerifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
  "redirectUri": "https://wedding.easyappfactory.com/auth/google/callback"
}
```

- `code`, `redirectUri`가 아니라 **`authCode`** 만 사용. `redirectUri`는 서버 환경변수로 처리.

---

## Kakao 로그인 `POST /api/v1/auth/kakao/login`

| 필드 | 타입 | 필수 | 설명 |
|------|------|------|------|
| **authCode** | string | O | Kakao 인가 코드 |
| **codeVerifier** | string | O | PKCE용 코드 검증자 |
| **redirectUri** | string | X | 인가 요청 시 사용한 redirect_uri. 없으면 서버 기본값 사용. |

**예시**
```json
{
  "authCode": "9d8fYl7x2zQ...",
  "codeVerifier": "NgAfIySigI...IVxKxbmrpg",
  "redirectUri": "https://wedding.easyappfactory.com/auth/kakao/callback"
}
```

---

## 400이 나는 흔한 원인

1. **필드명 불일치**: `code` 로 보내면 안 되고 **`authCode`** 로 보내야 함.
2. **Naver에서 `state` 누락**: Naver만 `state` 필수.
3. **빈 문자열/누락**: `authCode`, `codeVerifier`(및 Naver의 `state`)가 비어 있거나 null이면 400.

응답 본문에 `authCode는 필수입니다`, `state는 필수입니다`, `codeVerifier는 필수입니다` 등의 메시지가 오면 위 스펙을 다시 확인하면 됩니다.
