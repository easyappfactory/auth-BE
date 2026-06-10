---
layout: default
title: API 명세서
permalink: /api-명세서/
---

# Auth API 명세서

본 문서는 **auth-api** (`com.wq.auth`) REST API의 계약을 정리합니다. 구현 기준은 `src/main/kotlin` 컨트롤러 및 DTO입니다.

> **위치:** 저장소 `docs/api-명세서.md`. GitHub Pages(`/docs`)에서도 동일 경로로 렌더링됩니다.

## 목차

- [공통 규약](#공통-규약)
- [응답 래퍼 `CommonResponse`](#응답-래퍼-commonresponse)
- [인증·토큰 전달](#인증토큰-전달)
- [클라이언트 구분 `X-Client-Type`](#클라이언트-구분-x-client-type)
- [API 목록](#api-목록)
- [OpenAPI (Swagger)](#openapi-swagger)

---

## 공통 규약

| 항목 | 값 |
|------|-----|
| 기본 경로 | `/api/v1` (일부 레거시·테스트용은 `/api/v1/members`, `/api/public` 등) |
| Content-Type | `application/json` (본문이 있는 요청) |
| 서버 포트 (기본) | `9000` (`application.yml`) |

---

## 응답 래퍼 `CommonResponse`

대부분의 JSON 응답은 아래 형태입니다.

| 필드 | 타입 | 설명 |
|------|------|------|
| `success` | `boolean` | 성공 여부 |
| `code` | `string` | 성공 시 `"SUCCESS"`, 실패 시 오류 코드 문자열 |
| `message` | `string` | 사용자/클라이언트용 메시지 |
| `data` | `T \| null` | 페이로드 (없으면 `null`) |

**성공 예시**

```json
{
  "success": true,
  "code": "SUCCESS",
  "message": "로그인에 성공했습니다.",
  "data": null
}
```

예외는 `GlobalExceptionHandler`에서 HTTP 상태와 함께 `CommonResponse` 형태로 반환됩니다.

---

## 인증·토큰 전달

### JWT 추출 우선순위 (`JwtAuthenticationFilter`)

1. **`accessToken` 쿠키**가 있으면 그 값만 사용 (이 경우 `Authorization` 헤더는 **무시**).
2. 쿠키가 없으면 **`Authorization: Bearer <access_token>`**.

### 소셜 로그인·이메일 로그인 성공 시

- **`Set-Cookie`**: `accessToken`, `refreshToken` (HttpOnly 등은 환경·`CookieFactory` 설정에 따름).

### 인증이 필요한 API (`@AuthenticatedApi`)

- 웹: 보통 `accessToken` 쿠키 + `credentials` 포함 요청.
- 앱: `Authorization: Bearer` 또는 정책에 맞는 방식(쿠키 미사용 시 헤더).

---

## 클라이언트 구분 `X-Client-Type`

일부 API는 **필수 헤더**입니다.

| 값 | 의미 |
|----|------|
| `web` | 브라우저: 리프레시 토큰은 **쿠키**(`refreshToken`), 응답 `data`는 종종 생략 |
| `web` 이외 (예: `app`) | 네이티브 앱: 리프레시 토큰은 **요청 본문**으로 전달, 응답 `data`에 토큰 포함 |

해당 헤더가 필요한 엔드포인트는 아래 표에 명시합니다.

---

## API 목록

### 1. 소셜 로그인 (`SocialLoginController`)

| Method | Path | 인증 | 설명 |
|--------|------|------|------|
| POST | `/api/v1/auth/social/login` | 불필요 | 범용 소셜 로그인 (`providerType`: GOOGLE / KAKAO / NAVER) |
| POST | `/api/v1/auth/google/login` | 불필요 | Google 로그인 |
| POST | `/api/v1/auth/kakao/login` | 불필요 | Kakao 로그인 |
| POST | `/api/v1/auth/naver/login` | 불필요 | Naver 로그인 |
| POST | `/api/v1/auth/link/google` | **필요** | Google 계정 연동 |
| POST | `/api/v1/auth/link/kakao` | **필요** | Kakao 계정 연동 |
| POST | `/api/v1/auth/link/naver` | **필요** | Naver 계정 연동 |

**Rate limit (참고)**  
로그인: 분당 10회(10분 윈도우) / 연동: 분당 5회(10분 윈도우) — 컨트롤러 `@RateLimit` 기준.

#### 1.1 범용 소셜 로그인 `POST /api/v1/auth/social/login`

**Body — `SocialLoginRequestDto`**

| 필드 | 필수 | 설명 |
|------|------|------|
| `authCode` | 예 | OAuth 인가 코드 |
| `codeVerifier` | DTO상 필수 문자열 | PKCE용 (Naver 등에서도 필드 존재) |
| `state` | 조건부 | **Naver** 시 인가 요청과 동일한 값 |
| `providerType` | 예 | `GOOGLE`, `KAKAO`, `NAVER` |
| `redirectUri` | 아니오 | 허용 목록에 있을 때만 사용, 없으면 서버 기본값 |

#### 1.2 Google `POST /api/v1/auth/google/login`

**Body — `GoogleSocialLoginRequestDto`**

| 필드 | 필수 | 설명 |
|------|------|------|
| `authCode` | 예 | 인가 코드 |
| `codeVerifier` | 예 | PKCE 코드 검증자 |
| `redirectUri` | 아니오 | 선택, 서버 기본값 대체 |

#### 1.3 Kakao `POST /api/v1/auth/kakao/login`

**Body — `KakaoSocialLoginRequestDto`**

| 필드 | 필수 | 설명 |
|------|------|------|
| `authCode` | 예 | 인가 코드 |
| `codeVerifier` | 예 | PKCE (권장) |
| `redirectUri` | 아니오 | 선택 |

#### 1.4 Naver `POST /api/v1/auth/naver/login`

**Body — `NaverSocialLoginRequestDto`**

| 필드 | 필수 | 설명 |
|------|------|------|
| `authCode` | 예 | 인가 코드 |
| `state` | 예 | CSRF용, 인가 요청 시 사용한 값과 동일 |
| `codeVerifier` | 예 | PKCE 코드 검증자 |
| `redirectUri` | 아니오 | 선택 |

#### 1.5 소셜 계정 연동 (Google / Kakao / Naver)

로그인된 사용자의 `accessToken`(쿠키 또는 정책에 맞는 인증) 필요.

- **Google / Kakao**: `authCode`, `codeVerifier` 필수, `redirectUri` 선택.
- **Naver**: `authCode`, `state`, `codeVerifier` 필수, `redirectUri` 선택.

**성공 시**  
`CommonResponse` 메시지 문자열만 반환 (토큰 재발급 없음).

---

### 2. 이메일 인증 (`AuthEmailController`)

| Method | Path | 인증 | 설명 |
|--------|------|------|------|
| POST | `/api/v1/auth/email/request` | 불필요 | 인증 코드 이메일 발송 |
| POST | `/api/v1/auth/email/verify` | 불필요 | 인증 코드 검증 |

**`POST .../request` Body — `EmailRequestDto`**

| 필드 | 타입 |
|------|------|
| `email` | string |

**`POST .../verify` Body — `EmailVerifyRequestDto`**

| 필드 | 타입 |
|------|------|
| `email` | string |
| `verifyCode` | string |

Rate limit: 요청 3회/10분, 검증 10회/5분 (컨트롤러 기준).

---

### 3. 인증·세션 (`AuthController`)

| Method | Path | 인증 | `X-Client-Type` |
|--------|------|------|-----------------|
| POST | `/api/v1/auth/members/email-login` | 불필요 | **필수** |
| POST | `/api/v1/auth/link/email-login` | **필요** | 불필요 |
| POST | `/api/v1/auth/members/logout` | 불필요 (리프레시 토큰으로 식별) | **필수** |
| POST | `/api/v1/auth/members/refresh` | 불필요 (리프레시 토큰) | **필수** |
| GET | `/api/v1/auth/introspect` | 불필요 (토큰으로 검증) | 선택 |

#### 3.1 이메일 로그인/가입 `POST /api/v1/auth/members/email-login`

**Headers**

- `X-Client-Type`: `web` \| `app` (필수)

**Body — `EmailLoginRequestDto`**

| 필드 | 타입 | 설명 |
|------|------|------|
| `email` | string | |
| `verifyCode` | string | 이메일 인증 코드 |
| `deviceId` | string \| null | 선택 |

**동작**

- 성공 시 `Set-Cookie`로 `accessToken`, `refreshToken` 설정.
- `X-Client-Type: web` → `data`는 `null`.
- `app` → `data`에 `LoginResponseDto` (`refreshToken` 포함).

#### 3.2 이메일 계정 연동 `POST /api/v1/auth/link/email-login`

**Body — `EmailLoginLinkRequestDto`**

| 필드 | 설명 |
|------|------|
| `email` | 이메일 |
| `verifyCode` | 6자리 숫자 |

#### 3.3 로그아웃 `POST /api/v1/auth/members/logout`

**Headers**

- `X-Client-Type`: **필수**

**Body — `LogoutRequestDto` (선택)**

| 필드 | 설명 |
|------|------|
| `refreshToken` | `app`일 때 본문으로 전달. `web`은 `Cookie: refreshToken` |

**동작**

- `web`: 서버가 리프레시 삭제 후 `accessToken`/`refreshToken` 쿠키 만료 응답.

#### 3.4 액세스 토큰 재발급 `POST /api/v1/auth/members/refresh`

**Headers**

- `X-Client-Type`: **필수**

**Body — `RefreshAccessTokenRequestDto` (선택)**

| 필드 | 설명 |
|------|------|
| `refreshToken` | `app`일 때 필수에 가깝게 사용 |
| `deviceId` | 선택 |

**동작**

- `web`: `refreshToken` 쿠키 사용.
- 성공 시 새 토큰 `Set-Cookie`.
- `web` → `data` null; `app` → `data`에 `RefreshAccessTokenResponseDto` (`refreshToken`).

#### 3.5 토큰 introspect (Gateway 연동) `GET /api/v1/auth/introspect`

**목적**: Access Token 검증 후 사용자 식별자를 헤더로 전달.

**토큰 출처 (구현상 `JwtAuthenticationFilter`와 정합)**

- 우선 `accessToken` 쿠키, 없으면 `Authorization: Bearer`.

**동작 요약**

- 유효한 AT로부터 사용자 UUID(`opaqueId`)를 구해 응답 헤더에 설정.
- AT 남은 시간이 5분 미만이거나 만료된 경우, `refreshToken` 쿠키로 **사일런트 리프레시** 시도 후 새 쿠키 `Set-Cookie`.
- 실패 시 401 및 쿠키 제거 가능.

**성공 응답 헤더**

| 헤더 | 설명 |
|------|------|
| `X-User-Id` | 사용자 UUID (opaqueId) |

응답 본문은 컨트롤러에서 별도 JSON을 쓰지 않을 수 있음(상태 200 + 헤더 중심).

---

### 4. 회원 (`MemberController`)

| Method | Path | 인증 | 설명 |
|--------|------|------|------|
| GET | `/api/v1/auth/members/user-info` | **필요** | 로그인 사용자 정보 |
| GET | `/api/v1/members` | 설정상 인증 필요 | 전체 회원 목록 (운영 시 권한 검토 권장) |
| GET | `/api/v1/members/{id}` | 설정상 인증 필요 | 단건 조회 |
| POST | `/api/v1/members` | 설정상 인증 필요 | 회원 생성 |
| PUT | `/api/v1/members/{id}/nickname` | 설정상 인증 필요 | 닉네임 변경 (`{"nickname":"..."}`) |
| DELETE | `/api/v1/members/{id}` | 설정상 인증 필요 | 삭제 |

#### 4.1 내 정보 `GET /api/v1/auth/members/user-info`

**성공 시 `data` — `UserInfoResponseDto`**

| 필드 | 타입 |
|------|------|
| `userId` | string (UUID, opaqueId) |
| `nickname` | string |
| `email` | string |
| `linkedProviders` | `ProviderType[]` (예: GOOGLE, KAKAO, NAVER, EMAIL) |

---

### 5. 보안 테스트용 (`TestSecurityController`)

개발·테스트용이며 운영에서는 제거·차단 검토.

| Method | Path | 인증 |
|--------|------|------|
| GET | `/api/public/test` | 불필요 |
| GET | `/api/test` | 필요 (`@AuthenticatedApi`) |
| GET | `/api/public/token` | 불필요 (테스트용 JWT 발급, `opaqueId` 쿼리 가능) |

---

## OpenAPI (Swagger)

- API 문서 JSON: `/v3/api-docs`
- Swagger UI 경로: `springdoc.swagger-ui.path` — 환경변수 **`SWAGGER_PATH`** 로 설정 (`application.yml`).

로컬 예시: `http://localhost:9000/swagger-ui/index.html` (설정에 따라 경로 변동 가능)

---

## 참고

- 배포·환경 변수·EC2 Docker는 저장소 **README** 및 [`GITHUB-ENVIRONMENTS.md`](GITHUB-ENVIRONMENTS.md)를 참고하세요.
- API Gateway 연동 시 `GET /api/v1/auth/introspect`와 응답 헤더 `X-User-Id`를 활용할 수 있습니다.
