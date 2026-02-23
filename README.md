# Auth-BE

Spring Boot 기반의 인증/소셜 로그인 및 계정 연동(링크) 백엔드입니다.

## 목차
- [주요 기능](#주요-기능)
- [기술 스택](#기술-스택)
- [빠른 시작](#빠른-시작)
- [배포 (EC2 Docker)](#배포-ec2-docker)
- [환경 변수 설정](#환경-변수-설정)
- [API 엔드포인트](#api-엔드포인트)
- [인증 플로우](#인증-플로우)
- [OAuth/PKCE 규칙](#oauthpkce-규칙)
- [보안 고려사항](#보안-고려사항)

## 주요 기능

- **소셜 로그인**: Google, Kakao, Naver OAuth2 지원
- **이메일 인증**: 인증코드 기반 이메일 로그인/가입
- **계정 연동**: 기존 계정에 소셜 계정 추가 링크
- **PKCE 지원**: Authorization Code Flow with PKCE
- **보안 강화**: HttpOnly 쿠키 기반 RefreshToken 관리
- **토큰 갱신**: AccessToken 자동 갱신 지원

## 기술 스택

- **언어**: Kotlin
- **프레임워크**: Spring Boot 3, Spring Web, Spring Security
- **인증**: OAuth2 (Google, Kakao, Naver)
- **검증**: Validation
- **로깅**: Kotlin Logging
- **직렬화**: Jackson
- **HTTP 클라이언트**: RestTemplate
- **빌드**: Gradle (KTS)

## 빠른 시작

### 요구사항
- JDK 17+
- Gradle 8+

### 실행

```bash
# 개발 환경 실행
./gradlew bootRun

# 빌드
./gradlew build

# JAR 실행
java -jar build/libs/auth-be-0.0.1-SNAPSHOT.jar
```

## 배포 (EC2 Docker)

배포는 **Docker** 방식으로 수행하며, systemd/JAR 직접 실행은 사용하지 않습니다.

- **main** 브랜치 push 시 GitHub Actions가 Docker 이미지를 빌드·푸시한 뒤 EC2에 SSH로 접속해 컨테이너를 갱신합니다.
- EC2에서는 env를 **단일 파일**로만 사용합니다. GitHub Secret **`ENV_FILE`**(전체 .env 내용)을 CI가 **`~/env/auth-be.env`** 에 복사하고, 컨테이너는 `--env-file ~/env/auth-be.env` 로 실행합니다. (다른 도커 서비스와 구분을 위해 패키지명.env 형식 사용.)

실행 예:

```bash
docker run -d --restart unless-stopped --name auth-be -p 9000:9000 --env-file ~/env/auth-be.env <DOCKERHUB_USERNAME>/auth-server:latest
```

## 환경 변수 설정

환경 변수는 다음 파일에 매핑됩니다:
- `src/main/resources/application.yml`
- `src/main/resources/application-jwt.yml`
- `src/main/resources/application-dev.yml`
- `src/main/resources/application-prod.yml`
- `src/main/resources/application-oauth.yml`

### 필수 환경 변수

#### 공통
```properties
# CORS 설정
CORS_ALLOWED_ORIGINS=http://localhost:5173,http://localhost:3000

# JWT 설정
JWT_SECRET_KEY=your-secret-key-min-256-bits
JWT_ACCESS_TOKEN_EXPIRATION=3600000      # 1시간 (ms)
JWT_REFRESH_TOKEN_EXPIRATION=604800000   # 7일 (ms)
```

#### Google OAuth
```properties
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:5173/auth/google/callback
```

#### Kakao OAuth
```properties
KAKAO_CLIENT_ID=your-kakao-rest-api-key
KAKAO_CLIENT_SECRET=your-kakao-client-secret
KAKAO_REDIRECT_URI=http://localhost:5173/auth/kakao/callback
```

#### Naver OAuth
```properties
NAVER_CLIENT_ID=your-naver-client-id
NAVER_CLIENT_SECRET=your-naver-client-secret
NAVER_REDIRECT_URI=http://localhost:5173/auth/naver/callback
```

### 선택 환경 변수
```properties
# 이메일 인증 (사용 시)
MAIL_HOST=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
```

## API 엔드포인트

### 소셜 로그인/연동 (`SocialLoginController`)

| Method | Endpoint | 설명 | 인증 |
|--------|----------|------|------|
| POST | `/api/v1/auth/google/login` | Google 로그인 | 불필요 |
| POST | `/api/v1/auth/kakao/login` | Kakao 로그인 | 불필요 |
| POST | `/api/v1/auth/naver/login` | Naver 로그인 | 불필요 |
| POST | `/api/v1/auth/link/google` | Google 계정 연동 | **필요** |
| POST | `/api/v1/auth/link/kakao` | Kakao 계정 연동 | **필요** |
| POST | `/api/v1/auth/link/naver` | Naver 계정 연동 | **필요** |

**요청 바디 필드 (Provider별)**  
- **Google/Kakao**: `authCode`, `codeVerifier` (필수). `redirectUri`는 서버 환경변수 사용.
- **Naver**: `authCode`, `state`, `codeVerifier` (세 필수 모두 필요). 인가 요청 시 사용한 `state`와 동일한 값 전달.

**요청 예시** (Google 로그인):
```json
POST /api/v1/auth/google/login
Content-Type: application/json

{
  "authCode": "4/0AfJohXmx...",
  "codeVerifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
}
```

**요청 예시** (Naver 로그인):
```json
POST /api/v1/auth/naver/login
Content-Type: application/json

{
  "authCode": "네이버에서_받은_인가코드",
  "state": "인가_요청시_사용한_state_값과_동일",
  "codeVerifier": "PKCE_코드_검증자"
}
```

> AccessToken은 Authorization 헤더로 자동 설정됩니다.
> RefreshToken은 HttpOnly 쿠키로 자동 설정됩니다.

### 이메일 인증/로그인 (`AuthEmailController`, `AuthController`)

| Method | Endpoint | 설명 | 인증 |
|--------|----------|------|------|
| POST | `/api/v1/auth/email/request` | 이메일 인증코드 발송 | 불필요 |
| POST | `/api/v1/auth/email/verify` | 이메일 인증코드 검증 | 불필요 |
| POST | `/api/v1/auth/members/email-login` | 이메일 로그인/가입 | 불필요 |
| POST | `/api/v1/auth/members/logout` | 로그아웃 | 불필요 |
| POST | `/api/v1/auth/members/refresh` | AccessToken 재발급 | 불필요* |

\* RefreshToken 쿠키 필요

**요청 예시** (이메일 인증 요청):
```json
POST /api/v1/auth/email/request
Content-Type: application/json

{
  "email": "user@example.com"
}
```

**요청 예시** (토큰 재발급):
```http
POST /api/v1/auth/members/refresh
Cookie: refreshToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 회원 관리 (`MemberController`)

| Method | Endpoint | 설명 | 인증 |
|--------|----------|------|------|
| GET | `/api/v1/auth/members/user-info` | 내 정보 조회 | **필요** |
| GET | `/api/v1/members` | 회원 목록 조회 | 불필요 |
| GET | `/api/v1/members/{id}` | 회원 단건 조회 | 불필요 |
| POST | `/api/v1/members` | 회원 생성 | 불필요 |
| PUT | `/api/v1/members/{id}/nickname` | 닉네임 변경 | 불필요 |
| DELETE | `/api/v1/members/{id}` | 회원 삭제 | 불필요 |

> 내 정보 조회 이외에는 테스트용 CRUD 엔드포인트입니다. 실제 운영 시 권한 설정 필요.

**인증 헤더 형식**:
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 보안 테스트 (`TestSecurityController`)

개발/테스트 전용 엔드포인트:

| Method | Endpoint | 설명 | 권한 |
|--------|----------|------|------|
| GET | `/api/public/test` | 공개 API 테스트 | 없음 |
| GET | `/api/test` | 인증 API 테스트 | USER |
| GET | `/api/admin/test` | 관리자 API 테스트 | ADMIN |
| GET | `/api/public/token` | 테스트용 JWT 발급 | 없음 |

## 인증 플로우

### 소셜 로그인 (PKCE) 전체 플로우

```
┌─────────┐                ┌──────────┐                ┌──────────┐
│  Client │                │ Auth-BE  │                │  OAuth   │
│(Browser)│                │ (Backend)│                │ Provider │
└────┬────┘                └─────┬────┘                └─────┬────┘
     │                           │                           │
     │ 1. Generate code_verifier │                           │
     │    & code_challenge       │                           │
     ├──────────────────────────>│                           │
     │                           │                           │
     │ 2. Redirect to OAuth      │                           │
     ├───────────────────────────┼──────────────────────────>│
     │   (with code_challenge)   │                           │
     │                           │                           │
     │ 3. User Authentication    │                           │
     │<──────────────────────────┼───────────────────────────┤
     │                           │                           │
     │ 4. Redirect with code     │                           │
     │<──────────────────────────┼───────────────────────────┤
     │                           │                           │
     │ 5. POST /auth/{provider}  │                           │
     │   (code + code_verifier)  │                           │
     ├──────────────────────────>│                           │
     │                           │ 6. Exchange code for token│
     │                           │   (with code_verifier)    │
     │                           ├──────────────────────────>│
     │                           │                           │
     │                           │ 7. Access Token           │
     │                           │<──────────────────────────┤
     │                           │                           │
     │                           │ 8. Get User Info          │
     │                           ├──────────────────────────>│
     │                           │<──────────────────────────┤
     │                           │                           │
     │ 9. JWT Tokens             │                           │
     │   + RefreshToken Cookie   │                           │
     │<──────────────────────────┤                           │
     │                           │                           │
```

## OAuth/PKCE 규칙

### PKCE (Proof Key for Code Exchange)
- **Authorization 요청**: `code_challenge` (SHA-256 해시) 전송
- **Token 교환**: 동일한 `code_verifier` 사용
- **보안**: Authorization Code 탈취 공격 방지

### Authorization Code
- **1회용**: 사용 후 즉시 무효화
- **유효시간**: 매우 짧음 (보통 10분 이내)
- **재사용 시**: `400 invalid_grant` 에러 발생
- **권장사항**: 획득 즉시 토큰으로 교환

### Redirect URI
- **일치 필수**: Authorization과 Token 교환 시 **완전히 동일**해야 함
- **쿼리 파라미터**: 포함 시 정확히 일치 필요
- **백엔드 동작**: 환경변수(`*_REDIRECT_URI`)에 설정된 값 사용
- **화이트리스트**: 운영 환경에서 반드시 검증 필요

### Naver 특이사항
- **State 파라미터**: Authorization과 Token 교환 시 동일 값 필수
- **CSRF 방어**: State 값으로 요청 위변조 방지

### Provider별 Scope

#### Google
```
openid email profile
```

#### Kakao
```
account_email profile_nickname
```

#### Naver
```
email name
```

## 보안 고려사항

### 토큰 관리
- **AccessToken**: AUTHORIZATION 헤더 저장 (짧은 만료시간)
- **RefreshToken**: HttpOnly 쿠키로만 전달 (XSS 공격 방지)
- **Cookie 속성**:
  - `HttpOnly`: JavaScript 접근 차단
  - `Secure`: HTTPS에서만 전송 (운영 환경)
  - `SameSite=Strict`: CSRF 공격 방지

### CORS 설정
```yaml
cors:
  allowed-origins: ${CORS_ALLOWED_ORIGINS}
  allowed-methods: GET, POST, PUT, DELETE, OPTIONS
  allowed-headers: "*"
  allow-credentials: true
```

### 환경별 쿠키 설정
```kotlin
// 개발 환경
secure = false
sameSite = Lax

// 운영 환경
secure = true
sameSite = Strict
```

## 추가 자료

- [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749)
- [PKCE RFC](https://tools.ietf.org/html/rfc7636)
- [Google OAuth 문서](https://developers.google.com/identity/protocols/oauth2)
- [Kakao OAuth 문서](https://developers.kakao.com/docs/latest/ko/kakaologin/rest-api)
- [Naver OAuth 문서](https://developers.naver.com/docs/login/api/api.md)

---

**Maintained by**: GrowGrammers Team  
**Last Updated**: 2025-10-16
