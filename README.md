# auth-api

Spring Boot 기반 **인증·인가** 백엔드입니다. 소셜 로그인(Google, Kakao, Naver), 이메일 인증 로그인, 계정 연동, JWT·HttpOnly 쿠키, API Gateway용 `introspect` 등을 제공합니다.

## 문서 위치

| 구분 | 내용 |
|------|------|
| **이 README** | 빠른 시작, 환경 변수, 배포, 인증 요약, GitHub Pages 안내 |
| **API 명세** | [`docs/api-명세서.md`](docs/api-명세서.md) |
| **CI 환경** | [`docs/GITHUB-ENVIRONMENTS.md`](docs/GITHUB-ENVIRONMENTS.md) |

---

## 목차

- [문서 위치](#문서-위치)
- [역할 한눈에](#역할-한눈에)
- [기술 스택](#기술-스택)
- [저장소 구조](#저장소-구조)
- [실행 방법](#실행-방법)
- [GitHub Pages](#github-pages)
- [배포 (Docker / EC2)](#배포-docker--ec2)
- [환경 변수](#환경-변수)
- [인증·토큰 요약](#인증토큰-요약)
- [OAuth / PKCE 요약](#oauth--pkce-요약)
- [보안·운영 참고](#보안운영-참고)

---

## 역할 한눈에

| 영역 | 내용 |
|------|------|
| 소셜 로그인 | OAuth2 인가 코드 + PKCE, 범용·제공자별 엔드포인트 |
| 이메일 | 인증 코드 발송/검증, 이메일 로그인·가입, 로그인 후 이메일 연동 |
| 토큰 | JWT Access / Refresh, Refresh는 DB 저장, 웹은 HttpOnly 쿠키 중심 |
| 클라이언트 | `X-Client-Type`(`web` / `app`)으로 쿠키 vs 본문 토큰 분기 |
| 게이트웨이 | `GET /api/v1/auth/introspect`, 응답 헤더 `X-User-Id`, 사일런트 리프레시 |

---

## 기술 스택

| 구분 | 사용 |
|------|------|
| 언어 | Kotlin |
| 런타임 | JDK 25 (Gradle toolchain) |
| 프레임워크 | Spring Boot 4, Spring Web, Spring Security, Spring Data JPA |
| DB | PostgreSQL (런타임), H2 (테스트 등) |
| 인증 | OAuth2 연동, JWT (jjwt) |
| API 탐색 | springdoc OpenAPI 3 (`/v3/api-docs`, UI는 `SWAGGER_PATH`) |
| 기타 | Bucket4j(레이트 리밋), 메일 발송 |

---

## 저장소 구조

```
src/main/kotlin/com/wq/auth/
├── AuthApplication.kt
├── api/
│   ├── controller/          # REST
│   ├── domain/
│   └── external/oauth/
├── security/
├── shared/
└── web/common/

src/main/resources/
├── application.yml
├── application-{local,alpha,prod}.yml
├── application-jwt.yml
└── application-oauth.yml

docs/
├── _config.yml              # GitHub Pages (Jekyll)
├── api-명세서.md            # API 명세
└── GITHUB-ENVIRONMENTS.md   # 배포 CI Environment
```

---

## 실행 방법

**요구:** JDK 17 이상(프로젝트는 **25** 툴체인), Gradle 래퍼.

```bash
./gradlew bootRun
./gradlew build
java -jar build/libs/auth-api-0.0.1-SNAPSHOT.jar
```

- 앱 이름: `auth-api` (`spring.application.name`)
- 기본 포트: **9000**
- 로컬 프로필: 기본 `local` + `jwt` + `oauth` (그룹은 `application.yml` 참고)

---

## GitHub Pages

GitHub에서 정적 사이트로 **`docs/`** 폴더를 게시합니다.

1. 저장소 **Settings → Pages**
2. **Build and deployment**: Branch **`main`**, 폴더 **`/docs`**
3. 저장 후 몇 분 뒤 Pages가 빌드됩니다.

**API 명세 (Pages):** 사이트에서 **`/api-명세서/`** 로 열립니다 (`docs/api-명세서.md`의 `permalink`). 루트 URL(`/`)에는 별도 `index`가 없어 **404일 수 있음**에 유의하세요.

**API 명세 (저장소에서 보기):** `https://github.com/<owner>/<repo>/blob/main/docs/api-명세서.md`

랜딩 페이지가 필요하면 `docs/index.md`를 다시 두면 됩니다.

---

## 배포 (Docker / EC2)

- **`main`** push 시 GitHub Actions로 이미지 빌드·푸시 후 EC2에서 컨테이너 갱신.
- EC2에서는 env를 **단일 파일**로 씁니다. Secret **`ENV_FILE`**(또는 CI에서 쓰는 이름) 전체를 **`~/env/auth-be.env`** 에 두고 `--env-file` 로 실행하는 흐름을 전제로 합니다.

```bash
docker run -d --restart unless-stopped --name auth-be -p 9000:9000 \
  --env-file ~/env/auth-be.env <DOCKERHUB_USERNAME>/auth-server:latest
```

**GitHub Environments**(`production` / `alpha`)와 Secret 이름 표는 [`docs/GITHUB-ENVIRONMENTS.md`](docs/GITHUB-ENVIRONMENTS.md)를 따릅니다.

---

## 환경 변수

설정은 주로 다음에 매핑됩니다.

- `application.yml`
- `application-jwt.yml` — `JWT_SECRET`, 토큰 만료 (`JWT_ACCESS_TOKEN_EXPIRATION`, `JWT_REFRESH_TOKEN_EXPIRATION` 등, Duration 형식 예: `30m`, `P7D`)
- `application-oauth.yml` — OAuth 클라이언트 ID/Secret, redirect URI
- `application-{local,alpha,prod}.yml` — 프로필별

### 자주 쓰는 예시

```properties
JWT_SECRET=BASE64_OR_RAW_SECRET
JWT_ACCESS_TOKEN_EXPIRATION=30m
JWT_REFRESH_TOKEN_EXPIRATION=P7D

DB_HOST=localhost
DB_PORT=5432
DB_NAME=authdb
DB_USERNAME=postgres
DB_PASSWORD=postgres

GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URI=
KAKAO_CLIENT_ID=
KAKAO_CLIENT_SECRET=
KAKAO_REDIRECT_URI=
NAVER_CLIENT_ID=
NAVER_CLIENT_SECRET=
NAVER_REDIRECT_URI=

MAIL_USERNAME=
MAIL_PASSWORD=
SWAGGER_PATH=/
APP_COOKIE_DOMAIN=
```

---

## 인증·토큰 요약

- **Access Token:** 웹은 `accessToken` HttpOnly 쿠키; 앱은 로그인/갱신 응답 본문 등(`X-Client-Type: app`).
- **Refresh Token:** 웹은 `refreshToken` 쿠키; 앱은 요청/응답 본문.
- **호출 시 읽기 순서** (`JwtAuthenticationFilter`):  
  1) `accessToken` 쿠키가 있으면 **Authorization 헤더 무시**  
  2) 없으면 `Authorization: Bearer`

**엔드포인트·DTO 표**는 [`docs/api-명세서.md`](docs/api-명세서.md)를 보세요.

---

## OAuth / PKCE 요약

- Authorization Code는 **1회용**, 받은 뒤 곧바로 교환.
- **Redirect URI**는 인가 요청과 토큰 요청에서 **동일**해야 함.
- **Naver**는 `state` 일치 필요.
- PKCE: `codeVerifier` 등은 DTO 및 제공자 문서를 따름.

참고: [OAuth 2.0](https://tools.ietf.org/html/rfc6749), [PKCE](https://tools.ietf.org/html/rfc7636), [Google](https://developers.google.com/identity/protocols/oauth2), [Kakao](https://developers.kakao.com/docs/latest/ko/kakaologin/rest-api), [Naver](https://developers.naver.com/docs/login/api/api.md)

---

## 보안·운영 참고

- 본 서비스 `SecurityConfig`에서는 **CORS를 끈 상태**이며, 보통 **API Gateway에서 CORS**를 처리합니다. 로컬에서 브라우저로 직접 호출할 때는 게이트웨이·프록시 또는 허용 정책을 맞춥니다.
- 운영에서는 쿠키 `Secure` / `SameSite` 등을 프로필에 맞게 유지합니다.

---

**Maintained by:** GrowGrammers Team  
**Last updated:** 2026-04-08
