# 환경변수 분리 설계 (auth-be)

애플리케이션 설정값을 빌드 타임 / 런타임(민감) / 일반 설정으로 나누어 관리합니다.

## 요약

| 구분 | 저장소 | 용도 |
|------|--------|------|
| **빌드 타임** | GitHub Actions Secrets | Docker 이미지 빌드 시 필요한 값 (SonarQube 토큰, 프라이빗 레포 인증 등) |
| **런타임 (민감)** | AWS Secrets Manager 또는 GitHub Secret `ENV_FILE` | DB 비밀번호, JWT 시크릿, 메일 비밀번호, OAuth client secret 등 |
| **일반 설정** | Docker `env_file` 또는 ECS/EC2 환경변수 | 프로필, 포트, 비민감 설정 |

### EC2 Docker 배포 시 단일 env 파일 (ENV_FILE → ~/env/auth-be.env)

배포는 **Docker 방식**으로 수행하며, 환경변수는 **단일 파일**로만 사용합니다.

- **GitHub**: 전체 .env 내용을 **한 개의 Secret**에 넣어 둠. 시크릿 이름: **`ENV_FILE`**. (Repository Settings → Secrets and variables → Actions에서 추가 후, 로컬 .env 파일 전체를 복사·붙여넣기.)
- **EC2**: 배포 시 CI가 `ENV_FILE` 값을 **`~/env/auth-be.env`** 에 복사. 파일명은 패키지명.env 형식으로, 다른 도커 서비스와 구분.
- **실행**: 컨테이너는 `docker run --env-file ~/env/auth-be.env` 로 해당 파일을 로드.

---

## 1. 빌드 타임 변수 (GitHub Actions Secrets)

Docker `docker build` 시 `--build-arg`로 전달하는 값. Dockerfile에는 선택적 ARG로 선언.

| 변수명 | 설명 | 비고 |
|--------|------|------|
| `SONAR_TOKEN` | SonarQube 분석 토큰 | SonarQube 연동 시 사용 |
| (기타) | 프라이빗 Maven/레포 인증 | 필요 시 추가 |

현재 auth-be 빌드에 필수인 빌드 타임 변수는 없음. CI에서 `docker build` 시 필요 시에만 Secrets에 등록 후 `build-args`로 전달.

---

## 2. 런타임 변수 (AWS Secrets Manager)

민감 정보. ECS/EC2 등에서 컨테이너 실행 전에 Secrets Manager에서 조회해 환경변수로 주입.

| 변수명 | 설명 |
|--------|------|
| `DB_PASSWORD` | DB 접속 비밀번호 |
| `JWT_SECRET` | JWT 서명용 비밀키 |
| `MAIL_PASSWORD` | 메일 발송용 비밀번호 |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `KAKAO_CLIENT_SECRET` | Kakao OAuth client secret |
| `NAVER_CLIENT_SECRET` | Naver OAuth client secret |

---

## 3. 일반 설정값 (Docker Compose `env_file` 또는 ECS task 정의)

프로필, 포트, 비민감 연결 정보 등. `env_file` 또는 task definition 환경변수로 주입.

| 변수명 | 설명 | 예시 |
|--------|------|------|
| `SPRING_PROFILES_ACTIVE` | 활성 프로필 | `prod,jwt,oauth` |
| `SERVER_PORT` | 서버 포트 (선택) | `9000` (application.yml에 이미 9000 설정됨) |
| `DB_HOST` | DB 호스트 | |
| `DB_PORT` | DB 포트 | |
| `DB_NAME` | DB 이름 | |
| `DB_USERNAME` | DB 사용자명 | |
| `MAIL_USERNAME` | 메일 계정 (이메일) | |
| `SWAGGER_PATH` | Swagger UI 경로 | |
| `APP_DEFAULT_ZONE` | 기본 타임존 | `Asia/Seoul` |
| `CORS_ALLOWED_ORIGINS` | CORS 허용 오리진 목록 | |
| `GOOGLE_CLIENT_ID` | Google OAuth client id | |
| `GOOGLE_REDIRECT_URI` | Google OAuth redirect URI | |
| `KAKAO_CLIENT_ID` | Kakao OAuth client id | |
| `KAKAO_REDIRECT_URI` | Kakao OAuth redirect URI | |
| `NAVER_CLIENT_ID` | Naver OAuth client id | |
| `NAVER_REDIRECT_URI` | Naver OAuth redirect URI | |
| `JWT_ACCESS_TOKEN_EXPIRATION` | 액세스 토큰 만료 (Duration 형식) | |
| `JWT_REFRESH_TOKEN_EXPIRATION` | 리프레시 토큰 만료 (Duration 형식) | |

---

## Docker 실행 예시

### EC2 배포 (CI에서 ENV_FILE → ~/env/auth-be.env 사용)

CI(GitHub Actions)가 `ENV_FILE` Secret 내용을 EC2의 `~/env/auth-be.env`에 쓴 뒤, 아래처럼 실행합니다.

```bash
docker run -d \
  --restart unless-stopped \
  --name auth-be \
  -p 9000:9000 \
  --env-file ~/env/auth-be.env \
  <DOCKERHUB_USERNAME>/auth-server:latest
```

`~/env/auth-be.env`는 CI가 GitHub Secret `ENV_FILE` 내용을 EC2에 써 넣은 파일이며, 다른 서비스와 구분하기 위해 패키지명.env 형식(auth-be.env)을 사용합니다.

### 로컬/수동 실행 (env_file + 개별 변수)

```bash
# env_file로 일반 설정 로드, Secrets Manager 값은 별도 주입
docker run -d \
  --env-file .env.general \
  -e DB_PASSWORD="$(aws secretsmanager get-secret-value --secret-id prod/auth-be/db --query SecretString --output text)" \
  -e JWT_SECRET="..." \
  -p 9000:9000 \
  <DOCKERHUB_USERNAME>/auth-server:latest
```
