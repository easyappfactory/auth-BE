# auth-api

Kotlin / Spring Boot 기반 인증 API입니다. 소셜 로그인(Google, Kakao, Naver), 이메일 인증, JWT·쿠키, `GET /api/v1/auth/introspect` 등을 제공합니다.

## 문서

- [API 명세](docs/api-명세서.md)
- [GitHub Environments / 배포 CI](docs/GITHUB-ENVIRONMENTS.md)

## 실행

```bash
./gradlew bootRun
```

기본 포트 **9000**, 프로필은 `application.yml`의 `spring.profiles` 그룹을 따릅니다.

## 환경 변수

`application.yml`, `application-jwt.yml`, `application-oauth.yml`, 프로필별 `application-*.yml`에 매핑됩니다.  
필요한 키는 위 API 명세와 설정 파일을 참고하세요.
