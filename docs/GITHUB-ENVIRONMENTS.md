# GitHub Environments (배포 CI)

배포 워크플로(`.github/workflows/deploy.yml`)는 **GitHub Environments**의 `production` / `alpha`를 사용합니다.  
`main` 브랜치 → `production`, 그 외(`dev`, `deploy/alpha` 등) → `alpha`.

## 설정 절차

1. 저장소 **Settings → Environments**
2. **New environment** 로 `production`, `alpha` 각각 생성
3. 각 환경에 아래 **이름이 동일한** Environment secrets 등록

## Environment secrets (이름 통일)

| Secret 이름 | 설명 |
|-------------|------|
| `DOCKERHUB_USERNAME` | Docker Hub 사용자명 |
| `DOCKERHUB_TOKEN` | Docker Hub Access Token |
| `EC2_HOST` | EC2 SSH 호스트 |
| `EC2_USER` | EC2 SSH 사용자 |
| `EC2_KEY` | SSH 비밀키 — **PEM 원문** 또는 **Base64** |
| `AUTH_BE_ENV_FILE` | 앱 런타임용 `.env` 전체 (멀티라인) |

## 기존 Secret에서 이전할 때

- `PROD_AUTH_BE_ENV_FILE` / `ALPHA_AUTH_BE_ENV_FILE` → 각 환경의 `AUTH_BE_ENV_FILE`
- `PROD_EC2_KEY` / `ALPHA_EC2_KEY` → 각 환경의 `EC2_KEY`
- `PROD_DOCKERHUB_*` / `ALPHA_DOCKERHUB_*` → 각 환경의 `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN`
