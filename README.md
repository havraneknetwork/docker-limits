# Docker Limits Manager

Moderní a bezpečné webové rozhraní a REST API pro dynamickou správu a aplikaci zdrojových limitů (CPU, RAM) Docker kontejnerů přes cgroups bez nutnosti restartu a s automatickou synchronizací do souborů `docker-compose.yml`.

---

## 🚀 Klíčové vlastnosti

- **Změna limitů za běhu:** Úprava RAM (`mem_limit`) a CPU (`cpus`) bez restartování kontejneru.
- **Automatická synchronizace do Compose:** Změny limitů se atomicky zapisují do příslušných `docker-compose.yml` souborů.
- **OOM ochrana:** Automatická detekce rizika OOM (Out Of Memory) při pokusu nastavit limit RAM nižší než aktuální spotřeba.
- **Autentizace & Zabezpečení:**
  - Web Dashboard: session cookies (HMAC-SHA256 podepsané tokeny, HttpOnly, SameSite).
  - REST API: hlavička `X-API-Key`.
  - Ochrana proti brute-force: IP rate limiting a dočasné uzamčení účtu při opakovaných neúspěšných pokusech.
- **Žádné citlivé údaje v kódu:** Veškeré přihlašovací údaje, síťové vazby, cesty a klíče jsou čteny výhradně z `.env`.

---

## 🛠️ Instalace a spuštění

### 1. Klonování repozitáře a příprava `.env`
```bash
git clone <repo-url> limits
cd limits

# Vytvořte .env z připravené šablony
cp .env.example .env
```

### 2. Konfigurace `.env`
Upravte proměnné v souboru `.env`:
```dotenv
# Síťová vazba a porty
LIMITS_BIND_IP=0.0.0.0
LIMITS_HOST_PORT=8000
LIMITS_PORT=8000

# Cesta k vašim Compose projektům na hostiteli
HOST_PROJECTS_DIR=/home/user
ALLOWED_HOST_ROOT=/home/user

# Bezpečnostní klíče a hesla
LIMITS_API_KEY=vlastni-tajny-api-klic
SESSION_SECRET_KEY=nahodny-silny-klic-pro-sessions
ADMIN_USERNAME=admin
ADMIN_PASSWORD=silne-heslo
```

### 3. Spuštění přes Docker Compose
```bash
docker compose up -d --build
```

Aplikace bude dostupná na portu definovaném v `LIMITS_HOST_PORT` (výchozí `8000`).

---

## 🔒 Konfigurace prostředí (`.env`)

| Proměnná | Výchozí hodnota | Popis |
| :--- | :--- | :--- |
| `LIMITS_BIND_IP` | `0.0.0.0` | IP adresa rozhraní na hostiteli pro bind portu |
| `LIMITS_HOST_PORT` | `8000` | Port vystavený na hostiteli |
| `LIMITS_PORT` | `8000` | Interní port aplikace uvnitř kontejneru |
| `HOST_PROJECTS_DIR` | `.` | Cesta k projektům na hostiteli (namountuje se do kontejneru) |
| `ALLOWED_HOST_ROOT` | `/` | Bezpečnostní sandbox pro zápis do `docker-compose.yml` |
| `LIMITS_API_KEY` | *(náhodný token)* | API klíč pro hlavičku `X-API-Key` |
| `SESSION_SECRET_KEY` | *(náhodný token)* | Tajný klíč pro podepisování session cookies |
| `ADMIN_USERNAME` | `admin` | Přihlašovací jméno pro webový dashboard |
| `ADMIN_PASSWORD` | `""` | Heslo pro webový dashboard (při prázdném je login vypnut) |
| `SESSION_LIFETIME_HOURS`| `72` | Platnost relace v hodinách |
| `MAX_FAILED_LOGIN_ATTEMPTS` | `5` | Počet neúspěšných pokusů před uzamčením účtu |
| `ACCOUNT_LOCKOUT_MINUTES` | `15` | Doba uzamčení účtu v minutách |
| `IP_RATE_LIMIT_ATTEMPTS` | `10` | Max pokusů z jedné IP adresy |
| `IP_RATE_LIMIT_MINUTES` | `15` | Okno pro rate limiting z jedné IP adresy |

---

## 📄 Licence
MIT
