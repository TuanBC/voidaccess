#!/usr/bin/env bash
# VoidAccess Interactive Setup Wizard
# Works on macOS (zsh/bash), Ubuntu/Debian (bash), and Windows Git Bash/WSL

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
NC=$'\033[0m'

find_compose() {
    if [ -f "$SCRIPT_DIR/infra/docker-compose.yml" ]; then
        echo "$SCRIPT_DIR/infra/docker-compose.yml"
    elif [ -f "$SCRIPT_DIR/docker-compose.yml" ]; then
        echo "$SCRIPT_DIR/docker-compose.yml"
    else
        printf "  ${RED}✗${NC}  docker-compose.yml not found\n" >&2
        exit 1
    fi
}
COMPOSE_FILE=$(find_compose)
# Absolute paths so --env-file (containing POSTGRES_PASSWORD, JWT_SECRET, etc.)
# is always resolved correctly even if cwd changes mid-script.
COMPOSE_CMD="docker compose -f $COMPOSE_FILE \
    --project-directory $SCRIPT_DIR \
    --env-file $SCRIPT_DIR/.env"

print_ok()   { printf "${GREEN}  ✓${NC}  %s\n" "$1"; }
print_fail() { printf "${RED}  ✗${NC}  %s\n" "$1"; }
print_warn() { printf "${YELLOW}  ⚠${NC}  %s\n" "$1"; }
print_info() { printf "${DIM}  →${NC}  %s\n" "$1"; }
prompt()     { printf "${CYAN}  ▸${NC}  %s" "$1"; }

print_step() {
    local num="$1"
    local title="$2"
    printf "\n${CYAN}  ┌─────────────────────────────────┐${NC}\n"
    printf "${CYAN}  │${NC} ${BOLD}  %s / 10  ·  %s${NC}" "$num" "$title"
    local pad=$((33 - ${#title} - ${#num} - 8))
    [ $pad -lt 0 ] && pad=0
    printf "%${pad}s${CYAN}│${NC}\n" ""
    printf "${CYAN}  └─────────────────────────────────┘${NC}\n\n"
}

show_progress() {
    local pid=$1
    local msg="$2"
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        i=$(( (i+1) % 10 ))
        printf "\r  ${CYAN}${spin:$i:1}${NC}  %s" "$msg"
        sleep 0.1
    done
    printf "\r  ${GREEN}✓${NC}  %s\n" "$msg"
}

spin() {
    local pid=$1
    local msg="$2"
    local frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    tput civis 2>/dev/null || true
    while kill -0 "$pid" 2>/dev/null; do
        local frame="${frames:$i:1}"
        printf "\r  ${CYAN}%s${NC}  %s" "$frame" "$msg"
        i=$(( (i + 1) % 10 ))
        sleep 0.1
    done
    tput cnorm 2>/dev/null || true
    printf "\r"
}

_prompt() {
    local prompt_text="$1"
    local default="$2"
    read -r -p "$prompt_text" answer || answer="$default"
    echo "${answer:-$default}"
}

env_update() {
    local key="$1"
    local value="$2"
    local env_file="$SCRIPT_DIR/.env"

    if grep -q "^${key}=" "$env_file" 2>/dev/null; then
        if sed -i "s|^${key}=.*|${key}=${value}|" "$env_file" 2>/dev/null; then
            :
        else
            python3 -c "
import re
with open('$env_file', 'r') as f:
    content = f.read()
content = re.sub(r'^${key}=.*', '${key}=${value}', content, flags=re.MULTILINE)
with open('$env_file', 'w') as f:
    f.write(content)
"
        fi
    else
        echo "${key}=${value}" >> "$env_file"
    fi
}

env_append() {
    local line="$1"
    local env_file="$SCRIPT_DIR/.env"
    echo "$line" >> "$env_file"
}

wait_for_key() {
    local prompt_text="$1"
    local default="${2:-}"
    local yn_default=""
    if [ "$default" = "Y" ] || [ "$default" = "y" ]; then
        yn_default="Y/n"
    elif [ "$default" = "N" ] || [ "$default" = "n" ]; then
        yn_default="y/N"
    else
        yn_default="y/n"
    fi
    local response=""
    printf "\n"
    prompt "$prompt_text [$yn_default]: "
    response="$(_prompt "" "$default")"
    echo "$response"
}

# =============================================================================
# Opening banner
# =============================================================================
printf "\n"
printf "${CYAN}"
printf "  ╔═══════════════════════════════════╗\n"
printf "  ║                                   ║\n"
printf "  ║     V O I D A C C E S S           ║\n"
printf "  ║     Setup Wizard                  ║\n"
printf "  ║                                   ║\n"
printf "  ╚═══════════════════════════════════╝\n"
printf "${NC}\n"

# =============================================================================
# Docker permission check
# =============================================================================
check_docker_permission() {
    if ! docker info > /dev/null 2>&1; then
        if sudo docker info > /dev/null 2>&1; then
            printf "\n  ${YELLOW}⚠${NC}  Docker requires sudo on this system.\n"
            printf "  ${DIM}→${NC}  Re-run with: ${BOLD}sudo bash setup.sh${NC}\n\n"
            printf "  ${DIM}→${NC}  Or add yourself to the docker group (no sudo needed after):\n"
            printf "       ${DIM}sudo usermod -aG docker \$USER && newgrp docker${NC}\n\n"
            exit 1
        else
            printf "\n  ${RED}✗${NC}  Docker not found or not running.\n"
            printf "  ${DIM}→${NC}  Install: ${DIM}https://docs.docker.com/get-docker/${NC}\n\n"
            exit 1
        fi
    fi
}

check_docker_permission

# =============================================================================
# STEP 1: Prerequisites Check
# =============================================================================
print_step "1" "Prerequisites"

check_cmd() {
    if command -v "$1" >/dev/null 2>&1; then
        print_ok "$1 found: $($1 --version 2>/dev/null | head -n1 | cut -d' ' -f1-2 || echo "installed")"
        return 0
    else
        print_fail "$1 not found"
        return 1
    fi
}

check_python() {
    _py_pipe_test() {
        echo '{}' | "$1" -c "import sys,json; json.load(sys.stdin)" >/dev/null 2>&1
    }

    if python3 --version > /dev/null 2>&1 && _py_pipe_test python3; then
        PY_CMD="python3"
    elif python --version > /dev/null 2>&1 && _py_pipe_test python; then
        PY_CMD="python"
    else
        PY_CMD=""
    fi

    if [ -n "$PY_CMD" ]; then
        if ! $PY_CMD -c "import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)" > /dev/null 2>&1; then
            PY_CMD=""
        fi
    fi

    if [ -n "$PY_CMD" ]; then
        print_ok "Python ($PY_CMD)"
    else
        print_warn "Python 3.8+ not found (or stdin pipe broken)"
        print_info "Secret generation will use /dev/urandom fallback"
    fi
}

DOCKER_OK=false
DOCKER_COMPOSE_OK=false
TOR_OK=false
PYTHON_OK=false
GIT_OK=false

if [ ! -t 0 ]; then
    print_warn "Non-interactive mode detected. Using defaults for all prompts."
fi

if check_cmd docker; then
    DOCKER_OK=true
fi

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    print_ok "docker compose v$(docker compose version 2>/dev/null | grep -oP 'v\K[0-9.]+' | head -1 || echo 'available')"
    DOCKER_COMPOSE_OK=true
else
    if command -v docker-compose >/dev/null 2>&1; then
        print_ok "docker-compose installed"
        DOCKER_COMPOSE_OK=true
    else
        print_fail "docker compose not found"
    fi
fi

check_cmd tor >/dev/null 2>&1 && TOR_OK=true || print_warn "Tor not found (optional, for non-Docker setup)"
check_python
[ -n "$PY_CMD" ] && PYTHON_OK=true
check_cmd git && GIT_OK=true

printf "\n"
if [ "$DOCKER_OK" = false ]; then
    print_fail "Docker is required to run VoidAccess."
    printf "\n"
    printf "  Install Docker:\n"
    printf "    ${DIM}macOS:    brew install --cask docker${NC}\n"
    printf "    ${DIM}Ubuntu:   sudo apt install docker.io docker-compose${NC}\n"
    printf "    ${DIM}Windows:  https://docs.docker.com/desktop/install/windows-install/${NC}\n"
    printf "\n"
    exit 1
fi

if [ "$PYTHON_OK" = false ]; then
    print_warn "Python not found — will use Docker for all services."
fi

if [ "$GIT_OK" = false ]; then
    print_warn "Git not found — cannot verify source version."
fi

# =============================================================================
# STEP 2: Environment File Setup
# =============================================================================
print_step "2" "Environment"

ENV_FILE="$SCRIPT_DIR/.env"
ENV_EXAMPLE="$SCRIPT_DIR/.env.example"
OVERWRITE=false

# Save existing password BEFORE overwriting — needed to preserve compatibility
# with an existing postgres_data volume (which only knows the original password).
OLD_POSTGRES_PASSWORD=""
if [ -f "$ENV_FILE" ]; then
    OLD_POSTGRES_PASSWORD=$(grep '^POSTGRES_PASSWORD=' "$ENV_FILE" 2>/dev/null | cut -d= -f2)
fi

if [ -f "$ENV_FILE" ]; then
    print_info "A .env file already exists."
    response="$(wait_for_key "Overwrite" "N")"
    if [ "$response" = "Y" ] || [ "$response" = "y" ]; then
        OVERWRITE=true
        print_info "Overwriting existing .env"
    else
        print_info "Keeping existing .env — skipping configuration."
        printf "\n"
        print_warn "To re-run setup, delete or rename .env and run setup.sh again."
        exit 0
    fi
fi

if [ -f "$ENV_EXAMPLE" ]; then
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    print_ok "Created .env from .env.example"
else
    touch "$ENV_FILE"
    print_info "Created empty .env"
fi

# =============================================================================
# STEP 3: Generate Required Secrets
# =============================================================================
print_step "3" "Secrets"

if [ -n "$PY_CMD" ]; then
    JWT_SECRET=$($PY_CMD -c "import secrets; print(secrets.token_hex(32))")
    POSTGRES_PASSWORD=$($PY_CMD -c "import secrets; print(secrets.token_hex(16))")
else
    if [ -f /dev/urandom ]; then
        JWT_SECRET=$(cat /dev/urandom | tr -dc 'a-f0-9' | head -c 64)
        POSTGRES_PASSWORD=$(cat /dev/urandom | tr -dc 'a-f0-9' | head -c 32)
    else
        printf "${RED}  ✗${NC}  Cannot generate secrets — install Python 3\n"
        exit 1
    fi
fi

# Handle pre-existing voidaccess_postgres_data volume.
#
# Docker volumes are global — they survive `git clone` into a new directory.
# If a previous setup.sh run created the volume, postgres was initialized with
# THAT password. The new password we just generated won't authenticate, and
# fastapi's entrypoint will exit 1 after a 30s retry window. Catch that here.
#
#   - If we have OLD_POSTGRES_PASSWORD (preserved from existing .env): reuse it.
#   - If volume exists but OLD is empty (.env was wiped or this is a re-clone):
#     the volume is unrecoverable. Offer to wipe before we waste a 5-min build.
HAS_PG_VOLUME=false
if docker volume ls --format '{{.Name}}' 2>/dev/null \
        | grep -qxF "voidaccess_postgres_data"; then
    HAS_PG_VOLUME=true
fi

if [ "$HAS_PG_VOLUME" = "true" ]; then
    if [ -n "$OLD_POSTGRES_PASSWORD" ]; then
        POSTGRES_PASSWORD="$OLD_POSTGRES_PASSWORD"
        print_info "Existing database volume detected — preserving PostgreSQL password"
    else
        printf "\n"
        print_warn "Found 'voidaccess_postgres_data' volume from a previous setup,"
        print_warn "but no recoverable POSTGRES_PASSWORD (no prior .env on disk)."
        print_info "Docker volumes are global — they persist across re-cloning the repo."
        print_info "The fastapi container will fail to authenticate against this volume."
        printf "\n"
        response="$(wait_for_key "Wipe stale volumes and start fresh?" "Y")"
        if [ -z "$response" ] || [ "$response" = "Y" ] || [ "$response" = "y" ]; then
            print_info "Removing stale voidaccess_* volumes..."
            # Best-effort: bring down anything still attached, then nuke volumes.
            $COMPOSE_CMD down -v >/dev/null 2>&1 || true
            docker volume rm -f \
                voidaccess_postgres_data \
                voidaccess_chroma_data \
                voidaccess_monitors_data \
                voidaccess_tor_data >/dev/null 2>&1 || true
            print_ok "Stale volumes removed — proceeding with fresh password"
        else
            print_fail "Cannot continue — fastapi would fail to authenticate."
            print_info "Either wipe manually:"
            printf "    ${DIM}docker volume rm voidaccess_postgres_data \\
        voidaccess_chroma_data voidaccess_monitors_data voidaccess_tor_data${NC}\n"
            print_info "Or restore the .env that matches the existing volume's password."
            exit 1
        fi
    fi
fi

env_update "JWT_SECRET" "$JWT_SECRET"
env_update "POSTGRES_PASSWORD" "$POSTGRES_PASSWORD"
print_ok "Generated JWT_SECRET and POSTGRES_PASSWORD"

# =============================================================================
# STEP 4: LLM Provider Selection
# =============================================================================
print_step "4" "LLM Provider"

printf "  ${BOLD}Choose your LLM provider:${NC}\n\n"
printf "  ${CYAN}[1]${NC} ${BOLD}Groq${NC}          ${GREEN}FREE${NC} · No credit card needed\n"
printf "      Llama 3.3 70B · ${DIM}console.groq.com${NC}\n\n"
printf "  ${CYAN}[2]${NC} ${BOLD}OpenRouter${NC}    ${GREEN}FREE${NC} models available\n"
printf "      100+ models · ${DIM}openrouter.ai${NC}\n\n"
printf "  ${CYAN}[3]${NC} ${BOLD}Anthropic${NC}     ${YELLOW}Paid${NC}\n"
printf "      Claude models · ${DIM}console.anthropic.com${NC}\n\n"
printf "  ${CYAN}[4]${NC} ${BOLD}OpenAI${NC}        ${YELLOW}Paid${NC}\n"
printf "      GPT-4o · ${DIM}platform.openai.com${NC}\n\n"
printf "  ${CYAN}[5]${NC} ${BOLD}Google Gemini${NC} ${GREEN}FREE${NC} tier available\n"
printf "      Gemini 1.5 Flash · ${DIM}aistudio.google.com${NC}\n\n"
printf "  ${CYAN}[6]${NC} ${BOLD}Ollama${NC}        ${GREEN}FREE${NC} · Fully local · No internet\n"
printf "      ${DIM}ollama.ai${NC}\n\n"
printf "  ${DIM}[7]  Skip — configure later${NC}\n\n"

CHOICE=""
while true; do
    prompt "Enter choice [1-7]: "
    CHOICE="$(_prompt "" "1")"
    case "$CHOICE" in
        1|2|3|4|5|6|7) break ;;
        *) print_warn "Invalid choice. Please enter 1-7." ;;
    esac
done

test_api_key() {
    local provider="$1"
    local url="$2"
    local auth_header="$3"
    local key="$4"

    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $key" \
        "$url" 2>/dev/null || echo "000")

    if [ "$HTTP_CODE" = "200" ]; then
        return 0
    else
        return 1
    fi
}

case "$CHOICE" in
    1)
        printf "\n"
        prompt "Enter your Groq API key: "
        read -rs GROQ_KEY || GROQ_KEY=""
        printf "\n"
        if [ -n "$GROQ_KEY" ]; then
            print_info "Testing Groq API key..."
            if test_api_key "groq" "https://api.groq.com/openai/v1/models" "Bearer $GROQ_KEY" "$GROQ_KEY"; then
                env_update "GROQ_API_KEY" "$GROQ_KEY"
                print_ok "Groq API key valid"
            else
                print_warn "Key test failed (HTTP $HTTP_CODE)"
                response="$(wait_for_key "Save anyway" "N")"
                if [ "$response" = "Y" ] || [ "$response" = "y" ]; then
                    env_update "GROQ_API_KEY" "$GROQ_KEY"
                    print_info "Saved (untested)"
                else
                    print_info "Key discarded"
                fi
            fi
        fi
        ;;
    2)
        printf "\n"
        prompt "Enter your OpenRouter API key: "
        read -rs OPENROUTER_KEY || OPENROUTER_KEY=""
        printf "\n"
        if [ -n "$OPENROUTER_KEY" ]; then
            print_info "Testing OpenRouter API key..."
            if test_api_key "openrouter" "https://openrouter.ai/api/v1/models" "Bearer $OPENROUTER_KEY" "$OPENROUTER_KEY"; then
                env_update "OPENROUTER_API_KEY" "$OPENROUTER_KEY"
                print_ok "OpenRouter API key valid"
            else
                print_warn "Key test failed (HTTP $HTTP_CODE)"
                response="$(wait_for_key "Save anyway" "N")"
                if [ "$response" = "Y" ] || [ "$response" = "y" ]; then
                    env_update "OPENROUTER_API_KEY" "$OPENROUTER_KEY"
                    print_info "Saved (untested)"
                else
                    print_info "Key discarded"
                fi
            fi
        fi
        ;;
    3)
        printf "\n"
        prompt "Enter your Anthropic API key: "
        read -rs ANTHROPIC_KEY || ANTHROPIC_KEY=""
        printf "\n"
        if [ -n "$ANTHROPIC_KEY" ]; then
            print_info "Testing Anthropic API key..."
            if test_api_key "anthropic" "https://api.anthropic.com/v1/models" "Bearer $ANTHROPIC_KEY" "$ANTHROPIC_KEY"; then
                env_update "ANTHROPIC_API_KEY" "$ANTHROPIC_KEY"
                print_ok "Anthropic API key valid"
            else
                print_warn "Key test failed (HTTP $HTTP_CODE)"
                response="$(wait_for_key "Save anyway" "N")"
                if [ "$response" = "Y" ] || [ "$response" = "y" ]; then
                    env_update "ANTHROPIC_API_KEY" "$ANTHROPIC_KEY"
                    print_info "Saved (untested)"
                else
                    print_info "Key discarded"
                fi
            fi
        fi
        ;;
    4)
        printf "\n"
        prompt "Enter your OpenAI API key: "
        read -rs OPENAI_KEY || OPENAI_KEY=""
        printf "\n"
        if [ -n "$OPENAI_KEY" ]; then
            print_info "Testing OpenAI API key..."
            if test_api_key "openai" "https://api.openai.com/v1/models" "Bearer $OPENAI_KEY" "$OPENAI_KEY"; then
                env_update "OPENAI_API_KEY" "$OPENAI_KEY"
                print_ok "OpenAI API key valid"
            else
                print_warn "Key test failed (HTTP $HTTP_CODE)"
                response="$(wait_for_key "Save anyway" "N")"
                if [ "$response" = "Y" ] || [ "$response" = "y" ]; then
                    env_update "OPENAI_API_KEY" "$OPENAI_KEY"
                    print_info "Saved (untested)"
                else
                    print_info "Key discarded"
                fi
            fi
        fi
        ;;
    5)
        printf "\n"
        prompt "Enter your Google AI API key: "
        read -rs GOOGLE_KEY || GOOGLE_KEY=""
        printf "\n"
        if [ -n "$GOOGLE_KEY" ]; then
            print_info "Testing Google AI API key..."
            HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
                -H "Authorization: Bearer $GOOGLE_KEY" \
                "https://generativelanguage.googleapis.com/v1/models" 2>/dev/null || echo "000")
            if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "403" ]; then
                env_update "GOOGLE_API_KEY" "$GOOGLE_KEY"
                if [ "$HTTP_CODE" = "200" ]; then
                    print_ok "Google AI API key valid"
                else
                    print_ok "Google AI API key saved (403 = valid key, quota issue)"
                fi
            else
                print_warn "Key test failed (HTTP $HTTP_CODE)"
                response="$(wait_for_key "Save anyway" "N")"
                if [ "$response" = "Y" ] || [ "$response" = "y" ]; then
                    env_update "GOOGLE_API_KEY" "$GOOGLE_KEY"
                    print_info "Saved (untested)"
                else
                    print_info "Key discarded"
                fi
            fi
        fi
        ;;
    6)
        print_info "Checking for Ollama..."
        OLLAMA_RESPONSE=$(curl -s --max-time 5 http://127.0.0.1:11434/api/tags 2>/dev/null || echo "")
        if [ -n "$OLLAMA_RESPONSE" ] && echo "$OLLAMA_RESPONSE" | grep -q "models"; then
            print_ok "Ollama is running"
            printf "\n"
            print_info "Available models:"
            echo "$OLLAMA_RESPONSE" | ${PY_CMD:-python3} -c "
import sys, json
try:
    data = json.load(sys.stdin)
    models = data.get('models', [])
    if models:
        for m in models:
            name = m.get('name', 'unknown')
            size = m.get('size', 0)
            if size > 0:
                size_gb = size / (1024**3)
                print(f'  - {name} ({size_gb:.1f} GB)')
            else:
                print(f'  - {name}')
    else:
        print('  (no models found)')
except:
    print('  (could not parse model list)')
" 2>/dev/null || echo "  (could not list models)"
            printf "\n"
            env_update "OLLAMA_BASE_URL" "http://127.0.0.1:11434"
            print_ok "Ollama configured"
        else
            print_warn "Ollama is not running."
            printf "\n"
            print_info "To use Ollama:"
            printf "    ${DIM}1. Install: https://ollama.ai${NC}\n"
            printf "    ${DIM}2. Run: ollama serve${NC}\n"
            printf "    ${DIM}3. Pull a model: ollama pull llama3.2${NC}\n"
            printf "    ${DIM}4. Re-run setup.sh${NC}\n"
            printf "\n"
            env_append "# OLLAMA_BASE_URL=http://127.0.0.1:11434"
            print_info "Skipped for now (uncomment in .env after installing Ollama)"
        fi
        ;;
    7)
        env_append "# LLM provider: skipped — configure manually in .env"
        print_info "Skipped — configure your LLM provider manually in .env"
        ;;
esac

# =============================================================================
# STEP 5: Optional Enrichment Keys
# =============================================================================
print_step "5" "Enrichment Keys"

print_info "Threat intelligence enrichment keys"
print_info "Press Enter to skip any"
printf "\n"

prompt "AlienVault OTX API key (https://otx.alienvault.com): "
read -rs OTX_KEY || OTX_KEY=""
printf "\n"
if [ -n "$OTX_KEY" ]; then
    print_info "Testing OTX API key..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "X-OTX-API-KEY: $OTX_KEY" \
        "https://otx.alienvault.com/api/v1/user/me" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
        env_update "OTX_API_KEY" "$OTX_KEY"
        print_ok "OTX API key valid"
    else
        print_warn "Key test failed (HTTP $HTTP_CODE)"
        response="$(wait_for_key "Save anyway" "N")"
        if [ "$response" = "Y" ] || [ "$response" = "y" ]; then
            env_update "OTX_API_KEY" "$OTX_KEY"
            print_info "Saved (untested)"
        else
            print_info "Key discarded"
        fi
    fi
fi

printf "\n"
prompt "VirusTotal API key (https://virustotal.com): "
read -rs VT_KEY || VT_KEY=""
printf "\n"
if [ -n "$VT_KEY" ]; then
    print_info "Testing VirusTotal API key..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "x-apikey: $VT_KEY" \
        "https://www.virustotal.com/api/v3/users/me" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
        env_update "VT_API_KEY" "$VT_KEY"
        print_ok "VirusTotal API key valid"
    else
        print_warn "Key test failed (HTTP $HTTP_CODE)"
        response="$(wait_for_key "Save anyway" "N")"
        if [ "$response" = "Y" ] || [ "$response" = "y" ]; then
            env_update "VT_API_KEY" "$VT_KEY"
            print_info "Saved (untested)"
        else
            print_info "Key discarded"
        fi
    fi
fi

# =============================================================================
# STEP 6: Redis Configuration
# =============================================================================
print_step "6" "Redis"

printf "  ${DIM}→${NC}  Redis enables JWT token "
printf "revocation and circuit breaker state.\n"
printf "  ${DIM}→${NC}  Recommended for production. "
printf "Skip for local / dev use.\n\n"
printf "  ${CYAN}▸${NC}  Enable Redis? [y/${BOLD}N${NC}]: "
read -r redis_ans </dev/tty || redis_ans="n"
redis_ans="${redis_ans:-n}"

if [[ "${redis_ans,,}" == "y" ]]; then
    printf "  ${CYAN}▸${NC}  Redis URL "
    printf "[redis://localhost:6379/0]: "
    read -r redis_url </dev/tty || redis_url=""
    redis_url="${redis_url:-redis://localhost:6379/0}"
    grep -q "^REDIS_URL=" .env 2>/dev/null && \
        sed -i "s|^REDIS_URL=.*|REDIS_URL=$redis_url|" \
        .env || echo "REDIS_URL=$redis_url" >> .env
    printf "  ${GREEN}✓${NC}  Redis configured\n"
else
    printf "  ${DIM}→${NC}  Skipped\n"
fi

# =============================================================================
# STEP 7: Pre-seed MITRE ATT&CK Cache
# =============================================================================
print_step "7" "MITRE ATT&CK Cache"

printf "\n"
printf "  ${CYAN}▸${NC}  Download MITRE ATT&CK database "
printf "now? (~33MB) [${BOLD}Y${NC}/n]: "
read -r mitre_ans </dev/tty || mitre_ans="y"
mitre_ans="${mitre_ans:-y}"

if [[ "${mitre_ans,,}" != "n" ]]; then
    printf "  ${DIM}→${NC}  Downloading...\n"
    python3 -c "
import urllib.request, sys
try:
    urllib.request.urlretrieve(
        'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
        '/tmp/voidaccess_mitre_attack.json'
    )
    print('  \033[0;32m✓\033[0m  Download complete')
except Exception as e:
    print(f'  \033[1;33m⚠\033[0m  Download failed: {e}')
    print('  \033[2m→\033[0m  Will retry on first investigation')
" 2>/dev/null || \
    printf "  ${YELLOW}⚠${NC}  Download failed — will retry later\n"
else
    printf "  ${DIM}→${NC}  Skipped — will download on first use\n"
fi

# =============================================================================
# STEP 8: Start the Stack
# =============================================================================
print_step "8" "Start Stack"

printf "\n"
printf "  ${CYAN}▸${NC}  Start VoidAccess now? "
printf "[${BOLD}Y${NC}/n]: "
read -r start_ans </dev/tty || start_ans="y"
start_ans="${start_ans:-y}"

if [[ "${start_ans,,}" == "n" ]]; then
    printf "  ${DIM}→${NC}  Start later with: "
    printf "${BOLD}sudo bash start.sh${NC}\n"
else
    printf "\n  ${DIM}→${NC}  Building and starting "
    printf "(first run: 3-5 min)...\n\n"
    
    # Show docker output directly — 
    # no background process, no spinner
    # Users can see progress
    $COMPOSE_CMD up --build -d
    BUILD_EXIT=$?
    
    if [ $BUILD_EXIT -ne 0 ]; then
        printf "\n  ${RED}✗${NC}  Build failed.\n"
        printf "  ${DIM}→${NC}  Run manually to see "
        printf "full output:\n"
        printf "  ${DIM}   $COMPOSE_CMD up --build${NC}\n"
        exit 1
    fi
    
    printf "\n  ${DIM}→${NC}  Waiting for services...\n\n"
    
    # Poll services
    for SVC in postgres tor fastapi nextjs; do
        LABEL="$SVC"
        case $SVC in
            postgres) LABEL="PostgreSQL" ;;
            tor)      LABEL="Tor" ;;
            fastapi)  LABEL="FastAPI" ;;
            nextjs)   LABEL="Next.js" ;;
        esac
        
        for attempt in $(seq 1 40); do
            STATE=$(docker inspect \
                --format='{{.State.Status}}' \
                "voidaccess-${SVC}" 2>/dev/null \
                || echo "missing")
            HEALTH=$(docker inspect \
                --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
                "voidaccess-${SVC}" 2>/dev/null \
                || echo "none")
            
            if [ "$HEALTH" = "healthy" ] || \
               { [ "$STATE" = "running" ] && \
                 [ "$HEALTH" = "none" ]; }; then
                printf "  ${GREEN}✓${NC}  $LABEL\n"
                break
            fi
            
            if [ $attempt -eq 40 ]; then
                printf "  ${YELLOW}⚠${NC}  $LABEL slow to start\n"
            else
                printf "\r  ${CYAN}·${NC}  $LABEL (${attempt}/40)...   "
                sleep 3
            fi
        done
        printf "\r%-60s\r" " "
    done
fi

# =============================================================================
# STEP 9: Set Admin Password
# =============================================================================
print_step "9" "Admin Password"

printf "  The default admin account requires a password before first login.\n"
printf "\n"

ADMIN_EMAIL="admin@voidaccess.tech"
ADMIN_PASS=""

if [ -t 0 ]; then
    prompt "Admin email [admin@voidaccess.tech]: "
    read -r _email_input || _email_input=""
    ADMIN_EMAIL="${_email_input:-admin@voidaccess.tech}"

    while true; do
        prompt "Admin password (min 8 chars, letters + numbers): "
        read -rs ADMIN_PASS || ADMIN_PASS=""
        printf "\n"

        if [ ${#ADMIN_PASS} -lt 8 ]; then
            print_fail "Password too short (min 8 chars)"
            continue
        fi
        if ! echo "$ADMIN_PASS" | grep -qE '[a-zA-Z]' || \
           ! echo "$ADMIN_PASS" | grep -qE '[0-9]'; then
            print_fail "Must contain letters and numbers"
            continue
        fi

        prompt "Confirm password: "
        read -rs ADMIN_CONFIRM || ADMIN_CONFIRM=""
        printf "\n"

        if [ "$ADMIN_PASS" != "$ADMIN_CONFIRM" ]; then
            print_fail "Passwords don't match"
            continue
        fi
        break
    done
else
    print_warn "Non-interactive mode — skipping admin password setup."
    print_info "Log in and set your password via: Settings → Security → Change Password"
fi

if [ -n "$ADMIN_PASS" ]; then
    print_info "Setting admin password..."
    HASH=$($COMPOSE_CMD \
        exec -T fastapi \
        python3 -c "
from passlib.context import CryptContext
ctx = CryptContext(schemes=['bcrypt'])
print(ctx.hash('$ADMIN_PASS'))
" 2>/dev/null)

    if [ -n "$HASH" ]; then
        $COMPOSE_CMD \
            exec -T postgres psql \
            -U voidaccess -d voidaccess -c \
            "UPDATE users SET
             hashed_password='$HASH',
             must_reset_password=false,
             email='$ADMIN_EMAIL'
             WHERE email='admin@voidaccess.tech'
             OR email='$ADMIN_EMAIL';" \
            2>/dev/null
        print_ok "Admin password set"
    else
        print_warn "Could not set password automatically"
        print_info "Log in and change it via Settings"
    fi
fi

# =============================================================================
# STEP 10: Complete
# =============================================================================
print_step "10" "Complete"

printf "\n${GREEN}"
printf "  ╔═══════════════════════════════════╗\n"
printf "  ║                                   ║\n"
printf "  ║   ✓  VoidAccess is ready          ║\n"
printf "  ║                                   ║\n"
printf "  ╠═══════════════════════════════════╣\n"
printf "  ║  UI   →  http://localhost:3001    ║\n"
printf "  ║  API  →  http://localhost:8000    ║\n"
printf "  ║                                   ║\n"
printf "  ╚═══════════════════════════════════╝\n"
printf "${NC}\n"
