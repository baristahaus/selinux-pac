# lab_env.sh — Load QA_HOST, PROD_HOST, and SSH_USER from lab/lab.env.
# Source this file. Call lab_env_load, then lab_env_require when a script
# is about to use the addresses. --help must exit before lab_env_require.

lab_env_file() {
    local here="${BASH_SOURCE[0]%/*}"
    local primary="${here}/../lab.env"
    if [[ -f "${primary}" ]]; then
        printf '%s\n' "${primary}"
        return
    fi
    # Fallback: scripts/lab.env (pre-reorg location)
    local legacy="${here}/../../scripts/lab.env"
    if [[ -f "${legacy}" ]]; then
        echo "Move scripts/lab.env to lab/lab.env" >&2
        printf '%s\n' "${legacy}"
        return
    fi
    printf '%s\n' "${primary}"
}

lab_env_set_if_empty() {
    local key="$1" value="$2"
    if [[ -z "${!key:-}" ]]; then
        printf -v "${key}" '%s' "${value}"
    fi
}

lab_env_load() {
    local file line key value
    file="$(lab_env_file)"
    if [[ -f "${file}" ]]; then
        while IFS= read -r line || [[ -n "${line}" ]]; do
            line="${line%%#*}"
            line="${line#"${line%%[![:space:]]*}"}"
            line="${line%"${line##*[![:space:]]}"}"
            [[ -n "${line}" && "${line}" == *=* ]] || continue
            key="${line%%=*}"
            value="${line#*=}"
            value="${value%\"}"
            value="${value#\"}"
            value="${value%\'}"
            value="${value#\'}"
            case "${key}" in
                QA_HOST|PROD_HOST|SSH_USER|DEV_HOST|REPO_HOST) lab_env_set_if_empty "${key}" "${value}" ;;
            esac
        done <"${file}"
    fi
    if [[ -n "${DEV_HOST:-}" && -z "${QA_HOST:-}" ]]; then
        QA_HOST="${DEV_HOST}"
    fi
    if [[ -n "${QA_HOST:-}" && -z "${DEV_HOST:-}" ]]; then
        DEV_HOST="${QA_HOST}"
    fi
    if [[ -n "${ANSIBLE_SSH_USER:-}" && -z "${SSH_USER:-}" ]]; then
        SSH_USER="${ANSIBLE_SSH_USER}"
    fi
    if [[ -n "${SSH_USER:-}" ]]; then
        ANSIBLE_SSH_USER="${SSH_USER}"
        E2E_SSH_USER="${SSH_USER}"
    fi
    : "${QA_HOST:=}"
    : "${PROD_HOST:=}"
    : "${DEV_HOST:=}"
    : "${SSH_USER:=}"
    : "${E2E_SSH_USER:=}"
    : "${ANSIBLE_SSH_USER:=}"
    : "${REPO_HOST:=}"
}

lab_env_require() {
    lab_env_load
    local missing=()
    [[ -n "${QA_HOST:-}" ]] || missing+=(QA_HOST)
    [[ -n "${PROD_HOST:-}" ]] || missing+=(PROD_HOST)
    [[ -n "${SSH_USER:-}" ]] || missing+=(SSH_USER)
    if [[ "${#missing[@]}" -gt 0 ]]; then
        echo "Set ${missing[*]}, or copy lab/lab.env.example to lab/lab.env." >&2
        exit 2
    fi
    if [[ -z "${DEV_HOST:-}" ]]; then
        DEV_HOST="${QA_HOST}"
    fi
    E2E_SSH_USER="${SSH_USER}"
    ANSIBLE_SSH_USER="${SSH_USER}"
}
