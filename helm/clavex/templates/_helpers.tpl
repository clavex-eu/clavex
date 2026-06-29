{{/*
Expand the name of the chart.
*/}}
{{- define "clavex.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "clavex.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart label value.
*/}}
{{- define "clavex.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "clavex.labels" -}}
helm.sh/chart: {{ include "clavex.chart" . }}
{{ include "clavex.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "clavex.selectorLabels" -}}
app.kubernetes.io/name: {{ include "clavex.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service account name.
*/}}
{{- define "clavex.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "clavex.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
GeoIP PVC claim name — honour an externally-provided claim, else the managed one.
*/}}
{{- define "clavex.geoip.claimName" -}}
{{- if .Values.geoip.pvc.existingClaim }}
{{- .Values.geoip.pvc.existingClaim }}
{{- else }}
{{- printf "%s-geoip-data" (include "clavex.fullname" .) }}
{{- end }}
{{- end }}

{{/*
GeoIP MaxMind credential env entries (account id + license key from licenseSecret).
*/}}
{{- define "clavex.geoip.credsEnv" -}}
- name: MAXMIND_ACCOUNT_ID
  valueFrom:
    secretKeyRef:
      name: {{ .Values.geoip.autoUpdate.licenseSecret | quote }}
      key: MAXMIND_ACCOUNT_ID
- name: MAXMIND_LICENSE_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .Values.geoip.autoUpdate.licenseSecret | quote }}
      key: MAXMIND_LICENSE_KEY
{{- end }}

{{/*
GeoIP download shell snippet. Downloads each DB in $DATABASES from MaxMind into
$MMDB_DIR using an atomic temp-then-rename. Honours $FORCE (0 = skip when all
files already present) and $BEST_EFFORT (1 = exit 0 instead of failing, so geo
stays optional and never blocks pod startup).
*/}}
{{- define "clavex.geoip.downloadSnippet" -}}
mkdir -p "${MMDB_DIR}"

fail() { if [ "${BEST_EFFORT:-0}" = "1" ]; then echo "[geoip] $1 — continuing without geo" >&2; exit 0; else echo "[geoip] ERROR: $1" >&2; exit 1; fi; }

if [ "${FORCE:-0}" != "1" ]; then
  present=1
  for DB in ${DATABASES}; do [ -f "${MMDB_DIR}/${DB}.mmdb" ] || present=0; done
  if [ "${present}" = "1" ]; then echo "[geoip] mmdb already present, skipping download"; exit 0; fi
fi

for DB in ${DATABASES}; do
  echo "[geoip] Downloading ${DB}..."
  curl -fsSL --retry 3 \
    --user "${MAXMIND_ACCOUNT_ID}:${MAXMIND_LICENSE_KEY}" \
    "https://download.maxmind.com/geoip/databases/${DB}/download?suffix=tar.gz" \
    -o "/tmp/${DB}.tar.gz" || fail "download ${DB} failed"

  tar -xzf "/tmp/${DB}.tar.gz" -C /tmp || fail "extract ${DB} failed"
  MMDB=$(find /tmp -name "${DB}.mmdb" 2>/dev/null | head -1)
  [ -n "${MMDB}" ] || fail "${DB}.mmdb not found in archive"

  # atomic replace so readers never see a half-written file
  mv "${MMDB}" "${MMDB_DIR}/${DB}.mmdb.tmp"
  mv -f "${MMDB_DIR}/${DB}.mmdb.tmp" "${MMDB_DIR}/${DB}.mmdb"
  rm -f "/tmp/${DB}.tar.gz"
  find /tmp -maxdepth 1 -name "${DB}_*" -type d -exec rm -rf {} + 2>/dev/null || true
  echo "[geoip] ${DB}.mmdb ready ($(du -sh "${MMDB_DIR}/${DB}.mmdb" | cut -f1))"
done
{{- end }}
