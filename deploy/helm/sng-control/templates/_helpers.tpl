{{/* Expand the name of the chart. */}}
{{- define "sng-control.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified app name. */}}
{{- define "sng-control.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "sng-control.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "sng-control.labels" -}}
helm.sh/chart: {{ include "sng-control.chart" . }}
{{ include "sng-control.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "sng-control.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sng-control.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "sng-control.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "sng-control.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "sng-control.configMapName" -}}
{{- printf "%s-config" (include "sng-control.fullname" .) -}}
{{- end -}}

{{- define "sng-control.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secret" (include "sng-control.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
The image reference, defaulting the tag to the chart appVersion.
*/}}
{{- define "sng-control.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/*
Effective PG_PGBOUNCER_MODE: forced "true" when the PgBouncer sidecar is
enabled, otherwise the configured value. Keeps the runtime flag and the
sidecar from drifting apart.
*/}}
{{- define "sng-control.pgbouncerMode" -}}
{{- if .Values.pgbouncer.enabled -}}true{{- else -}}{{ default "false" .Values.config.PG_PGBOUNCER_MODE }}{{- end -}}
{{- end -}}

{{/*
Effective PG_HOST as seen by the app: the local PgBouncer when the
sidecar is enabled, otherwise the configured upstream host.
*/}}
{{- define "sng-control.pgHost" -}}
{{- if .Values.pgbouncer.enabled -}}127.0.0.1{{- else -}}{{ .Values.config.PG_HOST }}{{- end -}}
{{- end -}}

{{- define "sng-control.pgPort" -}}
{{- if .Values.pgbouncer.enabled -}}{{ .Values.pgbouncer.port }}{{- else -}}{{ .Values.config.PG_PORT }}{{- end -}}
{{- end -}}
