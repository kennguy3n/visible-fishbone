{{/*
Expand the name of the chart.
*/}}
{{- define "sng-edge.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name.
*/}}
{{- define "sng-edge.fullname" -}}
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

{{- define "sng-edge.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "sng-edge.labels" -}}
helm.sh/chart: {{ include "sng-edge.chart" . }}
{{ include "sng-edge.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: edge
{{- end -}}

{{- define "sng-edge.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sng-edge.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "sng-edge.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "sng-edge.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Image reference; tag falls back to the chart appVersion.
*/}}
{{- define "sng-edge.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{- define "sng-edge.configMapName" -}}
{{- printf "%s-config" (include "sng-edge.fullname" .) -}}
{{- end -}}

{{- define "sng-edge.envoyConfigMapName" -}}
{{- printf "%s-envoy" (include "sng-edge.fullname" .) -}}
{{- end -}}
