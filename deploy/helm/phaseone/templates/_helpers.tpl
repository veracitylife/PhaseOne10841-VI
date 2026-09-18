{{/*
PhaseOne10841 Helm helpers — Veracity Integrity LLC
*/}}

{{- define "phaseone.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "phaseone.fullname" -}}
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

{{- define "phaseone.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "phaseone.labels" -}}
helm.sh/chart: {{ include "phaseone.chart" . }}
{{ include "phaseone.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: phaseone10841
app.kubernetes.io/component: defensive-agent-gateway
vendor: Veracity Integrity LLC
{{- end -}}

{{- define "phaseone.selectorLabels" -}}
app.kubernetes.io/name: {{ include "phaseone.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "phaseone.gatewaySelectorLabels" -}}
{{ include "phaseone.selectorLabels" . }}
app.kubernetes.io/component: gateway
{{- end -}}

{{- define "phaseone.dashboardSelectorLabels" -}}
{{ include "phaseone.selectorLabels" . }}
app.kubernetes.io/component: dashboard
{{- end -}}

{{- define "phaseone.postgresSelectorLabels" -}}
{{ include "phaseone.selectorLabels" . }}
app.kubernetes.io/component: postgres
{{- end -}}

{{- define "phaseone.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "phaseone.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "phaseone.secretName" -}}
{{- if .Values.existingSecret.name -}}
{{- .Values.existingSecret.name -}}
{{- else -}}
{{- printf "%s-secrets" (include "phaseone.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "phaseone.configMapName" -}}
{{- printf "%s-config" (include "phaseone.fullname" .) -}}
{{- end -}}

{{- define "phaseone.postgresSecretName" -}}
{{- if .Values.postgres.auth.existingSecret -}}
{{- .Values.postgres.auth.existingSecret -}}
{{- else -}}
{{- printf "%s-postgres" (include "phaseone.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "phaseone.databaseUrlSecretName" -}}
{{- if and (not .Values.postgres.enabled) .Values.database.externalUrlSecret.name -}}
{{- .Values.database.externalUrlSecret.name -}}
{{- else -}}
{{- include "phaseone.secretName" . -}}
{{- end -}}
{{- end -}}

{{- define "phaseone.databaseUrlSecretKey" -}}
{{- if and (not .Values.postgres.enabled) .Values.database.externalUrlSecret.name -}}
{{- .Values.database.externalUrlSecret.key -}}
{{- else -}}
DATABASE_URL
{{- end -}}
{{- end -}}

{{- define "phaseone.gatewayServiceName" -}}
{{- printf "%s-gateway" (include "phaseone.fullname" .) -}}
{{- end -}}

{{- define "phaseone.dashboardServiceName" -}}
{{- printf "%s-dashboard" (include "phaseone.fullname" .) -}}
{{- end -}}

{{- define "phaseone.postgresServiceName" -}}
{{- printf "%s-postgres" (include "phaseone.fullname" .) -}}
{{- end -}}

{{- define "phaseone.image" -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- end -}}

{{- define "phaseone.secretEnv" -}}
{{- range $key, $_ := .Values.secrets }}
{{- if ne $key "DATABASE_URL" }}
- name: {{ $key }}
  valueFrom:
    secretKeyRef:
      name: {{ include "phaseone.secretName" $ }}
      key: {{ $key }}
      optional: true
{{- end }}
{{- end }}
{{- end -}}
