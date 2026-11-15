{{- define "caphe.name" -}}caphe{{- end -}}
{{- define "caphe.labels" -}}
app.kubernetes.io/name: {{ include "caphe.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
