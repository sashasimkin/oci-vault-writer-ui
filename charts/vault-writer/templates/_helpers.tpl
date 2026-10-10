{{- define "vault-writer.name" -}}
vault-writer
{{- end }}
{{- define "vault-writer.labels" -}}
app.kubernetes.io/name: {{ include "vault-writer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- end }}
