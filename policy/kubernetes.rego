package main

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.runAsUser == 0
  msg := sprintf("Le conteneur '%s' ne doit pas s'exécuter en root.", [container.name])
}