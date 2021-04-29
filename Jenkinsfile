podTemplate(yaml: """
apiVersion: v1
kind: Pod
metadata:
  labels:
    some-label: some-label-value
spec:
  securityContext:
   fsGroup: 2000
  containers:
  - name: docker
    image: artifactory.legalzoom.com/docker-remote/docker:dind
    tty: true
    securityContext:
      privileged: true
      seLinuxOptions:
        user: system_u
        role: system_r
        type: container_t
        level: s0
    env:
    - name: DOCKER_TLS_CERTDIR
      value: /certs
    ports:
    - containerPort: 2376
    volumeMounts:
    - name: shared-data
      mountPath: /certs
    - name: tmp
      mountPath: /tmp
  - name: jnlp
    image: artifactory.legalzoom.com/docker/devops/jenkins-inbound-agent-arm:latest
  volumes:
  - name: shared-data
    emptyDir: {}
  - name: tmp
    emptyDir: {}
  nodeSelector:
    kubernetes.io/os: linux
    kubernetes.io/arch: arm64
  tolerations:
  - key: "namespace"
    value: "jenkins-agents"
    operator: "Equal"
    effect: "NoSchedule"
""",
workspaceVolume: dynamicPVC(accessModes: 'ReadWriteOnce', requestsSize: "30Gi")
) {
    node(POD_LABEL) {
        final scmVars = checkout scm
        def gitCommit = scmVars.GIT_COMMIT
        stage('Docker Build & Publish') {
            stage('build') {
                container('docker') {
                    ansiColor('xterm') {
                      sh """
                      docker build -t artifactory.legalzoom.com/docker/devops/aws-cert-importer:${gitCommit} .
                      """
                    }
                }
            }
            stage('publish') {
                container('docker') {
                    withCredentials([
                                        usernamePassword(
                                            credentialsId: 'Artifactory',
                                            passwordVariable: 'PASSWORD',
                                            usernameVariable: 'USER'
                                        )
                                    ]) {
                        sh """
                        docker login artifactory.legalzoom.com -u ${USER} -p ${PASSWORD}
                        docker push artifactory.legalzoom.com/docker/devops/aws-cert-importer:${gitCommit}
                        docker tag artifactory.legalzoom.com/docker/devops/aws-cert-importer:${gitCommit} artifactory.legalzoom.com/docker/devops/aws-cert-importer:latest
                        docker push artifactory.legalzoom.com/docker/devops/aws-cert-importer:latest
                        """
                    }
                }
            }
        }
    }
}
