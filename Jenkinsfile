pipeline {
  agent none

  stages {
    stage('Generate bundle') {
      agent {
        dockerfile { filename 'Dockerfile' }
      }
      steps {
        script {
          sh './anchore-bundle generate'
        }
      }
    }

    stage('Upload bundle') {
      agent {
        docker {
          image 'anchore/engine-cli:latest'
          args '--network quickstart_default -e ANCHORE_CLI_URL="http://api:8228/v1/"'
        }
      }
      steps {
        script {
          sh 'anchore-cli policy add bundle.json && anchore-cli policy activate $(cat bundle_id)'
        }
      }
    }

  }
}
