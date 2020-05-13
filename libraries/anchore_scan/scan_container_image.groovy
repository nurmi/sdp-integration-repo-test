/*
  Copyright © 2018 Booz Allen Hamilton. All Rights Reserved.
  This software package is licensed under the Booz Allen Public License. The license can be found in the License file or at http://boozallen.github.io/licenses/bapl
*/


void call(){
  stage("Scanning Container Image: Anchore Scan"){
    node{
        String anchore_engine_base_url = config.anchore_engine_url ?: null
        withCredentials([usernamePassword(credentialsId: config.cred, passwordVariable: 'pass', usernameVariable: 'user')]) {
                String url = "${anchore_engine_base_url}/system/"
		sh "echo curl -u '${user}:${pass}' ${url}"
		sh "curl -u '${user}:${pass}' ${url}"		
	}  	 
      }
    }
  }