/*
  Copyright © 2018 Booz Allen Hamilton. All Rights Reserved.
  This software package is licensed under the Booz Allen Public License. The license can be found in the License file or at http://boozallen.github.io/licenses/bapl
*/
import groovy.json.*

void call(){
  stage("Scanning Container Image: Anchore Scan"){
    node{
        String anchore_engine_base_url = config.anchore_engine_url ?: null
        withCredentials([usernamePassword(credentialsId: config.cred, passwordVariable: 'pass', usernameVariable: 'user')]) {
                String url = "${anchore_engine_base_url}/system/"
		sh "echo curl -u '${user}:${pass}' ${url}"
		sh "curl -u '${user}:${pass}' ${url}"

                def images = get_images_to_build()
                images.each{ img ->
		  url = "${anchore_engine_base_url}/images"
		  def new_image = [tag: "${img.registry}/${img.repo}:${img.tag}"]
		  def new_image_json = JsonOutput.toJson(new_image)
		  sh "echo curl -u -H 'content-type: application/json' -X POST '${user}:${pass}' ${url} -d '${new_image_json}'"
                  //sh "docker build ${img.context} -t ${img.registry}/${img.repo}:${img.tag}"
                  //sh "docker push ${img.registry}/${img.repo}:${img.tag}"
                }
	}  	 
      }
    }
  }