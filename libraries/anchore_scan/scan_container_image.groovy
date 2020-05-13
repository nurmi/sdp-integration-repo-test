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
		  def input_image = [tag: "${img.registry}/${img.repo}:${img.tag}"]
		  def input_image_json = JsonOutput.toJson(new_image)
		  sh "echo curl -u '${user}':'${pass}' -H 'content-type: application/json' -X POST ${url} -d '${input_image_json}'"		  
		  sh "curl -u '${user}':'${pass}' -H 'content-type: application/json' -X POST ${url} -d '${input_image_json}' > new_image.json"
		  def new_image = readJSON(file: "new_image.json")

		  Boolean done = false
 		  url = "${anchore_engine_base_url}/images/${new_image.imageDigest}"		  
		  while(!done) {
		    sh "curl -u '${user}':'${pass}' -H 'content-type: application/json' -X GET ${url} > new_image_check.json"
		    def new_image_check = readJSON(file: "new_image_check.json")
		    sh "echo ${new_image_check.analysis_status}"
		    if (new_image_check.analysis_status == "analyzed") {
		      done = true
		    } else {
		      attempts++
		      if (attempts > 10) {
		        done = true
	              }
		    }
		  }  
                }
	}  	 
      }
    }
  }