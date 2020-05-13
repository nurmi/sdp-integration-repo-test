/*
  Copyright © 2018 Booz Allen Hamilton. All Rights Reserved.
  This software package is licensed under the Booz Allen Public License. The license can be found in the License file or at http://boozallen.github.io/licenses/bapl
*/
import groovy.json.*

def parse_json(input_file) {
    //return readJSON(file: "${input_file}")
    def ret = [analysis_status: "analyzed", imageDigest: 'sha256:a0e1f3334315165b1e75ee28d62f48b1623a8ad31ad3c9b99f964ed750cbd1ba']
    return (ret)
}

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
		  def input_image_json = JsonOutput.toJson(input_image)
		  sh "echo curl -u '${user}':'${pass}' -H 'content-type: application/json' -X POST ${url} -d '${input_image_json}'"		  
		  sh "curl -u '${user}':'${pass}' -H 'content-type: application/json' -X POST ${url} -d '${input_image_json}' > new_image.json"

		  def new_image = parse_json("new_image.json")
		  Boolean done = false
 		  url = "${anchore_engine_base_url}/images/${new_image.imageDigest}"		  
		  while(!done) {
		    sh "curl -u '${user}':'${pass}' -H 'content-type: application/json' -X GET ${url} > new_image_check.json"
		    def new_image_check = parse_json("new_image_check.json")
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