/*
  Copyright © 2018 Booz Allen Hamilton. All Rights Reserved.
  This software package is licensed under the Booz Allen Public License. The license can be found in the License file or at http://boozallen.github.io/licenses/bapl
*/
import groovy.json.*

def parse_json(input_file) {
    return readJSON(file: "${input_file}")
}

def add_image(config, user, pass, img) {
    		  String anchore_engine_base_url = config.anchore_engine_url
		  int anchore_image_wait_timeout = config.image_wait_timeout ?: 300
                  Boolean done = false
		  Boolean success = false
		  
		  
                  url = "${anchore_engine_base_url}/images"
		  def input_image = [tag: "${img.registry}/${img.repo}:${img.tag}"]
		  def input_image_json = JsonOutput.toJson(input_image)
		  sh "echo curl -u '${user}':'${pass}' -H 'content-type: application/json' -X POST ${url} -d '${input_image_json}'"		  
		  sh "curl -u '${user}':'${pass}' -H 'content-type: application/json' -X POST ${url} -d '${input_image_json}' > new_image.json"
		  def new_image = this.parse_json("new_image.json")[0]
		  def ret_image = null
 		  url = "${anchore_engine_base_url}/images/${new_image.imageDigest}"		  
		  timeout(time: anchore_image_wait_timeout, unit: 'SECONDS') {
  		    while(!done) {
		      sh "curl -u '${user}':'${pass}' -H 'content-type: application/json' -X GET ${url} > new_image_check.json"
		      def new_image_check = this.parse_json("new_image_check.json")[0]
		      sh "echo ${new_image_check.analysis_status}"
		      if (new_image_check.analysis_status == "analyzed") {
		        done = true
			success = true
			ret_image = new_image_check
		      } else if ( new_image_check.analysis_status == "analysis_failed") {
		        done = true
			success = false
		      } else {
		        sh "echo image not yet analyzed - status is ${new_image_check.analysis_status}"
			sleep 5
		      }
		    }
		  }
  return [success, ret_image]
}

def get_image_vulnerabilities(config, user, pass, image) {
  String anchore_engine_base_url = config.anchore_engine_url
  success = false
  vulnerabilities = ret_vulnerabilities = null
  try {
    url = "${anchore_engine_base_url}/images/${image.imageDigest}/vuln/all?vendor_only=True"
    sh "curl -u '${user}':'${pass}' -H 'content-type: application/json' ${url} > anchore_result_vulnerabilities.json"
    archiveArtifacts 'anchore_result_vulnerabilities.json'
    vulnerabilities = this.parse_json("anchore_result_vulnerabilities.json")
  } catch (any) {
    throw any
  }
  if (vulnerabilities && vulnerabilities.vulnerabilities) {
    success = true
    ret_vulnerabilities = vulnerabilities.vulnerabilities
  }
  return [success, ret_vulnerabilities]
}
void call(){
  stage("Scanning Container Image: Anchore Scan"){
    node{
        //String anchore_engine_base_url = config.anchore_engine_url ?: null
	//int anchore_image_wait_timeout = config.image_wait_timeout ?: 300
        withCredentials([usernamePassword(credentialsId: config.cred, passwordVariable: 'pass', usernameVariable: 'user')]) {
                //String url = "${anchore_engine_base_url}/system/"
		//sh "echo curl -u '${user}:${pass}' ${url}"
		//sh "curl -u '${user}:${pass}' ${url}"

                def images = get_images_to_build()
                images.each{ img ->
		  (success, new_image) = this.add_image(config, user, pass, img)
		  if (success) {
		    println("Image analysis successful")
		    //println("${new_image}")
		  }

		  (success, vulnerabilities) = this.get_image_vulnerabilities(config, user, pass, new_image)
		  if (success) {
		    println("Image vulnerabilities report generated")
		    //println("${vulnerabilities}")
		    vulnerabilities.each {
		      println("${it.vuln} ${it.severity} ${it.package_name} ${it.package_version} ${it.package_type}")
		  }
                }
	}  	 
      }
    }
  }