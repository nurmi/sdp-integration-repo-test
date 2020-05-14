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
  def ret_image = null
  String url
  String image_digest
  def input_image = [tag: "${img.registry}/${img.repo}:${img.tag}"]
  def input_image_json = JsonOutput.toJson(input_image)

  try {
    url = "${anchore_engine_base_url}/images"
    http_result = "new_anchore_image.json"
    sh "curl -u '${user}':'${pass}' -H 'content-type: application/json' -X POST -o ${http_result} ${url} -d '${input_image_json}'"
    def new_image = this.parse_json(http_result)[0]
    image_digest = new_image.imageDigest
  } catch (any) {
    println ("Unable to add image to Anchore Engine - exception ${any}")
    throw any
  }
  

try {
  url = "${anchore_engine_base_url}/images/${image_digest}"
  timeout(time: anchore_image_wait_timeout, unit: 'SECONDS') {
    while(!done) {
      try {
        http_result = "new_anchore_image_check.json"
        sh "curl -u '${user}':'${pass}' -H 'content-type: application/json' -X GET -o ${http_result} ${url}"
        def new_image_check = this.parse_json(http_result)[0]
        if (new_image_check.analysis_status == "analyzed") {
          done = true
          success = true
          ret_image = new_image_check
        } else if ( new_image_check.analysis_status == "analysis_failed") {
          done = true
          success = false
        } else {
          println("image not yet analyzed - status is ${new_image_check.analysis_status}")
          sleep 5
        }
      } catch (any) {
        success = false
	done = true
	throw any
      } 
    }
  }
 } catch (any) {
   println("ERRO")
 }
 return [success, ret_image]
}

def get_image_vulnerabilities(config, user, pass, image) {
  String anchore_engine_base_url = config.anchore_engine_url
  Boolean success = false
  def vulnerabilities = null
  ArrayList ret_vulnerabilities = null
  String url = null
  
  try {
    http_result = "anchore_results/anchore_vulnerabilities.json"
    url = "${anchore_engine_base_url}/images/${image.imageDigest}/vuln/all?vendor_only=True"
    sh "curl -u '${user}':'${pass}' -H 'content-type: application/json' -o ${http_result} ${url}"

    vulnerabilities = this.parse_json("anchore_result_vulnerabilities.json")
  } catch (any) {
    throw any
  }
  if (vulnerabilities) {
    success = true
    ret_vulnerabilities = vulnerabilities.vulnerabilities
  }
  return [success, ret_vulnerabilities]
}

def initialize_workspace(config) {
  sh "mkdir -p anchore_results"
  return(true)
}

void call(){

  if (!config.anchore_engine_url) {
    error "The anchore_engine_url parameter must be set in the library configuration."
  } else if (!config.cred) {
    error "Credentials for accessing Anchore Engine must be set in the library configuration."
  }

  stage("Scanning Container Image: Anchore Scan"){
    node{
           try {
              withCredentials([usernamePassword(credentialsId: config.cred, passwordVariable: 'pass', usernameVariable: 'user')]) {
                def images = get_images_to_build()
		def archive_only = config.archive_only ?: false

		this.initialize_workspace(config)

                images.each { img ->
		  (success, new_image) = this.add_image(config, user, pass, img)
		  if (success) {
		    println("Image analysis successful")
		  } else {
		    error "Failed to add image to Anchore Engine for analysis"
		  }

		  (success, vulnerabilities) = this.get_image_vulnerabilities(config, user, pass, new_image)
		  if (success) {
		    println("Image vulnerabilities report generation complete")
		    vulnerability_result = "Anchore Image Scan Vulnerability Results\n*****\n"
		    if (vulnerabilities) {
		      vulnerabilities.each { vuln ->
		        vulnerability_result += "${vuln.vuln} ${vuln.severity} ${vuln.package_name} ${vuln.package_version} ${vuln.package_type}\n"
		      }
		    } else {
		      vulnerability_result += "No vulnerabilities detected\n"
		    }

                    if (!archive_only) {
		        println(vulnerability_result)
                    }
		    
		  } else {
		    error "Failed to retrieve vulnerability results from Anchore Engine from analyzed image"
		  }
                }
		
	  }
  	} catch (any) {
	  throw any
	} finally {
	  archiveArtifacts allowEmptyArchive: true, artifacts: 'anchore_results/'
	}
      }
    }
  }