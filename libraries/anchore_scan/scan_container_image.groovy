/*
  Copyright © 2018 Booz Allen Hamilton. All Rights Reserved.
  This software package is licensed under the Booz Allen Public License. The license can be found in the License file or at http://boozallen.github.io/licenses/bapl
*/
import groovy.json.*

def parse_json(input_file) {
    return readJSON(file: "${input_file}")
}

def add_image(config, user, pass, input_image_fulltag) {
  String anchore_engine_base_url = config.anchore_engine_url
  int anchore_image_wait_timeout = config.image_wait_timeout ?: 300
  Boolean done = false
  Boolean success = false
  def ret_image = null
  String url
  String image_digest
  def input_image = [tag: "${input_image_fulltag}"]
  def input_image_json = JsonOutput.toJson(input_image)

  try {
    url = "${anchore_engine_base_url}/images"
    http_result = "new_anchore_image.json"
    sh "curl -u '${user}':'${pass}' -H 'content-type: application/json' -X POST --stderr curl.err -o ${http_result} '${url}' -d '${input_image_json}'"
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
        sh "curl -u '${user}':'${pass}' -H 'content-type: application/json' -X GET --stderr curl.err -o ${http_result} '${url}'"
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
   println("Timed out or error waiting for image to reach analyzed state")
   success = false
   ret_image = null
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
    url = "${anchore_engine_base_url}/images/${image.imageDigest}dd/vuln/all?vendor_only=True"
    sh "curl -u '${user}':'${pass}' -H 'content-type: application/json' -o ${http_result} '${url}' 2>curl.err"
    vulnerabilities = this.parse_json(http_result)
    ret_vulnerabilities = vulnerabilities["vulnerabilities"]
    success = true
  } catch (any) {
    if ( (new File(http_result)).exists()) {
      sh "mv ${http_result} anchore_results/last_error.response"
    }
    throw any
  } finally {
    if ( (new File("curl.err")).exists()) {
      sh "mv curl.err anchore_results/last_error.curl"
    }
  }
  return [success, ret_vulnerabilities]
}

def get_image_evaluations(config, user, pass, image, input_image_fulltag) {
  String anchore_engine_base_url = config.anchore_engine_url
  String anchore_policy_bundle_file = config.policy_bundle ?: null
  Boolean success = false
  def evaluations = null
  def ret_evaluations = null
  String url = null
  String policy_bundle_id = null
  def policy_bundle = null

  if (anchore_policy_bundle_file) {
    policy_bundle = readJSON(file: "${anchore_policy_bundle_file}")
    policy_bundle_id = policy_bundle.id
  }
  String image_digest = image.imageDigest
  String image_id = image.image_detail[0].imageId
  
  http_result = "anchore_results/anchore_policy_evaluations.json"
  try {
    url = "${anchore_engine_base_url}/images/${image_digest}/check?history=false&detail=true&tag=${input_image_fulltag}"
    sh "curl -u '${user}':'${pass}' -H 'content-type: application/json' --stderr curl.err -o ${http_result} '${url}'"
    evaluations = this.parse_json(http_result)
  } catch (any) {
    if ( (new File(http_result)).exists()) {
      sh "mv ${http_result} anchore_results/last_error.response"
    }
    throw any
  } finally {
    if ( (new File("curl.err")).exists()) {
      sh "mv curl.err anchore_results/last_error.curl"
    }
  }
  if (evaluations) {
    success = true
    ret_evaluations = evaluations[0]["${image_digest}"]["${input_image_fulltag}"]["detail"]["result"]["result"][0]["${image_id}"]["result"]
  }
  return [success, ret_evaluations]
}

def initialize_workspace(config) {
  if (!config.anchore_engine_url) {
    error "The anchore_engine_url parameter must be set in the library configuration."
  } else if (!config.cred) {
    error "Credentials for accessing Anchore Engine must be set in the library configuration."
  }

  // TODO add more input validation
  
  sh "mkdir -p anchore_results"
  
  return(true)
}

void call(){
  this.initialize_workspace(config)

  stage("Scanning Container Image: Anchore Scan"){
    node{
           try {
              withCredentials([usernamePassword(credentialsId: config.cred, passwordVariable: 'pass', usernameVariable: 'user')]) {
                def images = get_images_to_build()
		def archive_only = config.archive_only ?: false
		def bail_on_fail = config.fail_on_eval_stop ?: false

                images.each { img ->
		  def input_image_fulltag = "${img.registry}/${img.repo}:${img.tag}"
		  (success, new_image) = this.add_image(config, user, pass, input_image_fulltag)
		  if (success) {
		    println("Image analysis successful")
		  } else {
		    error "Failed to add image to Anchore Engine for analysis"
		  }

		  (success, vulnerabilities) = this.get_image_vulnerabilities(config, user, pass, new_image)
		  if (success) {
		    println("Image vulnerabilities report generation complete")
		    vulnerability_result =  "Anchore Image Scan Vulnerability Results\n"
		    vulnerability_result += "****************************************\n\n"
		    if (vulnerabilities) {
		      vulnerability_result += "VulnID".padRight(16, ' ')+"\t" + "Severity".padRight(12, ' ') + "\t" + "Package".padRight(30, ' ') + "\t" + "Type".padRight(6, ' ') + "\t" + "Fix Available".padRight(12, ' ') + "\tLink\n"
		      vulnerabilities.each { vuln ->
		      	vid = vuln.vuln.padRight(16, ' ')
			vsev = vuln.severity.padRight(12, ' ')
			vpkg = vuln.package.padRight(30, ' ') 
			vtype = vuln.package_type.padRight(6, ' ')
			vfix = vuln.fix.padRight(12, ' ')
			vurl = vuln.url
		        vulnerability_result += "${vid}\t${vsev}\t${vpkg}\t${vtype}\t${vfix}\t${vurl}\n"
		      }
		    } else {
		      vulnerability_result += "No vulnerabilities detected\n"
		    }

                    if (!archive_only) {
		        println(vulnerability_result)
                    }
                    
                    (success, evaluations) = get_image_evaluations(config, user, pass, new_image, input_image_fulltag)
		    if (success) {
		      println("Image policy evaluation report generation complete")
      		      String final_action = evaluations.final_action

		      evaluation_result =  "Anchore Image Scan Policy Evaluation Results\n"
		      evaluation_result += "********************************************\n"
		      evaluation_result += "Gate".padRight(12, ' ')+"\t" + "Trigger".padRight(12, ' ') + "\t" + "Action".padRight(6, ' ') + "\t" + "Details\n"
		      evaluations.rows.each { eval ->
		      	egate = eval[3].padRight(12, ' ')
			etrigger = eval[4].padRight(12, ' ')
			eaction = eval[6].padRight(6, ' ')
			edetail = eval[5]
			evaluation_result += "${egate}\t${etrigger}\t${eaction}\t${edetail}"
		      }

		      if (bail_on_fail) {
		        // check policy eval final action and exit if STOP
			if (final_action == "stop" || final_action == 'STOP') {
			  error "Anchore policy evaluation resulted in STOP action - failing scan."
			}
		      }			
		    } else {
		      evaluation_result = "No evaluations to report\n"
		    }
		    if (!archive_only) {
		      println(evaluation_result)
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