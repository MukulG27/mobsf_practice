pipeline {
    agent {
        label 'slave-security'
    }
    parameters {
        string name: "32biturl", defaultValue: "", description: ""
        string name: "64biturl", defaultValue: "", description: ""
        string name: "universalurl", defaultValue: "", description: ""
    }
    environment {
        // mobsf config variables
        port = '8000'
        api_url = "http://172.31.64.174:${port}/api/v1"
        api_key = ''
        thread = '1'
        app_type = ''
        app_hash = ''
        app_name = ''
        app_file = ''
        app_version = ''
        // status variables
        download_status = -1
        mobsf_install_status = -1
        mobsf_run_status = -1
        mobsf_config_status = -1
        mobsf_api_key_status = -1
        mobsf_remove_files_status = -1
        mobsf_server_stop_status = -1
        remove_files_status = -1
        // response codes
        mobsf_upload_response_code = '0'
        mobsf_scan_response_code = '0'
        mobsf_json_response_code = '0'
        dd_upload_json_response_code = '0'
        mobsf_pdf_response_code = '0'
        mobsf_delete_response_code = '0'
        // error messages
        mobsf_upload_error_message = ''
        mobsf_scan_error_message = ''
        mobsf_json_report_error_message = ''
        mobsf_pdf_report_error_message = ''
        mobsf_delete_error_message = ''
        // defect dojo config variables
        dd_port = '443'
        dd_api_url = "http://172.31.64.174:${dd_port}/api/v2"
        dd_api_key = credentials('defect-dojo-key')
        dd_product_type = 'Security Report'
        dd_product_name = 'Mobile App Scanner'
        dd_engagement_name = 'MobSF Scanner Research'
        dd_scan_type = 'MobSF Scan'
        dd_test_title = "MobSF"
        dd_test_id = -1
        dd_url = "http://172.31.64.174:${dd_port}/"
        // Slack config variables
        slack_api_token = 'security-slack-token'
        slack_channel = 'trial'
        slack_pdf_report = ''
    }
    stages {
        stage ('Resource Download') {
            steps {
                script {
                    try {
                        download_cmd = "wget -q ${params.universalurl}"
                        download_status = sh label: 'Source Code Downloading', returnStatus: true, script: download_cmd
                        if(download_status != 0) {
                            echo "Resource Download Error"
                            echo download_status.toString()
                            slackSend tokenCredentialId: slack_api_token, channel: slack_channel, botUser: true, color: "danger", message: "*Resource Download Error*\n*Pipeline URL:* ${env.BUILD_URL}console"
                        }
                        else {
                            parts = params.universalurl.split('/')
                            app_file = parts[parts.size()-1]
                            for(element in parts) {
                                if(element.contains('ver')) {
                                    app_version = element
                                    break
                                }
                            }
                        }
                    }
                    catch(Exception e) {
                        echo e.toString()
                        slackSend tokenCredentialId: slack_api_token, channel: slack_channel, botUser: true, color: "danger", message: "*Error in ${env.STAGE_NAME}*\n${e.getMessage()}\n*Pipeline URL:* ${env.BUILD_URL}console"
                    }
                }
            }
        }
        stage ('MobSF Scanner') {
            when {
                expression {
                    return download_status == 0
                }
            }
            stages {
                stage ('Server Initialization') {
                    environment {
                        image_install = "docker pull opensecurity/mobile-security-framework-mobsf:latest"
                        server_initialize = "docker run --rm --name mobsf -d -p ${port}:8000 opensecurity/mobile-security-framework-mobsf:latest"
                        config_cmd = "docker exec mobsf bash -c \"cd /home/mobsf/Mobile-Security-Framework-MobSF/mobsf/StaticAnalyzer/tools/jadx/bin && sed -i '/^DEFAULT_JVM_OPTS=/aJADX_OPTS=\\\"-j ${thread}\\\"' jadx\""
                    }
                    steps {
                        script {
                            try {
                                mobsf_install_status = sh label: "MobSF Install", returnStatus: true, script: image_install
                                if(mobsf_install_status == 0) {
                                    mobsf_run_status = sh label: "MobSF Server Run", returnStatus: true, script: server_initialize
                                    if(mobsf_run_status != 0) {
                                        echo "MobSF Server Initialization Error"
                                        echo mobsf_run_status.toString()
                                        slackSend tokenCredentialId: slack_api_token, channel: slack_channel, botUser: true, color: "danger", message: "*MobSF Server Initialization Error*\n*Pipeline URL:* ${env.BUILD_URL}console"
                                    }
                                    else {
                                        mobsf_config_status = sh label: 'MobSF Configuration', returnStatus: true, script: config_cmd
                                        if(mobsf_config_status != 0) {
                                            echo "MobSF Server Configuration Error"
                                            echo mobsf_config_status.toString()
                                            slackSend tokenCredentialId: slack_api_token, channel: slack_channel, botUser: true, color: "danger", message: "*MobSF Server Configuration Error*\n*Pipeline URL:* ${env.BUILD_URL}console"
                                        }
                                    }
                                }
                                else {
                                    echo "MobSF Server Installation Error"
                                    echo mobsf_install_status.toString()
                                    slackSend tokenCredentialId: slack_api_token, channel: slack_channel, botUser: true, color: "danger", message: "*MobSF Server Installation Error*\n*Pipeline URL:* ${env.BUILD_URL}console"
                                }
                            }
                            catch(Exception e) {
                                echo e.toString()
                                slackSend tokenCredentialId: slack_api_token, channel: slack_channel, botUser: true, color: "danger", message: "*Error in ${env.STAGE_NAME}*\n${e.getMessage()}\n*Pipeline URL:* ${env.BUILD_URL}console"
                            }
                        }
                    }
                }
                stage ('API Key Extraction') {
                    when {
                        expression {
                            return mobsf_config_status == 0
                        }
                    }
                    environment {
                        wait_cmd = "wget -qO /dev/null http://localhost:${port}"
                        log_cmd = "docker logs mobsf"
                    }
                    steps {
                        script {
                            try {
                                sleep 5
                                waitUntil {
                                    
                                    wait_exit_code = sh label: "Waiting for Server", returnStatus: true, script: wait_cmd
                                    return (wait_exit_code == 0)
                                }
                                
                                logs = sh label: 'Log Output', returnStdout: true, script: log_cmd
                                pattern = /API\s+Key:\s+(\w+)/
                                line = logs =~ pattern ? logs.find(pattern) : null
                                if(line) {
                                    key = line.split(": ")[1].trim()
                                    api_key = key
                                    mobsf_api_key_status = 0
                                }
                                else {
                                    mobsf_api_key_status = 1
                                    echo "MobSF API Key Not Found"
                                    slackSend tokenCredentialId: slack_api_token, channel: slack_channel, botUser: true, color: "danger", message: "*MobSF API Key Not Found*\n*Pipeline URL:* ${env.BUILD_URL}console"
                                }
                            }
                            catch(Exception e) {
                                echo e.toString()
                                slackSend tokenCredentialId: slack_api_token, channel: slack_channel, botUser: true, color: "danger", message: "*Error in ${env.STAGE_NAME}*\n${e.getMessage()}\n*Pipeline URL:* ${env.BUILD_URL}console"
                            }
                        }
                    }
                }
                stage ('Upload') {
                    when {
                        expression {
                            return mobsf_api_key_status == 0
                        }
                    }
                    environment {
                        upload_cmd = "curl -s -S -w \"%{http_code}\" -o response.json -F \"file=@${app_file}\" --url ${api_url}/upload -H \"Authorization:${api_key}\""
                    }
                    steps {
                        script {
                            try {
                                mobsf_upload_response_code = sh label: 'Upload Binary', returnStdout: true, script: upload_cmd
                                response_map = readJSON file: 'response.json'
                                if(mobsf_upload_response_code == '200') {
                                    app_type = response_map["scan_type"]
                                    app_hash = response_map["hash"]
                                    app_name = response_map["file_name"]
                                    if(app_type == 'ipa') {
                                        slack_pdf_report = 'IOSAppReport.pdf'
                                    }
                                    else {
                                        slack_pdf_report = 'AndroidAppReport.pdf'
                                    }
                                }
                                else {
                                    mobsf_upload_error_message = response_map["error"]
                                    echo "MobSF Resource Upload Error"
                                    echo mobsf_upload_response_code
                                    echo mobsf_upload_error_message
                                    slackSend tokenCredentialId: slack_api_token, channel: slack_channel, botUser: true, color: "danger", message: "*MobSF Resource Upload Error*\n*${mobsf_upload_error_message}*\n*Pipeline URL:* ${env.BUILD_URL}console"
                                }
                            }
                            catch(Exception e) {
                                echo e.toString()
                                slackSend tokenCredentialId: slack_api_token, channel: slack_channel, botUser: true, color: "danger", message: "*Error in ${env.STAGE_NAME}*\n${e.getMessage()}\n*Pipeline URL:* ${env.BUILD_URL}console"
                            }
                        }
                    }
                }
                stage ('Scan') {
                    when {
                        expression {
                            return mobsf_upload_response_code == '200'
                        }
                    }
                    environment {
                        scan_start_cmd = "curl -s -S -w \"%{http_code}\" -o response.json -X POST --url ${api_url}/scan --data \"scan_type=${app_type}&file_name=${app_name}&hash=${app_hash}\" -H \"Authorization:${api_key}\""
                    }
                    steps {
                        script {
                            try {
                                mobsf_scan_response_code = sh label: 'Start Scan of Binary', returnStdout: true, script: scan_start_cmd
                                response_map = readJSON file: 'response.json'
                                if(mobsf_scan_response_code != '200') {
                                    mobsf_scan_error_message = response_map["error"]
                                    echo "MobSF Scan Error"
                                    echo mobsf_scan_response_code
                                    echo mobsf_scan_error_message
                                    slackSend tokenCredentialId: slack_api_token, channel: slack_channel, botUser: true, color: "danger", message: "*MobSF Scan Error*\n*${mobsf_scan_error_message}*\n*Pipeline URL:* ${env.BUILD_URL}console"
                                }
                            }
                            catch(Exception e) {
                                echo e.toString()
                                slackSend tokenCredentialId: slack_api_token, channel: slack_channel, botUser: true, color: "danger", message: "*Error in ${env.STAGE_NAME}*\n${e.getMessage()}\n*Pipeline URL:* ${env.BUILD_URL}console"
                            }
                        }
                    }
                }
                stage ('Upload JSON') {
                    when {
                        expression {
                            return mobsf_scan_response_code == '200'
                        }
                    }
                    environment {
                        generate_json_cmd = "curl -s -S -w \"%{http_code}\" -o json_report.json -X POST --url ${api_url}/report_json --data \"hash=${app_hash}\" -H \"Authorization:${api_key}\""
                        upload_json_cmd = """
                                            curl -s -S -w \"%{http_code}\" -o response.json -X POST \\
                                            -H \"Authorization: ${dd_api_key}\" --url \"${dd_api_url}/import-scan/\" \\
                                            -F \"product_type=${dd_product_type}\" -F \"product_name=${dd_product_name}\" -F \"engagement_name=${dd_engagement_name}\" \\
                                            -F \"scan_type=${dd_scan_type}\" -F \"file=@json_report.json\" -F \"test_title=${dd_test_title}-${app_name}\" \\
                                            -F \"auto_create_context=true\" -F \"deduplication_on_engagement=true\" -F \"skip_duplicates=true\"
                                            """
                    }
                    steps {
                        script {
                            try {
                                mobsf_json_response_code = sh label: 'Generate JSON Report', returnStdout: true, script: generate_json_cmd
                                response_map = readJSON file: 'json_report.json'
                                if(mobsf_json_response_code == '200') {
                                    app_version = response_map['version_name']
                                    dd_upload_json_response_code = sh label: 'Upload JSON Report', returnStdout: true, script: upload_json_cmd
                                    response_map = readJSON file: 'response.json'
                                    if(dd_upload_json_response_code != '201') {
                                        echo "DefectDojo JSON Report Upload Error"
                                        echo dd_upload_json_response_code
                                        echo response_map.toString()
                                        slackSend tokenCredentialId: slack_api_token, channel: slack_channel, botUser: true, color: "danger", message: "*DefectDojo JSON Report Upload Error*\n*Pipeline URL:* ${env.BUILD_URL}console"
                                    }
                                    else {
                                        dd_test_id = response_map['test']
                                    }
                                }
                                else {
                                    mobsf_json_report_error_message = response_map["error"]
                                    echo "MobSF JSON Report Download Error"
                                    echo mobsf_json_response_code
                                    echo mobsf_json_report_error_message
                                    slackSend tokenCredentialId: slack_api_token, channel: slack_channel, botUser: true, color: "danger", message: "*MobSF JSON Report Download Error*\n*${mobsf_json_report_error_message}*\n*Pipeline URL:* ${env.BUILD_URL}console"
                                }
                            }
                            catch(Exception e) {
                                echo e.toString()
                                slackSend tokenCredentialId: slack_api_token, channel: slack_channel, botUser: true, color: "danger", message: "*Error in ${env.STAGE_NAME}*\n${e.getMessage()}\n*Pipeline URL:* ${env.BUILD_URL}console"
                            }
                        }
                    }
                }
                stage ('Upload PDF') {
                    when {
                        expression {
                            return mobsf_scan_response_code == '200'
                        }
                    }
                    environment {
                        generate_pdf_cmd = "curl -s -S -w \"%{http_code}\" -o response.tmp -X POST --url ${api_url}/download_pdf --data \"hash=${app_hash}\" -H \"Authorization:${api_key}\""
                    }
                    steps {
                        script {
                            try {
                                mobsf_pdf_response_code = sh label: 'Generate PDF Report', returnStdout: true, script: generate_pdf_cmd
                                if(mobsf_pdf_response_code == '200') {
                                    pdf_report_cmd = "mv response.tmp ${slack_pdf_report}"
                                    pdf_status = sh label: 'PDF Generation', returnStatus: true, script: pdf_report_cmd
                                    if(pdf_status == 0) {
                                        test_url = ""
                                        if(dd_test_id != -1) {
                                            test_url = "*Test URL:* ${dd_url}test/${dd_test_id}\n"
                                        }
                                        slackUploadFile credentialId: slack_api_token, channel: slack_channel, filePath: slack_pdf_report, initialComment: "*Mobile Application Static Analysis*\n\n*Application Version:* ${app_version}\n\n*Pipeline URL:* ${env.BUILD_URL}console\n${test_url}\n"
                                    }
                                    else {
                                        echo "Slack PDF Report Upload Error"
                                        echo pdf_status.toString()
                                        slackSend tokenCredentialId: slack_api_token, channel: slack_channel, botUser: true, color: "danger", message: "*Slack PDF Report Upload Error*\n*Pipeline URL:* ${env.BUILD_URL}console"
                                    }
                                }
                                else {
                                    response_cmd = "cat response.tmp"
                                    response = sh label: 'PDF Generation Error', returnStdout: true, script: response_cmd
                                    response_map = readJSON text: response
                                    mobsf_pdf_report_error_message = response_map["error"]
                                    echo "MobSF PDF Report Download Error"
                                    echo mobsf_pdf_response_code
                                    echo mobsf_pdf_report_error_message
                                    slackSend tokenCredentialId: slack_api_token, channel: slack_channel, botUser: true, color: "danger", message: "*MobSF PDF Report Download Error*\n*${mobsf_pdf_report_error_message}*\n*Pipeline URL:* ${env.BUILD_URL}console"
                                }
                            }
                            catch(Exception e) {
                                echo e.toString()
                                slackSend tokenCredentialId: slack_api_token, channel: slack_channel, botUser: true, color: "danger", message: "*Error in ${env.STAGE_NAME}*\n${e.getMessage()}\n*Pipeline URL:* ${env.BUILD_URL}console"
                            }
                        }
                    }
                }
                stage ('Cleanup') {
                    when {
                        expression {
                            return mobsf_scan_response_code == '200'
                        }
                    }
                    environment {
                        delete_scan_cmd = "curl -s -S -w \"%{http_code}\" -o response.json -X POST --url ${api_url}/delete_scan --data \"hash=${app_hash}\" -H \"Authorization:${api_key}\""
                        remove_files_cmd = "rm -f response.json json_report.json ${slack_pdf_report} response.tmp"
                    }
                    steps {
                        script {
                            try {
                                mobsf_delete_response_code = sh label: 'Delete Scan', returnStdout: true, script: delete_scan_cmd
                                response_map = readJSON file: 'response.json'
                                if(mobsf_delete_response_code != '200') {
                                    mobsf_delete_error_message = response_map["error"]
                                    echo "MobSF Scan Delete Error"
                                    echo mobsf_delete_response_code
                                    echo mobsf_delete_error_message
                                    slackSend tokenCredentialId: slack_api_token, channel: slack_channel, botUser: true, color: "danger", message: "*MobSF Scan Delete Error*\n*${mobsf_delete_error_message}*\n*Pipeline URL:* ${env.BUILD_URL}console"
                                }
                                mobsf_remove_files_status = sh label: 'Remove Files', returnStatus: true, script: remove_files_cmd
                                if(mobsf_remove_files_status != 0) {
                                    echo "Error in Removing Files"
                                    echo mobsf_remove_files_status.toString()
                                    slackSend tokenCredentialId: slack_api_token, channel: slack_channel, botUser: true, color: "danger", message: "*Error in Removing Files*\n*Pipeline URL:* ${env.BUILD_URL}console"
                                }
                            }
                            catch(Exception e) {
                                echo e.toString()
                                slackSend tokenCredentialId: slack_api_token, channel: slack_channel, botUser: true, color: "danger", message: "*Error in ${env.STAGE_NAME}*\n${e.getMessage()}\n*Pipeline URL:* ${env.BUILD_URL}console"
                            }
                        }
                    }
                }
            }
        }
    }
    post {
        always {
            script {
                stage ('MobSF Server Stop') {
                    if(mobsf_run_status == 0) {
                        server_stop_cmd = "docker stop mobsf"
                        mobsf_server_stop_status = sh label: 'MobSF Server End', returnStatus: true, script: server_stop_cmd
                        if(mobsf_server_stop_status != 0) {
                            echo "Error in stopping the server"
                            echo mobsf_server_stop_status.toString()
                            slackSend tokenCredentialId: slack_api_token, channel: slack_channel, botUser: true, color: "danger", message: "*MobSF Server Stop Error*\n*Pipeline URL:* ${env.BUILD_URL}console"
                        }
                    }
                }
                stage ('Cleanup of Resources') {
                    if(download_status == 0) {
                        remove_files_cmd = "rm -f ${app_file}"
                        remove_files_status = sh label: 'Remove Files', returnStatus: true, script: remove_files_cmd
                        if(remove_files_status != 0) {
                            echo "Error in Removing Resource Files"
                            echo remove_files_status.toString()
                            slackSend tokenCredentialId: slack_api_token, channel: slack_channel, botUser: true, color: "danger", message: "*Error in Removing Files*\n*Pipeline URL:* ${env.BUILD_URL}console"
                        }
                    }
                }
            }
        }
    }
}
