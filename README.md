AWS Cloud Security & Purple Team Automation Lab
This repository contains a hands-on Purple Team lab I built to test automated threat detection and incident response in AWS. I used Terraform to provision the infrastructure as code (IaC) and wrote a custom Python (Boto3) Lambda function to act as the Blue Team, automatically reverting insecure environment changes in near real-time.

The goal of this project was to execute Red Team attacks mapped to the MITRE ATT&CK framework and prove that event-driven architecture can neutralize threats faster than manual human intervention.

🏗️ Architecture Overview
Here is a high-level look at the event pipeline I set up:

Plaintext
[ Red Team Attack (AWS CLI) ] 
          │
          ▼
    [ AWS CloudTrail ] (Logs the API call)
          │
          ▼
   [ Amazon EventBridge ] (Filters for specific attack patterns)
          │
          ▼
     [ AWS Lambda ] (My Python remediation script)
          │
          ▼
 [ Target Resource ] (Lambda instantly secures the resource)
🚀 Lab Scenarios & Execution
Scenario A: Network Ingress Exposure & Automated Remediation
MITRE ATT&CK: T1190 — Exploit Public-Facing Application

The Attack: I acted as the Red Team by injecting a rogue ingress rule into my web server's security group, exposing MySQL (Port 3306) to the entire public internet (0.0.0.0/0).

The Defense: EventBridge caught the AuthorizeSecurityGroupIngress API call in CloudTrail and instantly triggered my Lambda function. The Python script extracted the security group ID and the specific rogue port, and automatically issued a revoke command.

Evidence & Verification:

Executing the Red Team Attack:

Verifying the Blue Team Automation (Port 3306 is gone):

CloudWatch Logs showing the Python execution success:

Scenario B: Defense Evasion (Telemetry Blinding)
MITRE ATT&CK: T1562.001 — Impair Defences: Disable or Modify Tools

The Attack: To simulate an attacker covering their tracks, I disabled my active CloudTrail stream using aws cloudtrail stop-logging.

The Defense: I queried the trail status to confirm IsLogging dropped to false, simulating the monitoring blind spot, before manually restoring the telemetry baseline so the Blue Team operations could resume.

Evidence:

Shutting down CloudTrail:

Scenario C: IAM Persistence
MITRE ATT&CK: T1098.001 — Account Manipulation: Additional Credentials

The Attack: I simulated an attacker establishing persistent backdoor access by generating a set of long-term IAM access keys for a compromised user account using the CLI.

Evidence:

Generating rogue access keys:

🛠️ Technology Stack
Infrastructure as Code: Terraform (AWS Provider v6.47.0)

Cloud Platform: Amazon Web Services (AWS)

Compute / Scripting: AWS Lambda (Python 3.10)

Monitoring & Routing: Amazon EventBridge, AWS CloudTrail, Amazon CloudWatch

Environment: Ubuntu Linux, AWS CLI v2

📜 Automated Remediation Logic
Here is the core Python logic I wrote for the Lambda function. It parses the nested JSON payload from CloudTrail, maps the keys to what Boto3 expects, and revokes the specific rule without touching legitimate traffic like ports 80 or 22.

Python
import boto3

def lambda_handler(event, context):
    ec2 = boto3.client('ec2')
    detail = event.get('detail', {})
    
    if detail.get('eventName') == 'AuthorizeSecurityGroupIngress':
        group_id = detail['requestParameters']['groupId']
        items = detail['requestParameters']['ipPermissions']['items']
        
        print(f"🚨 ALERT: Unauthorized ingress rule added to {group_id}. Reverting...")
        
        for item in items:
            try:
                protocol = item.get('ipProtocol', '-1')
                from_port = item.get('fromPort')
                to_port = item.get('toPort')
                
                ip_ranges = [
                    {'CidrIp': r['cidrIp']} 
                    for r in item.get('ipRanges', {}).get('items', []) 
                    if 'cidrIp' in r
                ]
                
                permission = {
                    'IpProtocol': str(protocol),
                    'IpRanges': ip_ranges
                }
                if from_port is not None:
                    permission['FromPort'] = int(from_port)
                if to_port is not None:
                    permission['ToPort'] = int(to_port)
                    
                response = ec2.revoke_security_group_ingress(
                    GroupId=group_id,
                    IpPermissions=[permission]
                )
                print(f"✅ SUCCESS: Automatically reverted rogue rule: {response}")
                return {"status": "success"}
                
            except Exception as e:
                print(f"❌ ERROR: Failed to revert rule: {e}")
                return {"status": "error", "message": str(e)}
🧹 Infrastructure Clean-Up
To prevent unexpected billing on my AWS account, I destroyed all the provisioned infrastructure once the lab scenarios were completed:

Bash
terraform destroy -auto-approve
