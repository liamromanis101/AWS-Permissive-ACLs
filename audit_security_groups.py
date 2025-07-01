import boto3
from botocore.exceptions import NoCredentialsError, ClientError
import ipaddress

def get_service_from_rule(rule):
     protocol = rule.get('IpProtocol')
     from_port = rule.get('FromPort')
     to_port = rule.get('ToPort')

     if protocol == '-1':
         return 'All Traffic'
     if from_port is None or to_port is None:
         return protocol.upper()
     if from_port == to_port:
         return f"{protocol.upper()} port {from_port}"
     else:
         return f"{protocol.upper()} ports {from_port}-{to_port}"

def is_too_permissive(cidr):
     try:
         network = ipaddress.ip_network(cidr, strict=False)
         num_hosts = network.num_addresses

         if network.version == 4:
             usable_hosts = max(0, num_hosts - 2) if num_hosts > 2 else num_hosts
         else:
             usable_hosts = num_hosts  # no broadcast in IPv6

         return usable_hosts > 1
     except ValueError:
         return False  # Invalid CIDR, ignore it


def find_permissive_rules():
     try:
         ec2 = boto3.client('ec2')  # Credentials from environment/config

         response = ec2.describe_security_groups()
         print("Scanning for overly permissive security group rules...\n")

         for sg in response['SecurityGroups']:
             sg_name = sg.get('GroupName', 'Unnamed')
             sg_id = sg.get('GroupId')

             # Ingress Rules
             for rule in sg.get('IpPermissions', []):
                 for ip_range in rule.get('IpRanges', []):
                     cidr = ip_range.get('CidrIp')
                     if cidr and is_too_permissive(cidr):
                         print(f"[Ingress] Security Group: {sg_name} ({sg_id})")
                         print(f"          Service: {get_service_from_rule(rule)}")
                         print(f"          Source: {cidr}")
                         print(f"          Destination: N/A")
                         print("")

             # Egress Rules
             for rule in sg.get('IpPermissionsEgress', []):
                 for ip_range in rule.get('IpRanges', []):
                     cidr = ip_range.get('CidrIp')
                     if cidr and is_too_permissive(cidr):
                         print(f"[Egress ] Security Group: {sg_name} ({sg_id})")
                         print(f"          Service: {get_service_from_rule(rule)}")
                         print(f"          Source: N/A")
                         print(f"          Destination: {cidr}")
                         print("")

     except NoCredentialsError:
         print("AWS credentials not found. Please set them in environment variables or AWS config.")
     except ClientError as e:
         print(f"AWS Client Error: {e}")
     except Exception as e:
         print(f"Unexpected error: {e}")

if __name__ == "__main__":
     find_permissive_rules()
