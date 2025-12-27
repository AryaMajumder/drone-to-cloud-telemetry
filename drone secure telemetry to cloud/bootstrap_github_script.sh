AWSTemplateFormatVersion: '2010-09-09'
Description: >
  SSM-ready EC2 instance that downloads and runs bootstrap script with parameters.
  Based on ssm_ready_ec_2.yaml with added parameters and modified UserData.

Parameters:
  # Existing parameters (keeping original structure)
  InstanceType:
    Type: String
    Default: t3.micro
    AllowedValues:
      - t3.micro
      - t3.small
      - t3.medium
    Description: EC2 instance type
  
  KeyName:
    Type: String
    Default: ''
    Description: (Optional) SSH key pair name
  
  # NEW PARAMETERS for bootstrap script
  AwsAccessKeyId:
    Type: String
    NoEcho: true
    Description: AWS Access Key ID for IoT Core forwarder (passed as $1 to bootstrap)
  
  AwsSecretAccessKey:
    Type: String
    NoEcho: true
    Description: AWS Secret Access Key for IoT Core forwarder (passed as $2 to bootstrap)
  
  AwsIoTEndpoint:
    Type: String
    Description: AWS IoT Core endpoint (passed as $3 to bootstrap) - e.g. abc123.iot.us-east-1.amazonaws.com

Conditions:
  HasKeyName: !Not [!Equals [!Ref KeyName, '']]

Resources:
  # VPC
  VPC:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
      EnableDnsHostnames: true
      EnableDnsSupport: true
      Tags:
        - Key: Name
          Value: mqtt-broker-vpc

  # Internet Gateway
  InternetGateway:
    Type: AWS::EC2::InternetGateway
    Properties:
      Tags:
        - Key: Name
          Value: mqtt-broker-igw

  AttachGateway:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties:
      VpcId: !Ref VPC
      InternetGatewayId: !Ref InternetGateway

  # Public Subnet
  PublicSubnet:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref VPC
      CidrBlock: 10.0.1.0/24
      MapPublicIpOnLaunch: true
      AvailabilityZone: !Select [0, !GetAZs '']
      Tags:
        - Key: Name
          Value: mqtt-broker-public-subnet

  # Route Table
  PublicRouteTable:
    Type: AWS::EC2::RouteTable
    Properties:
      VpcId: !Ref VPC
      Tags:
        - Key: Name
          Value: mqtt-broker-public-rt

  PublicRoute:
    Type: AWS::EC2::Route
    DependsOn: AttachGateway
    Properties:
      RouteTableId: !Ref PublicRouteTable
      DestinationCidrBlock: 0.0.0.0/0
      GatewayId: !Ref InternetGateway

  SubnetRouteTableAssociation:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      SubnetId: !Ref PublicSubnet
      RouteTableId: !Ref PublicRouteTable

  # Security Group
  InstanceSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Security group for MQTT broker instance
      VpcId: !Ref VPC
      SecurityGroupIngress:
        # Allow SSH if key is provided (optional)
        - !If
          - HasKeyName
          - IpProtocol: tcp
            FromPort: 22
            ToPort: 22
            CidrIp: 0.0.0.0/0
          - !Ref AWS::NoValue
      SecurityGroupEgress:
        # Allow all outbound (needed for SSM, GitHub downloads, etc)
        - IpProtocol: -1
          CidrIp: 0.0.0.0/0
      Tags:
        - Key: Name
          Value: mqtt-broker-sg

  # IAM Role for SSM
  SSMInstanceRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
      Tags:
        - Key: Name
          Value: mqtt-broker-ssm-role

  SSMInstanceProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      Roles:
        - !Ref SSMInstanceRole

  # EC2 Instance
  EC2Instance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: !Sub '{{resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64}}'
      InstanceType: !Ref InstanceType
      IamInstanceProfile: !Ref SSMInstanceProfile
      KeyName: !If [HasKeyName, !Ref KeyName, !Ref AWS::NoValue]
      NetworkInterfaces:
        - AssociatePublicIpAddress: true
          DeviceIndex: '0'
          GroupSet:
            - !Ref InstanceSecurityGroup
          SubnetId: !Ref PublicSubnet
      Tags:
        - Key: Name
          Value: mqtt-broker
      UserData:
        Fn::Base64: !Sub |
          #!/bin/bash
          set -e
          
          # Log all output
          exec > >(tee /var/log/userdata-bootstrap.log) 2>&1
          
          echo "=========================================="
          echo "UserData Bootstrap Script"
          echo "=========================================="
          date
          echo ""
          
          # ============================================================
          # STEP A: Install, run, and ensure SSM works
          # ============================================================
          echo "[STEP A] Setting up SSM access..."
          
          # Install SSM agent (usually pre-installed on AL2023)
          if ! command -v amazon-ssm-agent &> /dev/null; then
              echo "  Installing SSM agent..."
              dnf install -y amazon-ssm-agent
          else
              echo "  SSM agent already installed"
          fi
          
          # Enable and start SSM agent
          echo "  Starting SSM agent..."
          systemctl enable amazon-ssm-agent
          systemctl start amazon-ssm-agent
          
          # Verify SSM agent is running
          sleep 5
          if systemctl is-active --quiet amazon-ssm-agent; then
              echo "  ✓ SSM agent is running"
          else
              echo "  ✗ SSM agent failed to start"
              systemctl status amazon-ssm-agent --no-pager
          fi
          
          echo "✓ SSM setup complete"
          echo ""
          
          # ============================================================
          # STEP B: Download bootstrap script from GitHub
          # ============================================================
          echo "[STEP B] Downloading bootstrap script from GitHub..."
          
          GITHUB_SCRIPT_URL="https://raw.githubusercontent.com/AryaMajumder/drone-to-cloud-telemetry/refs/heads/main/drone%20secure%20telemetry%20to%20cloud/mqtt%20broker/bootstrap_github_script.sh.tmp"
          BOOTSTRAP_SCRIPT="/tmp/bootstrap_github_script.sh"
          
          echo "  URL: $GITHUB_SCRIPT_URL"
          echo "  Destination: $BOOTSTRAP_SCRIPT"
          
          # Download with retries
          for attempt in 1 2 3 4 5; do
              echo "  Attempt $attempt..."
              if curl -fsSL --retry 3 --retry-delay 2 "$GITHUB_SCRIPT_URL" -o "$BOOTSTRAP_SCRIPT"; then
                  if [ -s "$BOOTSTRAP_SCRIPT" ]; then
                      echo "  ✓ Downloaded successfully ($(stat -c%s "$BOOTSTRAP_SCRIPT") bytes)"
                      break
                  else
                      echo "  ✗ File is empty, retrying..."
                      rm -f "$BOOTSTRAP_SCRIPT"
                  fi
              else
                  echo "  ✗ Download failed, retrying..."
              fi
              
              if [ $attempt -eq 5 ]; then
                  echo "  ✗ Failed to download after 5 attempts"
                  exit 1
              fi
              sleep 3
          done
          
          # Make executable
          chmod +x "$BOOTSTRAP_SCRIPT"
          
          # Fix Windows line endings (CRLF -> LF)
          echo "  Converting line endings..."
          tr -d '\r' < "$BOOTSTRAP_SCRIPT" > "$BOOTSTRAP_SCRIPT.unix"
          mv "$BOOTSTRAP_SCRIPT.unix" "$BOOTSTRAP_SCRIPT"
          chmod +x "$BOOTSTRAP_SCRIPT"
          
          echo "✓ Bootstrap script downloaded"
          echo ""
          
          # ============================================================
          # STEP C: Run bootstrap script with parameters
          # ============================================================
          echo "[STEP C] Running bootstrap script with parameters..."
          echo ""
          echo "Parameters:"
          echo "  \$1 (Access Key): [provided]"
          echo "  \$2 (Secret Key): [hidden]"
          echo "  \$3 (IoT Endpoint): ${AwsIoTEndpoint}"
          echo ""
          echo "Command: bash $BOOTSTRAP_SCRIPT \"\$1\" \"\$2\" \"\$3\""
          echo ""
          echo "----------------------------------------"
          echo "Bootstrap Script Output:"
          echo "----------------------------------------"
          
          # Run the bootstrap script with the 3 parameters
          bash "$BOOTSTRAP_SCRIPT" "${AwsAccessKeyId}" "${AwsSecretAccessKey}" "${AwsIoTEndpoint}" 2>&1 | tee /var/log/bootstrap-script-output.log
          
          BOOTSTRAP_EXIT_CODE=${!PIPESTATUS[0]}
          
          echo ""
          echo "----------------------------------------"
          echo "Bootstrap Script Completed"
          echo "----------------------------------------"
          echo ""
          
          if [ $BOOTSTRAP_EXIT_CODE -eq 0 ]; then
              echo "✓ Bootstrap script executed successfully"
          else
              echo "✗ Bootstrap script failed with exit code: $BOOTSTRAP_EXIT_CODE"
          fi
          
          echo ""
          echo "=========================================="
          echo "UserData Bootstrap Complete"
          echo "=========================================="
          date
          echo ""
          echo "Log files:"
          echo "  UserData log: /var/log/userdata-bootstrap.log"
          echo "  Bootstrap output: /var/log/bootstrap-script-output.log"
          echo ""
          echo "Connect via SSM:"
          echo "  aws ssm start-session --target ${!AWS::StackName} --region ${!AWS::Region}"
          echo ""
          
          exit $BOOTSTRAP_EXIT_CODE

Outputs:
  InstanceId:
    Description: EC2 Instance ID
    Value: !Ref EC2Instance
    Export:
      Name: !Sub '${AWS::StackName}-InstanceId'
  
  InstancePublicIP:
    Description: Public IP address
    Value: !GetAtt EC2Instance.PublicIp
    Export:
      Name: !Sub '${AWS::StackName}-PublicIP'
  
  InstancePrivateIP:
    Description: Private IP address
    Value: !GetAtt EC2Instance.PrivateIp
    Export:
      Name: !Sub '${AWS::StackName}-PrivateIP'
  
  SSMConnectCommand:
    Description: Command to connect via SSM Session Manager
    Value: !Sub 'aws ssm start-session --target ${EC2Instance} --region ${AWS::Region}'
  
  CheckLogsCommand:
    Description: Commands to check bootstrap logs
    Value: !Sub |
      aws ssm start-session --target ${EC2Instance} --region ${AWS::Region}
      sudo tail -100 /var/log/userdata-bootstrap.log
      sudo tail -100 /var/log/bootstrap-script-output.log
  
  VPCId:
    Description: VPC ID
    Value: !Ref VPC
    Export:
      Name: !Sub '${AWS::StackName}-VPC'
  
  SubnetId:
    Description: Public Subnet ID
    Value: !Ref PublicSubnet
    Export:
      Name: !Sub '${AWS::StackName}-Subnet'
  
  SecurityGroupId:
    Description: Security Group ID
    Value: !Ref InstanceSecurityGroup
    Export:
      Name: !Sub '${AWS::StackName}-SecurityGroup'