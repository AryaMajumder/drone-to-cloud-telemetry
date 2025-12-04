#!/bin/bash

# Script to build and push drone telemetry consumer to AWS ECR
# Usage: ./build-and-push-to-ecr.sh <ecr-repository-uri> [aws-region]
#
# Example: ./build-and-push-to-ecr.sh 123456789012.dkr.ecr.us-east-1.amazonaws.com/drone-consumer us-east-1

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check arguments
if [ $# -lt 1 ]; then
    print_error "Usage: $0 <ecr-repository-uri> [aws-region]"
    echo ""
    echo "Example: $0 123456789012.dkr.ecr.us-east-1.amazonaws.com/drone-consumer us-east-1"
    echo ""
    echo "The ECR repository URI should be in the format:"
    echo "  <account-id>.dkr.ecr.<region>.amazonaws.com/<repository-name>"
    exit 1
fi

ECR_REPO_URI=$1
AWS_REGION=${2:-"us-east-1"}

# Extract account ID and repository name from URI
ACCOUNT_ID=$(echo $ECR_REPO_URI | cut -d'.' -f1)
REPO_NAME=$(echo $ECR_REPO_URI | cut -d'/' -f2)

print_info "Starting build and push process..."
print_info "ECR Repository: $ECR_REPO_URI"
print_info "AWS Region: $AWS_REGION"
print_info "Repository Name: $REPO_NAME"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    print_error "AWS CLI is not installed. Please install AWS CLI first."
    exit 1
fi

# Check if curl or wget is available
if command -v curl &> /dev/null; then
    DOWNLOAD_CMD="curl -sL -o"
elif command -v wget &> /dev/null; then
    DOWNLOAD_CMD="wget -q -O"
else
    print_error "Neither curl nor wget is installed. Please install one of them."
    exit 1
fi

# Create temporary directory
TEMP_DIR=$(mktemp -d)
print_info "Created temporary directory: $TEMP_DIR"

# Cleanup function
cleanup() {
    print_info "Cleaning up temporary directory..."
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# GitHub raw file base URL
GITHUB_BASE_URL="https://raw.githubusercontent.com/AryaMajumder/drone-to-cloud-telemetry/main/drone%20secure%20telemetry%20to%20cloud/consumer"

# Navigate to temp directory
cd "$TEMP_DIR"

# Download required files
print_info "Downloading files from GitHub..."

FILES=("consumer.py" "Dockerfile" "requirements.txt")

for file in "${FILES[@]}"; do
    FILE_URL="${GITHUB_BASE_URL}/${file}"
    print_info "  Downloading $file..."
    
    if command -v curl &> /dev/null; then
        curl -sL -o "$file" "$FILE_URL"
    else
        wget -q -O "$file" "$FILE_URL"
    fi
    
    if [ $? -ne 0 ]; then
        print_error "Failed to download $file from $FILE_URL"
        exit 1
    fi
    
    if [ ! -s "$file" ]; then
        print_error "Downloaded $file is empty or invalid"
        exit 1
    fi
    
    print_info "  ✓ Downloaded $file successfully"
done

# Verify required files exist and are not empty
print_info "Verifying downloaded files..."
for file in "${FILES[@]}"; do
    if [ ! -f "$file" ] || [ ! -s "$file" ]; then
        print_error "Required file missing or empty: $file"
        exit 1
    fi
    print_info "  ✓ Verified $file"
done

# Authenticate Docker to ECR
print_info "Authenticating Docker to AWS ECR..."
aws ecr get-login-password --region "$AWS_REGION" | \
    docker login --username AWS --password-stdin "$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"

if [ $? -ne 0 ]; then
    print_error "Failed to authenticate with ECR"
    exit 1
fi

# Build Docker image
IMAGE_TAG="latest"
FULL_IMAGE_NAME="$ECR_REPO_URI:$IMAGE_TAG"

print_info "Building Docker image: $FULL_IMAGE_NAME"
docker build -t "$REPO_NAME:$IMAGE_TAG" .

if [ $? -ne 0 ]; then
    print_error "Docker build failed"
    exit 1
fi

# Tag image for ECR
print_info "Tagging image for ECR..."
docker tag "$REPO_NAME:$IMAGE_TAG" "$FULL_IMAGE_NAME"

# Also tag with timestamp
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
TIMESTAMPED_IMAGE="$ECR_REPO_URI:$TIMESTAMP"
docker tag "$REPO_NAME:$IMAGE_TAG" "$TIMESTAMPED_IMAGE"
print_info "Also tagged as: $TIMESTAMPED_IMAGE"

# Push image to ECR
print_info "Pushing image to ECR..."
docker push "$FULL_IMAGE_NAME"

if [ $? -ne 0 ]; then
    print_error "Failed to push image to ECR"
    exit 1
fi

# Push timestamped version
print_info "Pushing timestamped image..."
docker push "$TIMESTAMPED_IMAGE"

# Success message
echo ""
print_info "================================================"
print_info "SUCCESS! Image pushed to ECR"
print_info "================================================"
print_info "Image URI (latest): $FULL_IMAGE_NAME"
print_info "Image URI (timestamped): $TIMESTAMPED_IMAGE"
print_info ""
print_info "You can now deploy this image using:"
print_info "  - ECS/Fargate"
print_info "  - EKS"
print_info "  - EC2 with Docker"
print_info ""
print_info "To pull the image:"
print_info "  docker pull $FULL_IMAGE_NAME"
echo ""

# Optional: Clean up local images
read -p "Do you want to remove local Docker images to free up space? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_info "Removing local images..."
    docker rmi "$REPO_NAME:$IMAGE_TAG" "$FULL_IMAGE_NAME" "$TIMESTAMPED_IMAGE" 2>/dev/null || true
    print_info "Local images removed"
fi

print_info "Script completed successfully!"