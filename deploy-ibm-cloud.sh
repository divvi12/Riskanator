#!/bin/bash
# Concert TEM - IBM Cloud Code Engine Deployment Script
# Prerequisites: IBM Cloud CLI with Code Engine plugin installed

set -e

# Configuration
PROJECT_NAME="concert-tem"
REGION="us-south"  # Change to your preferred region
RESOURCE_GROUP="default"  # Change to your resource group

echo "🚀 Concert Threat Exposure Management - IBM Cloud Deployment"
echo "============================================================"

# Check if IBM Cloud CLI is installed
if ! command -v ibmcloud &> /dev/null; then
    echo "❌ IBM Cloud CLI not found. Install it from:"
    echo "   https://cloud.ibm.com/docs/cli?topic=cli-getting-started"
    exit 1
fi

# Login check
echo "📋 Checking IBM Cloud login status..."
ibmcloud target || {
    echo "Please login first: ibmcloud login --sso"
    exit 1
}

# Install Code Engine plugin if needed
ibmcloud plugin install code-engine -f 2>/dev/null || true

# Set target
echo "🎯 Setting target region and resource group..."
ibmcloud target -r $REGION -g $RESOURCE_GROUP

# Create Code Engine project
echo "📦 Creating Code Engine project..."
ibmcloud ce project create --name $PROJECT_NAME 2>/dev/null || \
    ibmcloud ce project select --name $PROJECT_NAME

echo "⏳ Waiting for project to be ready..."
sleep 10

# Build and deploy backend
echo ""
echo "🔧 Building and deploying backend..."
cd backend
npm run build
ibmcloud ce build create --name concert-tem-backend-build \
    --source . \
    --strategy dockerfile \
    --dockerfile Dockerfile \
    --size medium 2>/dev/null || true

ibmcloud ce app create --name concert-tem-backend \
    --build-source . \
    --strategy dockerfile \
    --port 3001 \
    --min-scale 1 \
    --max-scale 3 \
    --memory 512M \
    --cpu 0.5 \
    --env GEMINI_API_KEY="${GEMINI_API_KEY:-}" \
    --env NODE_ENV=production \
    2>/dev/null || \
ibmcloud ce app update --name concert-tem-backend \
    --build-source . \
    --strategy dockerfile

# Get backend URL
BACKEND_URL=$(ibmcloud ce app get --name concert-tem-backend --output json | grep -o '"https://[^"]*"' | head -1 | tr -d '"')
echo "✅ Backend deployed at: $BACKEND_URL"

# Build and deploy frontend
echo ""
echo "🔧 Building and deploying frontend..."
cd ../frontend

# Update API URL in frontend build
echo "VITE_API_URL=$BACKEND_URL" > .env.production

ibmcloud ce app create --name concert-tem-frontend \
    --build-source . \
    --strategy dockerfile \
    --port 8080 \
    --min-scale 1 \
    --max-scale 3 \
    --memory 256M \
    --cpu 0.25 \
    2>/dev/null || \
ibmcloud ce app update --name concert-tem-frontend \
    --build-source .

# Get frontend URL
FRONTEND_URL=$(ibmcloud ce app get --name concert-tem-frontend --output json | grep -o '"https://[^"]*"' | head -1 | tr -d '"')

echo ""
echo "============================================================"
echo "✅ Deployment Complete!"
echo "============================================================"
echo ""
echo "🌐 Frontend URL: $FRONTEND_URL"
echo "🔧 Backend URL:  $BACKEND_URL"
echo ""
echo "📊 View in IBM Cloud Console:"
echo "   https://cloud.ibm.com/codeengine/projects"
echo ""
echo "🔍 View logs:"
echo "   ibmcloud ce app logs --name concert-tem-backend"
echo "   ibmcloud ce app logs --name concert-tem-frontend"
echo ""
