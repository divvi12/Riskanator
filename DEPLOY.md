# Concert TEM - IBM Cloud Deployment Guide

## Quick Deploy (IBM Code Engine)

### Prerequisites

1. **IBM Cloud Account**: [Sign up free](https://cloud.ibm.com/registration)

2. **IBM Cloud CLI**: Install from terminal:
   ```bash
   curl -fsSL https://clis.cloud.ibm.com/install/osx | sh
   ```

3. **Code Engine Plugin**:
   ```bash
   ibmcloud plugin install code-engine
   ```

4. **Login to IBM Cloud**:
   ```bash
   ibmcloud login --sso
   ```

### One-Command Deploy

```bash
# Set your Gemini API key (optional, for AI features)
export GEMINI_API_KEY="your-api-key"

# Run the deployment script
./deploy-ibm-cloud.sh
```

### Manual Deployment Steps

If you prefer manual control:

#### 1. Create Code Engine Project

```bash
ibmcloud ce project create --name concert-tem
ibmcloud ce project select --name concert-tem
```

#### 2. Deploy Backend

```bash
cd backend
npm run build

ibmcloud ce app create --name concert-tem-backend \
    --build-source . \
    --strategy dockerfile \
    --port 3001 \
    --min-scale 1 \
    --max-scale 3 \
    --memory 512M \
    --env NODE_ENV=production
```

#### 3. Get Backend URL

```bash
ibmcloud ce app get --name concert-tem-backend --output url
```

#### 4. Deploy Frontend

```bash
cd ../frontend

# Set the backend URL
echo "VITE_API_URL=https://your-backend-url" > .env.production

ibmcloud ce app create --name concert-tem-frontend \
    --build-source . \
    --strategy dockerfile \
    --port 8080 \
    --min-scale 1
```

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GEMINI_API_KEY` | Google AI API key for explanations | Optional |
| `NODE_ENV` | Set to `production` | Yes |
| `PORT` | Backend port (default: 3001) | No |

### Useful Commands

```bash
# View application logs
ibmcloud ce app logs --name concert-tem-backend --follow

# Scale application
ibmcloud ce app update --name concert-tem-backend --min-scale 2 --max-scale 5

# Delete deployment
ibmcloud ce app delete --name concert-tem-backend
ibmcloud ce app delete --name concert-tem-frontend
ibmcloud ce project delete --name concert-tem
```

### Estimated Costs

IBM Code Engine pricing (pay-per-use):
- **vCPU**: ~$0.00002060/vCPU-second
- **Memory**: ~$0.00000227/GB-second
- **Free tier**: 100,000 vCPU-seconds + 200,000 GB-seconds/month

For a low-traffic demo, expect **< $5/month**.

### Alternative: IBM Kubernetes Service

For production workloads, consider IKS:

```bash
# Create cluster (takes ~20 min)
ibmcloud ks cluster create vpc-gen2 \
    --name concert-tem-cluster \
    --zone us-south-1 \
    --flavor bx2.2x8 \
    --workers 2
```

Then use the Kubernetes manifests in `/k8s` directory.

### Troubleshooting

**Build fails:**
```bash
ibmcloud ce buildrun logs --name <buildrun-name>
```

**App not starting:**
```bash
ibmcloud ce app get --name concert-tem-backend
ibmcloud ce app logs --name concert-tem-backend
```

**Update CORS for frontend URL:**
Update `backend/src/index.ts` to include your Code Engine frontend URL in CORS origins.
