# Docker Setup Guide for SwiftCart

This guide explains how to run the SwiftCart application using Docker.

## Prerequisites

- Docker Desktop installed ([Download](https://www.docker.com/products/docker-desktop))
- Docker Compose (included with Docker Desktop)
- Git

## Project Structure

```
├── Dockerfile                 # Production frontend build
├── Dockerfile.dev            # Development frontend build
├── docker-compose.yml        # Production compose file
├── docker-compose.dev.yml    # Development compose file
├── .dockerignore             # Files to exclude from Docker build
├── server/
│   ├── Dockerfile            # Production backend build
│   ├── Dockerfile.dev        # Development backend build
│   └── .dockerignore         # Files to exclude from Docker build
└── .env.docker               # Environment variables template
```

## Quick Start

### 1. Setup Environment Variables

```bash
# Copy the environment template
cp .env.docker .env

# Edit .env with your actual values (optional for local development)
# The defaults should work for local testing
```

### 2. Production Build & Run

```bash
# Build and start all services
docker-compose up --build

# Or run in background
docker-compose up -d --build

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

**Access the application:**
- Frontend: http://localhost:3000
- Backend API: http://localhost:5000
- MongoDB: localhost:27017

### 3. Development Build & Run

```bash
# Build and start with hot-reload
docker-compose -f docker-compose.dev.yml up --build

# Or run in background
docker-compose -f docker-compose.dev.yml up -d --build

# View logs
docker-compose -f docker-compose.dev.yml logs -f

# Stop services
docker-compose -f docker-compose.dev.yml down
```

**Access the application:**
- Frontend (Vite dev server): http://localhost:5173
- Frontend (served): http://localhost:3000
- Backend API: http://localhost:5000
- MongoDB: localhost:27017

## Services

### MongoDB
- **Image:** mongo:7.0-alpine
- **Port:** 27017
- **Database:** SwiftCart
- **Volume:** Persists data in `mongodb_data` volume

### Backend
- **Port:** 5000
- **Environment:** Uses MongoDB service name `mongodb` for connection
- **Health Check:** Checks `/api/health` endpoint every 30 seconds
- **Dependencies:** Waits for MongoDB to be healthy before starting

### Frontend
- **Port:** 3000 (production) / 5173 (development)
- **Build:** Multi-stage build for optimized production image
- **Environment:** `VITE_API_URL` points to backend service

## Common Commands

### View running containers
```bash
docker-compose ps
```

### View logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f mongodb
```

### Execute commands in container
```bash
# Backend
docker-compose exec backend npm run seed

# Frontend
docker-compose exec frontend npm run build
```

### Rebuild specific service
```bash
docker-compose up -d --build backend
docker-compose up -d --build frontend
```

### Remove everything (including volumes)
```bash
docker-compose down -v
```

### Clean up unused Docker resources
```bash
docker system prune -a
```

## Troubleshooting

### Port already in use
```bash
# Find process using port
# Windows (PowerShell)
Get-NetTCPConnection -LocalPort 3000

# Kill process
Stop-Process -Id <PID> -Force

# Or change port in docker-compose.yml
# Change "3000:3000" to "3001:3000"
```

### MongoDB connection issues
```bash
# Check MongoDB logs
docker-compose logs mongodb

# Verify MongoDB is running
docker-compose exec mongodb mongosh
```

### Backend can't connect to MongoDB
- Ensure MongoDB service is healthy: `docker-compose ps`
- Check backend logs: `docker-compose logs backend`
- Verify `MONGODB_URI` is set to `mongodb://mongodb:27017/SwiftCart`

### Frontend can't reach backend
- Ensure backend is running: `docker-compose ps`
- Check backend logs: `docker-compose logs backend`
- Verify `VITE_API_URL` environment variable is set correctly
- Check frontend logs: `docker-compose logs frontend`

### Build fails
```bash
# Clear Docker cache and rebuild
docker-compose down -v
docker-compose up --build --no-cache
```

## Environment Variables

### Backend (.env)
```
MONGODB_URI=mongodb://mongodb:27017/SwiftCart
JWT_SECRET=your_secure_jwt_secret_key_here
PORT=5000
USER_EMAIL=your_email@gmail.com
USER_EMAIL_PASSWORD=your_app_password
ADMIN_EMAIL=admin_email@gmail.com
ADMIN_EMAIL_PASSWORD=admin_app_password
REDIS_URI=your_redis_uri
NODE_ENV=production
```

### Frontend (docker-compose.yml)
```
VITE_API_URL=http://backend:5000
```

## Production Deployment

### Using Docker Hub

```bash
# Build images
docker build -t yourusername/swiftcart-backend:latest ./server
docker build -t yourusername/swiftcart-frontend:latest .

# Push to Docker Hub
docker push yourusername/swiftcart-backend:latest
docker push yourusername/swiftcart-frontend:latest
```

### Using Docker Swarm or Kubernetes

Update `docker-compose.yml` with your registry URLs and deploy:

```bash
docker stack deploy -c docker-compose.yml swiftcart
```

## Performance Tips

1. **Use .dockerignore** - Already configured to exclude node_modules, dist, etc.
2. **Multi-stage builds** - Frontend uses multi-stage build to reduce image size
3. **Alpine images** - Using lightweight Alpine Linux images
4. **Volume mounts** - Development uses volumes for hot-reload without rebuilding

## Security Considerations

1. **Change JWT_SECRET** - Use a strong random string in production
2. **Use environment variables** - Don't hardcode secrets in Dockerfile
3. **Use .env files** - Keep sensitive data in .env (add to .gitignore)
4. **Network isolation** - Services communicate through Docker network
5. **Health checks** - Configured to detect unhealthy services

## Next Steps

1. Test the application: `docker-compose up --build`
2. Verify all services are running: `docker-compose ps`
3. Check logs for any errors: `docker-compose logs`
4. Access frontend at http://localhost:3000
5. Test API at http://localhost:5000/api/health

## Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Best Practices for Node.js in Docker](https://nodejs.org/en/docs/guides/nodejs-docker-webapp/)
