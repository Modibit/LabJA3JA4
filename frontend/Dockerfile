# Multi-stage multi-arch Dockerfile for Frontend
# Stage 1: Build React / Vite application
FROM node:22-alpine AS builder

WORKDIR /app

# Copy package files
COPY package.json package-lock.json ./

# Install dependencies (architecture-independent)
RUN npm ci

# Copy configurations and source code
COPY tsconfig*.json vite.config.ts index.html ./
COPY public/ ./public/
COPY src/ ./src/

# Build production distribution
RUN npm run build

# Stage 2: Serve via Nginx
FROM nginx:alpine

# Clean default static files
RUN rm -rf /usr/share/nginx/html/*

# Copy production build from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy Nginx reverse proxy configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:80/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
