# Build stage
FROM node:18-alpine AS build

# Set working directory to the calculator app
WORKDIR /app/med-cvss-calculator

# Add security updates and essential tools
RUN apk update && apk upgrade && apk add --no-cache \
    python3 \
    make \
    g++ \
    && rm -rf /var/cache/apk/*

# Copy package files first for better layer caching
COPY med-cvss-calculator/package*.json ./

# Install dependencies with audit fix and clean cache
RUN npm install --legacy-peer-deps && \
    npm audit fix --force --audit-level=moderate || true && \
    npm cache clean --force

# Skip prepare script during Docker build
ENV HUSKY=0

# Copy source files
COPY med-cvss-calculator/ ./

# Build the application
RUN npm run build

# Remove source files and node_modules to minimize attack surface
RUN rm -rf src node_modules

# Production stage
FROM nginx:alpine AS production

# Apply security updates
RUN apk update && apk upgrade && rm -rf /var/cache/apk/*

# Ensure nginx user exists (nginx:alpine already has nginx user)
RUN id nginx || (addgroup -g 101 -S nginx && \
    adduser -S -D -H -u 101 -h /var/cache/nginx -s /sbin/nologin -G nginx -g nginx nginx)

# Copy built files from build stage
COPY --from=build /app/med-cvss-calculator/build /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Create nginx temp directories and set proper permissions
RUN mkdir -p /var/cache/nginx/client_temp \
              /var/cache/nginx/proxy_temp \
              /var/cache/nginx/fastcgi_temp \
              /var/cache/nginx/uwsgi_temp \
              /var/cache/nginx/scgi_temp && \
    chown -R nginx:nginx /usr/share/nginx/html && \
    chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /var/log/nginx && \
    chown -R nginx:nginx /etc/nginx/conf.d && \
    touch /var/run/nginx.pid && \
    chown -R nginx:nginx /var/run/nginx.pid

# Remove unnecessary files
RUN rm -rf /usr/share/nginx/html/*.map

# Use non-root user
USER nginx

# Expose port 80
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost/ || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]